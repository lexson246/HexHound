"""容器化执行环境：真工具（sqlmap / nmap / nuclei / ffuf …）跑在隔离容器里。

为什么需要这一层（对标 Strix 与 PentAGI，但补上它们缺的东西）：

- **Strix** 每个扫描起一个 Kali 容器（`ghcr.io/usestrix/strix-sandbox`），
  工具通过 SDK 的 Shell 能力执行；PentAGI 每个 flow 一个常驻容器
  （`vxcontrol/kali-linux`，`tail -f /dev/null` + `docker exec`）。
  两家都是"LLM 想跑什么就跑什么"。
- **它们缺的**：容器里没有作用域约束。PentAGI 自己在文档里承认"后端没有 scope 校验，
  只有提示词模板"；Strix 的 scope 是 agent 自己维护的 `scope_rules`。
  也就是说：**提示词一失效，容器就能打任何地址**。

本模块的差异点：**每一次 exec 之前，先把命令行里出现的所有 URL/主机抠出来，
逐个过白名单**；出现任何白名单外的主机，直接拒绝执行并说明原因。
这样即使模型被诱导（或被目标页面注入提示词），也没法让容器去打别的地方。

同时在容器层再收一道：
- 容器以非 root 用户运行、`--cap-drop ALL`、只读根文件系统（tmpfs 放 /tmp）；
- 不挂载宿主目录（只挂一个临时结果目录）、不挂 docker.sock；
- 目标网络由宿主白名单决定，容器只被允许访问被授权的主机。

Docker 不可用时**不报错、不假装**：`Sandbox.available()` 返回 False，
`run()` 返回带 `error` 的结果，上层据此降级到纯 Python 探测并把这一点写进报告。
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import scope_allows
from .sanitize import clip_head_tail, decode_output, sanitize_terminal_text

# ---------------------------------------------------------------------------
# 默认镜像：优先本地已有；没有就按顺序拉
# ---------------------------------------------------------------------------
#: 预置的渗透测试镜像（按偏好排序）。第一个能用的会被采用。
DEFAULT_IMAGES: tuple[str, ...] = (
    "hexhound-sandbox:latest",     # 用户自己 build 的（见 docker/Dockerfile）
    "kalilinux/kali-rolling",      # 官方 Kali，--network host 时可现场装工具
    "instrumentisto/nmap",         # 极小的 nmap 镜像
    "python:3.12-slim",            # 兜底：只能跑 python，用于 pip 安装所需工具
)

#: 容器名前缀（便于 --label 清理与识别）
CONTAINER_PREFIX = "hexhound-sbx-"

#: 默认单命令超时；nmap / sqlmap 这类要放宽
DEFAULT_EXEC_TIMEOUT = 300

#: 输出上限（超过就截断，避免把上下文撑爆）
MAX_OUTPUT_CHARS = 24_000

#: 允许执行的工具白名单。**不在这张表里的命令一律拒绝**——
#: 这一层是"让 LLM 用工具"，不是"给 LLM 一个 shell"。
TOOL_ALLOWLIST: dict[str, str] = {
    "sqlmap": "SQL 注入探测与数据提取（--batch --flush-session，只读）",
    "nmap": "端口与服务发现",
    "nuclei": "模板化漏洞扫描",
    "ffuf": "目录 / 参数模糊测试",
    "gobuster": "目录与子域枚举",
    "nikto": "Web 服务器配置检查",
    "whatweb": "技术栈指纹",
    "curl": "原始 HTTP 请求",
    "python3": "受限脚本（用于自定义验证逻辑）",
}

#: 明确禁止的参数片段：破坏性 / 提权 / 反弹 / 写入目标
FORBIDDEN_ARGS: tuple[str, ...] = (
    "--os-shell", "--os-pwn", "--os-smbrelay", "--file-write", "--file-dest",
    "--sql-shell-write", "--priv-esc", "--eval=", "-e ", "--script=",
    "nc -e", "bash -i", "/dev/tcp", "mkfifo", "chmod 777", "rm -rf /",
    "--drop", "DROP TABLE", "DELETE FROM", "UPDATE ", "INSERT INTO",
)

#: 自定义脚本里禁止出现的片段：破坏性操作 / 反弹 shell / 起子进程。
#: 这些在真工具里本来就被 FORBIDDEN_ARGS 挡着，脚本通道不能成为后门。
FORBIDDEN_SCRIPT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("rm -rf", "递归删除"),
    ("shutil.rmtree", "递归删除目录"),
    ("os.remove", "删除文件"),
    ("os.unlink", "删除文件"),
    ("mkfs", "格式化文件系统"),
    ("dd if=", "裸设备写入"),
    ("/dev/tcp/", "bash 反弹 shell"),
    ("nc -e", "反弹 shell"),
    ("ncat -e", "反弹 shell"),
    ("bash -i", "交互式 shell"),
    ("sh -i", "交互式 shell"),
    ("socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect", "手工 socket 连接（请用 http 库）"),
    ("pty.spawn", "伪终端提权"),
    ("crontab", "计划任务持久化"),
    ("authorized_keys", "写入 SSH 公钥"),
    ("os.system(", "起子进程（脚本通道不允许，请用沙箱工具）"),
    ("os.popen(", "起子进程（脚本通道不允许，请用沙箱工具）"),
    ("subprocess", "起子进程（脚本通道不允许，请用沙箱工具）"),
    ("eval(input(", "交互式输入"),
    ("__import__('os').system", "绕过静态检查起子进程"),
)

#: 脚本通道里的“运行时护栏”前导代码。
#:
#: 为什么必须有它：静态文本扫描只能挡住**字面量**里出现的白名单外主机。
#: 一段脚本完全可以用 `"e"+"vil.com"`、base64、或 f-string 拼出域名来绕过扫描
#: （同一条路在命令行工具里也有，但脚本的表达能力强得多）。
#: 因此这里在**进程内**把 DNS 解析与 socket 连接都接管：任何不在白名单里的主机
#: 在真正发包前就被拒绝——拼接、编码、变量间接都绕不过去。
#: 代价是这层护栏是 Python 级的（脚本理论上能把钩子改回去），
#: 所以静态扫描 + 白名单双保险，且脚本通道只对注入/认证/复核角色开放。
#:
#: 不限制模式（`ALLOWED_HOSTS=*`）下**不注入这层护栏**：护栏的判据是
#: "主机名在允许集合里"，把 `*` 当普通成员传进去会让它拒绝**所有**主机——
#: 那就成了"设了不限制，沙箱脚本反而全挂"。此时靠静态扫描保住工具白名单与
#: 破坏性片段拦截，网络层面不做主机限制（与工具的 `scope_allows` 语义一致）。
_SCRIPT_GUARD = '''
import socket as _socket
_ALLOW = set({allow!r})
_ANY = "*" in _ALLOW
_getaddrinfo = _socket.getaddrinfo
_connect = _socket.socket.connect

def _check(host):
    if _ANY:
        return
    name = str(host).strip().strip("[]").lower()
    if name in _ALLOW:
        return
    raise RuntimeError(
        "[hexhound-scope] refused to connect non-allowlisted host: %s (allowed: %s)"
        % (name, ", ".join(sorted(_ALLOW)))
    )

def _guarded_getaddrinfo(host, *args, **kwargs):
    _check(host)
    return _getaddrinfo(host, *args, **kwargs)

def _guarded_connect(self, address):
    if isinstance(address, tuple) and address:
        _check(address[0])
    return _connect(self, address)

_socket.getaddrinfo = _guarded_getaddrinfo
_socket.socket.connect = _guarded_connect
'''


#: 从命令行里抠 URL / 主机（作用域校验用）
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.I)
#: nmap / ffuf 这类工具常写成裸主机或 host:port
_BARE_HOST_RE = re.compile(r"(?<![\w./-])([a-z0-9][a-z0-9.-]{2,253}\.[a-z]{2,24})(?![\w.-])", re.I)
#: 裸 IPv4（点分十进制）——**必须单独匹配**：域名正则要求顶级标签是字母，
#: 所以 `nmap 8.8.8.8` 这种写法会漏掉（早期版本真的漏过，测试抓到了）。
_BARE_IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
#: IPv6 字面量（宽松匹配，含方括号形式）
_BARE_IPV6_RE = re.compile(r"(?<![\w:])(\[[0-9a-fA-F:]{2,45}\]|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")


@dataclass
class ExecResult:
    """一次容器内命令的执行结果。"""

    ok: bool
    command: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    error: str = ""
    exec_id: str = ""
    truncated: bool = False
    scope_checked: bool = True
    #: 映射前的原始命令（回环地址改写前）。报告里用来说明"原本打的是哪个目标"，
    #: 否则读者看到宿主 IP 会以为打错了地方。
    original_command: str = ""
    #: 自定义脚本通道（sandbox_script）执行的脚本正文；有值时报告按脚本渲染。
    script: str = ""

    @property
    def output(self) -> str:
        """合并输出（给 LLM 看的文本）。

        这里再清理一次而不是只在 `_execute` 里清：`ExecResult` 也会被
        `build_image` / 安装路径等地方直接构造，出口统一清理才能保证
        「进报告、进模型上下文」的文本一定是干净的（见 `sanitize.py`）。
        已经是清理过的文本时这是幂等操作，代价可忽略。
        """
        parts = [
            sanitize_terminal_text(part)
            for part in (self.stdout, self.stderr)
            if part and part.strip()
        ]
        return "\n".join(part for part in parts if part.strip()).strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.exec_id,
            "ok": self.ok,
            "command": self.command,
            "script": self.script,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "output": self.output,
            "duration": round(self.duration, 2),
            "error": self.error,
            "truncated": self.truncated,
        }


class ScopeViolation(RuntimeError):
    """命令行里出现了白名单外的主机。"""


def _find_docker() -> str | None:
    """找 docker 可执行文件（Windows 上常不在 PATH 里，需要探常见安装位置）。"""
    found = shutil.which("docker")
    if found:
        return found
    candidates = [
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        r"C:\Program Files\Docker\cli-plugins\docker.exe",
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        str(Path.home() / ".docker" / "bin" / "docker"),
    ]
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return None


def _find_podman() -> str | None:
    """Podman 作为 Docker 的替代（CLI 基本兼容）。"""
    return shutil.which("podman")


def _find_wsl() -> str | None:
    """找 wsl.exe（Windows 10/11 自带）。"""
    if sys.platform != "win32":
        return None
    found = shutil.which("wsl") or shutil.which("wsl.exe")
    if found:
        return found
    candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wsl.exe"
    return str(candidate) if candidate.is_file() else None


def _wsl_distros(wsl_path: str) -> list[str]:
    """列出已安装的 WSL 发行版（跳过 Docker 的内部发行版）。

    编码陷阱：`wsl -l -q` 在不同 WSL 版本下分别输出 UTF-16LE / UTF-8，
    用固定编码去解另一方的输出会得到乱码（实测把 `Ubuntu-24.04` 解成
    `潤正牥搭獥瑫灯搭瑡`，于是"找不到发行版"）。
    这里改成**按字节扫描 ASCII 名字**：发行版名本来就是 ASCII，
    无论 UTF-16LE 还是 UTF-8 都能从字节流里捞出来。
    """
    try:
        proc = subprocess.run(
            [wsl_path, "-l", "-q"],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = (proc.stdout or b"") + b" " + (proc.stderr or b"")
    # 扫描 [A-Za-z0-9._-]{2,} 片段；UTF-16LE 时字符之间会夹 \x00，先删掉空字节
    cleaned = raw.replace(b"\x00", b"")
    names: list[str] = []
    for match in re.finditer(rb"[A-Za-z0-9][A-Za-z0-9._-]{1,63}", cleaned):
        name = match.group(0).decode("ascii", errors="ignore").strip()
        if not name or name.startswith(("docker-desktop",)):
            continue
        # 排除 wsl 自身输出里的英文短语（"Windows Subsystem..." 之类）
        if name.lower() in ("windows", "subsystem", "for", "linux", "distribution",
                            "the", "and", "name", "state", "version"):
            continue
        if name not in names:
            names.append(name)
    return names


@dataclass(frozen=True)
class Runtime:
    """一个可用的执行运行时。"""

    kind: str            # docker / podman / wsl
    path: str            # 可执行文件路径
    distro: str = ""     # wsl 专用

    def describe(self) -> str:
        if self.kind == "wsl":
            return f"WSL ({self.distro})"
        return f"{self.kind} ({self.path})"


def detect_runtime(prefer: str = "", wsl_distro: str = "") -> Runtime | None:
    """探测可用的执行运行时。

    优先级：显式指定 > 安装包的 HexHound-Tools > Docker > Podman > WSL。

    为什么把 WSL 也算进来：Windows 上 Docker Desktop 经常是"装了但没启动 /
    装坏了 / 当前用户没权限连守护进程"，而这三种情况下 **WSL 里的工具链照样能用**。
    PentAGI / Strix 都要 Docker 才能跑，这里多一条退路。
    """
    if not prefer and not wsl_distro:
        wsl = _find_wsl()
        if wsl and "HexHound-Tools" in _wsl_distros(wsl):
            return Runtime("wsl", wsl, distro="HexHound-Tools")
    order = [prefer] if prefer else ["docker", "podman", "wsl"]
    for kind in order:
        if kind == "docker":
            path = _find_docker()
            if path:
                return Runtime("docker", path)
        elif kind == "podman":
            path = _find_podman()
            if path:
                return Runtime("podman", path)
        elif kind == "wsl":
            path = _find_wsl()
            if not path:
                continue
            distros = _wsl_distros(path)
            if not distros:
                continue
            chosen = wsl_distro if wsl_distro in distros else distros[0]
            return Runtime("wsl", path, distro=chosen)
    return None


class Sandbox:
    """一个扫描对应一个执行环境，命令在里面跑。

    三种后端，按可用性自动选择（见 `detect_runtime`）：

    - **docker / podman**：一个常驻容器，命令走 `docker exec`（Strix / PentAGI 的做法）
    - **wsl**：Windows 上直接借用 WSL 发行版里的工具链（Docker Desktop 坏了也能用）

    用法：
        sandbox = Sandbox(allowed_hosts=frozenset({"target.com"}))
        if sandbox.available():
            result = sandbox.run("nmap -sV -Pn target.com")
    """

    def __init__(
        self,
        *,
        allowed_hosts: frozenset[str] = frozenset(),
        image: str = "",
        exec_timeout: int = DEFAULT_EXEC_TIMEOUT,
        network: str = "bridge",
        memory_limit: str = "2g",
        cpu_limit: str = "2",
        workdir: str = "/work",
        verbose: bool = False,
        extra_hosts: dict[str, str] | None = None,
        prefer_runtime: str = "",
        wsl_distro: str = "",
        map_loopback: bool = True,
    ) -> None:
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts if host)
        self.image = image or DEFAULT_IMAGES[0]
        self.exec_timeout = max(5, int(exec_timeout))
        self.network = network
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.workdir = workdir
        self.verbose = verbose
        #: 容器内把某个名字映射到宿主（例如把靶场域名指回宿主机）——
        #: 用于"目标在宿主机上跑"的场景（`host.docker.internal` 在 Linux 上不可用）。
        self.extra_hosts = dict(extra_hosts or {})
        self.prefer_runtime = prefer_runtime
        self.wsl_distro = wsl_distro
        #: 是否把回环目标改写成宿主可达地址。目标本身就跑在执行环境里时应设为 False
        #: （例如靶场跑在 WSL 里，容器直接打 127.0.0.1 即可，改写反而打错地方）。
        self.map_loopback = bool(map_loopback)

        self._runtime: Runtime | None = detect_runtime(prefer_runtime, wsl_distro)
        self._container: str = ""
        self._lock = threading.Lock()
        self._exec_log: list[dict[str, Any]] = []
        self._host_map_notes: list[str] = []
        self._staged_scripts: list[Path] = []
        self._gateway: str = ""
        self._gateway_resolved = False
        #: nuclei 模板目录探测结果（None = 未探测）
        self._nuclei_dir: str | None = None
        self._counter = 0
        self._probe: dict[str, Any] | None = None

    # ---------- 能力探测 ----------

    @property
    def runtime(self) -> Runtime | None:
        return self._runtime

    @property
    def runtime_kind(self) -> str:
        return self._runtime.kind if self._runtime else "none"

    def available(self) -> bool:
        """执行环境是否可用（结果缓存：探测要跑一次子进程，没必要反复做）。"""
        if self._probe is not None:
            return bool(self._probe.get("ok"))
        runtime = self._runtime
        if runtime is None:
            self._probe = {
                "ok": False,
                "reason": "未找到可用的执行环境（Docker / Podman / WSL 都没有）",
                "hint": (
                    "Windows 上可以任选其一：\n"
                    "  1) 启动 Docker Desktop（需管理员）\n"
                    "  2) 装一个 WSL 发行版：wsl --install -d Ubuntu-24.04\n"
                    "     （不需要管理员，装完运行 `hexhound sandbox install` 装工具）"
                ),
            }
            return False
        if runtime.kind == "wsl":
            return self._probe_wsl(runtime)
        return self._probe_docker(runtime)

    def _probe_wsl(self, runtime: Runtime) -> bool:
        """WSL 探测：发行版能起来 + 至少有一个工具可用。"""
        probe = self._wsl_exec("true && echo ok", timeout=45)
        if probe.returncode != 0:
            self._probe = {
                "ok": False,
                "runtime": runtime.describe(),
                "reason": f"WSL 发行版 {runtime.distro} 无法执行命令："
                          f"{(probe.stderr or probe.stdout or '').strip()[:200]}",
            }
            return False
        tools = self._which_tools(runtime)
        present = [name for name, ok in tools.items() if ok]
        if not present:
            self._probe = {
                "ok": False,
                "runtime": runtime.describe(),
                "distro": runtime.distro,
                "reason": f"WSL 发行版 {runtime.distro} 里没有可用的渗透工具",
                "hint": "运行 `hexhound sandbox install` 安装（nmap / sqlmap / ffuf / nuclei …）",
                "tools": tools,
            }
            return False
        self._probe = {
            "ok": True,
            "runtime": runtime.describe(),
            "kind": "wsl",
            "distro": runtime.distro,
            "tools": tools,
            "tools_present": present,
        }
        return True

    def _probe_docker(self, runtime: Runtime) -> bool:
        try:
            proc = subprocess.run(
                [runtime.path, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=25, check=False,
                encoding="utf-8", errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._probe = {"ok": False, "reason": f"执行 {runtime.path} info 失败：{exc}"}
            return False
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            reason = detail[-1] if detail else f"退出码 {proc.returncode}"
            self._probe = {
                "ok": False,
                "runtime": runtime.describe(),
                "reason": f"容器守护进程不可用：{reason}",
                "hint": "Docker Desktop 未启动、或当前用户无权连接 docker 守护进程。",
            }
            return False
        self._probe = {
            "ok": True,
            "runtime": runtime.describe(),
            "kind": runtime.kind,
            "version": proc.stdout.strip(),
        }
        return True

    def probe(self) -> dict[str, Any]:
        """返回能力探测详情（供 CLI/报告展示为什么没用上真工具）。"""
        self.available()
        return dict(self._probe or {})

    def tool_status(self) -> dict[str, bool]:
        """容器/发行版里实际装了哪些工具（决定给 LLM 下发哪些能力）。"""
        if not self.available():
            return dict(self._probe.get("tools") or {}) if self._probe else {}
        if self._probe and self._probe.get("tools"):
            return dict(self._probe["tools"])
        runtime = self._runtime
        assert runtime is not None
        tools = self._which_tools(runtime)
        if self._probe is not None:
            self._probe["tools"] = tools
        return tools

    def images(self) -> list[str]:
        """本地已有镜像列表（仅 docker/podman）。"""
        runtime = self._runtime
        if runtime is None or runtime.kind == "wsl" or not self.available():
            return []
        proc = self._run_host([runtime.path, "images", "--format", "{{.Repository}}:{{.Tag}}"])
        return [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]

    def pick_image(self) -> str:
        """选一个可用镜像：优先本地已有，其次配置指定，最后按偏好拉取。"""
        local = set(self.images())
        if self.image in local:
            return self.image
        for candidate in DEFAULT_IMAGES:
            if candidate in local:
                self.image = candidate
                return candidate
        return self.image

    # ---------- 作用域强制（本模块的核心差异）----------

    def check_scope(self, command: str) -> str:
        """校验命令行里出现的主机都在白名单内；返回规范化后的命令行。

        抠取范围：显式 URL + 形如 `host.tld` 的裸主机。会忽略：
        - 文件名 / 路径（带 `/` 或已知扩展名）
        - localhost / 127.0.0.1（由调用方决定是否加入白名单，不默认放行）
        - 明显是工具参数的值（如 `--output=result.txt`）
        """
        if not self.allowed_hosts:
            raise ScopeViolation(
                "沙箱未配置白名单（ALLOWED_HOSTS 为空），拒绝执行任何网络命令。"
            )
        hosts: set[str] = set()
        for match in _URL_RE.findall(command):
            host = (urlparse(match).hostname or "").lower()
            if host:
                hosts.add(host)
        # 裸主机：只在命令看起来是网络工具时才抠，避免把文件名当主机
        first_token = command.strip().split()[0] if command.strip() else ""
        tool = Path(first_token).name
        if tool in TOOL_ALLOWLIST:
            # `python3 -c "import urllib.request"` 里的点号标识符会被域名正则误判成
            # 白名单外主机（实测报过 "白名单外的主机：urllib.request、out.append"），
            # 于是合法的 python 一行流全被拒。python3 命令只按 **URL 与裸 IP** 判定作用域。
            if tool != "python3":
                for candidate in _BARE_HOST_RE.findall(command):
                    lowered = candidate.lower()
                    if Path(lowered).suffix.lower() in (".txt", ".json", ".xml", ".html", ".log", ".py", ".sh"):
                        continue
                    hosts.add(lowered)
            # 裸 IP：域名正则认不出，单独抠（含 IPv6）
            for candidate in _BARE_IPV4_RE.findall(command):
                hosts.add(candidate.lower())
            for candidate in _BARE_IPV6_RE.findall(command):
                hosts.add(candidate.strip("[]").lower())
        outside = sorted(host for host in hosts if not scope_allows(self.allowed_hosts, host))
        if outside:
            raise ScopeViolation(
                "命令里出现白名单外的主机，已拒绝执行："
                + "、".join(outside)
                + f"（白名单：{', '.join(sorted(self.allowed_hosts))}）"
            )
        return command

    # ---------- 宿主可达地址映射 ----------
    #
    # 容器 / WSL 是**另一个网络命名空间**：靶场绑在宿主 127.0.0.1 时，容器里的
    # nmap/sqlmap 打 127.0.0.1 打的是容器自己（实测 nmap 报 "5000/tcp closed"）。
    # 因此这里把"回环地址"映射成宿主可达地址：
    #   - docker/podman：host.docker.internal（Docker Desktop 提供）
    #   - wsl：默认网关（即宿主在 WSL 虚拟网卡上的地址，实测 192.168.160.1）
    # 顺序很关键：**先按用户配置的白名单校验，再做地址替换**，
    # 这样作用域检查永远针对"用户声明的目标"，不会被映射绕过去。

    _LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

    #: 合法主机/IP 的形态（用于校验探测出来的网关，避免把整行路由输出当地址）
    _HOST_SHAPE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9.\-]{1,253})$", re.I)

    def host_gateway(self) -> str:
        """返回宿主在这个执行环境里的可达地址（探测一次并缓存）。

        为什么需要：容器 / WSL 是**另一个网络命名空间**。靶场绑在宿主 127.0.0.1 时，
        容器里的 nmap/sqlmap 打 127.0.0.1 打的是容器自己（实测报 "5000/tcp closed"）。
        映射成宿主地址后才能真正打到宿主上的目标。

        如果不映射（`map_loopback=False`，目标本身就跑在同一个环境里），
        这里返回空串，所有映射函数退化为原样返回。
        """
        if self._gateway_resolved:
            return self._gateway
        self._gateway_resolved = True
        if not self.map_loopback:
            self._gateway = ""
            return ""
        runtime = self._runtime
        candidate = ""
        if runtime is not None and runtime.kind == "wsl":
            # 用脚本文件执行（带管道的命令在 -lc 里会被拆坏，见 _wsl_exec 注释）
            proc = self._wsl_exec(
                "ip route show default | awk '/default/ {print $3; exit}'", timeout=45
            )
            raw = (proc.stdout or "").strip()
            for line in reversed(raw.splitlines()):
                line = line.strip()
                if line and self._HOST_SHAPE.match(line):
                    candidate = line
                    break
        if not candidate:
            candidate = "host.docker.internal"
        self._gateway = candidate
        return candidate

    def map_host(self, host: str) -> str:
        """把回环主机名映射成宿主可达地址（其余主机原样返回）。"""
        lowered = (host or "").lower()
        if self.map_loopback and lowered in self._LOOPBACK:
            return self.host_gateway()
        return host

    def resolve_command(self, command: str) -> str:
        """把命令行里的回环地址替换成宿主可达地址（在校验作用域**之后**调用）。"""
        if not self.map_loopback:
            return command
        gateway = self.host_gateway()
        if not gateway:
            return command
        resolved = command
        for loopback in ("127.0.0.1", "localhost", "0.0.0.0"):
            if loopback in resolved:
                resolved = re.sub(
                    rf"(?<![\w.]){re.escape(loopback)}(?![\w.])", gateway, resolved
                )
        return resolved

    def resolve_url(self, url: str) -> str:
        """把 URL 里的回环主机换成宿主可达地址（给上层构造命令时用）。"""
        parsed = urlparse(url)
        if not parsed.hostname:
            return url
        mapped = self.map_host(parsed.hostname)
        if mapped == parsed.hostname:
            return url
        netloc = mapped + (f":{parsed.port}" if parsed.port else "")
        return parsed._replace(netloc=netloc).geturl()

    def check_tool(self, command: str) -> str:
        """校验命令用的是白名单工具，且不含禁止参数。"""
        stripped = command.strip()
        if not stripped:
            raise ValueError("命令为空。")
        first = stripped.split()[0]
        tool = Path(first).name
        if tool not in TOOL_ALLOWLIST:
            allowed = "、".join(sorted(TOOL_ALLOWLIST))
            raise ValueError(
                f"沙箱只允许执行预置工具（{allowed}），收到 {tool!r}。"
                "这是刻意的限制：容器不是给你一个任意 shell。"
            )
        low = stripped.lower()
        for token in FORBIDDEN_ARGS:
            if token.lower() in low:
                raise ValueError(
                    f"命令含禁止参数 {token!r}（破坏性 / 提权 / 反弹类），已拒绝执行。"
                    "HexHound 只做只读验证。"
                )
        return stripped

    # ---------- 容器生命周期 ----------

    def start(self, *, pull: bool = True) -> str:
        """启动常驻执行环境（docker/podman 起容器；wsl 无需启动）。

        返回环境标识（容器名 / 发行版名）。
        """
        runtime = self._runtime
        if runtime is None:
            raise RuntimeError(self.probe().get("reason", "没有可用的执行环境"))
        if runtime.kind == "wsl":
            # WSL 发行版常驻，按需唤醒即可；这里只确认可用。
            if not self.available():
                raise RuntimeError(self.probe().get("reason", "WSL 环境不可用"))
            return runtime.distro
        if self._container:
            return self._container
        if not self.available():
            raise RuntimeError(self.probe().get("reason", "容器运行时不可用"))
        image = self.pick_image()
        if pull and image not in set(self.images()):
            pulled = self._run_host([runtime.path, "pull", image], timeout=1800)
            if pulled.returncode != 0:
                raise RuntimeError(
                    f"拉取镜像 {image} 失败：{(pulled.stderr or '').strip()[:300]}"
                )
        name = f"{CONTAINER_PREFIX}{uuid.uuid4().hex[:10]}"
        args = [
            runtime.path, "run", "-d", "--name", name,
            "--label", "hexhound=1",
            # 容器内约束：去掉全部 capabilities、禁止提权、限制资源
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", self.memory_limit,
            "--cpus", self.cpu_limit,
            "--pids-limit", "512",
            "-w", self.workdir,
            "--entrypoint", "sh",
        ]
        for host, address in self.extra_hosts.items():
            args += ["--add-host", f"{host}:{address}"]
        args += [image, "-c", f"mkdir -p {self.workdir} 2>/dev/null; tail -f /dev/null"]
        proc = self._run_host(args, timeout=180)
        if proc.returncode != 0:
            raise RuntimeError(
                f"启动容器失败：{(proc.stderr or proc.stdout or '').strip()[:300]}"
            )
        self._container = name
        return name

    def stop(self, remove: bool = True) -> None:
        """停止（默认删除）容器；WSL 后端什么都不用做。"""
        runtime = self._runtime
        if runtime is None or runtime.kind == "wsl" or not self._container:
            self._container = ""
            return
        action = ["rm", "-f", self._container] if remove else ["stop", self._container]
        self._run_host([runtime.path, *action], timeout=120)
        self._container = ""

    def __enter__(self) -> Sandbox:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---------- 执行 ----------

    def run(
        self,
        command: str,
        *,
        timeout: int | None = None,
        check_scope: bool = True,
        check_tool: bool = True,
    ) -> ExecResult:
        """执行一条命令（默认含工具白名单 + 作用域双重校验）。

        `check_tool=False` 是给**内部运维操作**用的（安装工具、拷文件、探测环境）——
        那些命令天然要用 cp/tr/base64，不是给模型用的能力。作用域校验仍可独立开关，
        默认保持开启；只有明确的本地文件操作才关掉。
        """
        return self._execute(
            command, timeout=timeout, check_scope=check_scope, check_tool=check_tool
        )

    def _execute(
        self,
        command: str,
        *,
        timeout: int | None = None,
        check_scope: bool = True,
        check_tool: bool = True,
        script: str = "",
        resolve: bool = True,
    ) -> ExecResult:
        """run() 的实现体；`script` 仅由脚本通道传入（用于证据与报告渲染）。

        `resolve=False`：调用方已经自己做过回环映射（脚本通道就是对脚本文本做的），
        不能再对 base64 后的启动命令做一次字符串替换——那会改坏护栏里的白名单。
        """
        exec_id = self._next_id()
        started = time.time()
        try:
            if check_tool:
                command = self.check_tool(command)
            if check_scope:
                command = self.check_scope(command)
        except (ValueError, ScopeViolation) as exc:
            return ExecResult(
                ok=False, command=command, error=str(exc), exec_id=exec_id,
                scope_checked=check_scope,
            )
        # 校验通过后再做宿主地址映射：作用域永远按"用户声明的目标"判定。
        original = command
        if resolve:
            command = self.resolve_command(command)
        runtime = self._runtime
        if runtime is None:
            return ExecResult(
                ok=False, command=command, exec_id=exec_id,
                error=self.probe().get("reason", "没有可用的执行环境"),
            )
        if runtime.kind != "wsl" and not self._container:
            try:
                self.start()
            except RuntimeError as exc:
                return ExecResult(ok=False, command=command, error=str(exc), exec_id=exec_id)

        if runtime.kind == "wsl":
            proc = self._wsl_exec(command, timeout=timeout or self.exec_timeout)
        else:
            proc = self._run_host(
                [runtime.path, "exec", "-w", self.workdir, self._container,
                 "sh", "-lc", command],
                timeout=timeout or self.exec_timeout,
            )
        duration = time.time() - started
        stdout, cut_out = _clip(proc.stdout or "")
        stderr, cut_err = _clip(proc.stderr or "")
        # 先清理再落盘：报告与模型上下文里都不该出现 ANSI/OSC 控制序列与裸 \r
        # （sqlmap 带 `\x1b[?1049h`，进度行用 `\r` 原地刷新，实测都会污染输出）。
        stdout = sanitize_terminal_text(stdout)
        stderr = sanitize_terminal_text(stderr)
        result = ExecResult(
            ok=proc.returncode == 0,
            command=command,
            original_command=original,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            exec_id=exec_id,
            truncated=cut_out or cut_err,
            error="" if proc.returncode == 0 else f"退出码 {proc.returncode}",
            script=script,
        )
        if command != original:
            # 记录映射关系，报告里能看出"命令实际发往哪个地址"
            with self._lock:
                self._host_map_notes.append(f"{original}  ->  {command}")
        with self._lock:
            self._exec_log.append(result.to_dict())
        if self.verbose:
            print(f"[sandbox {exec_id}] $ {command} -> rc={proc.returncode} ({duration:.1f}s)")
        return result

    # ---------- 自定义脚本通道 ----------
    #
    # 为什么需要：竞态（并发窗口）、业务逻辑（多步状态机）、加密实现（要对密文做
    # 统计/爆破）这三类问题，**一条命令表达不出来**。Strix 有 race_conditions /
    # business_logic 两份 skill 手册，靠的就是"写脚本再跑"；HexHound 之前只有
    # 固定工具与内置 HTTP 探测，模型根本没有表达并发序列的地方。
    #
    # 代价与约束（必须说清楚）：脚本比命令行强大得多，所以这里做**两层**作用域约束：
    #   1. 静态扫描脚本正文（URL / 裸 IP / 引号里的域名 / 禁止片段）；
    #   2. 运行时护栏（_SCRIPT_GUARD）：进程内接管 getaddrinfo 与 socket.connect，
    #      拼接、base64、f-string 拼出来的域名在发包前一样会被拒。
    # 仍然不是"安全沙箱"：脚本在沙箱里以 root 运行，护栏是防越界与防破坏，不是防提权。

    def check_script(self, script: str) -> str:
        """静态校验脚本正文：主机必须在白名单内，且不含破坏性 / 反弹片段。"""
        text = str(script or "")
        if not text.strip():
            raise ValueError("脚本为空。")
        if len(text) > 20000:
            raise ValueError(f"脚本过长（{len(text)} 字符，上限 20000）。请拆成多次调用。")
        if not self.allowed_hosts:
            raise ScopeViolation(
                "沙箱未配置白名单（ALLOWED_HOSTS 为空），拒绝执行任何脚本。"
            )
        low = text.lower()
        for token, why in FORBIDDEN_SCRIPT_PATTERNS:
            if token.lower() in low:
                raise ValueError(
                    f"脚本含禁止片段 {token!r}（{why}），已拒绝执行。"
                    "脚本通道只用于**只读验证**：并发请求、密文分析、状态机重放。"
                )
        hosts: set[str] = set()
        for match in _URL_RE.findall(text):
            host = (urlparse(match).hostname or "").lower()
            if host:
                hosts.add(host)
        for candidate in _BARE_IPV4_RE.findall(text):
            hosts.add(candidate.lower())
        for candidate in _BARE_IPV6_RE.findall(text):
            hosts.add(candidate.strip("[]").lower())
        # 引号/字典里的裸域名：脚本里最常见的形式是 "http://host" 或 {"host": ...}
        for candidate in re.findall(r"""['"]([a-z0-9][a-z0-9.\-]{2,253}\.[a-z]{2,24})['"]""", text, re.I):
            hosts.add(candidate.lower())
        outside = sorted(host for host in hosts if not scope_allows(self.allowed_hosts, host))
        if outside:
            raise ScopeViolation(
                "脚本里出现白名单外的主机，已拒绝执行："
                + "、".join(outside)
                + f"（白名单：{', '.join(sorted(self.allowed_hosts))}）"
            )
        return text

    def run_script(
        self,
        script: str,
        *,
        interpreter: str = "python3",
        timeout: int | None = None,
    ) -> ExecResult:
        """在沙箱里执行一段自定义脚本（只有 python3 受支持）。

        执行方式：`护栏 + 脚本` 整体 base64 后，用**单行**启动器写入沙箱内的临时文件并 exec。

        **为什么必须是单行**（实测踩过的坑，整条通道因此静默失效）：最早把多行
        护栏直接塞进 `python3 -c "..."`，中间经过 `json.dumps` 与 bash 两层解析后，
        真正的换行变成了字面量 `\\n`，而 `python3 -c` 不解释 `\\n` 转义 →
        `SyntaxError: unexpected character after line continuation character`，
        每一次脚本调用都失败。现在启动器里**一个换行都没有**（只有分号），
        换行与中文全部藏在 base64 里，三层解析都拆不坏。
        """
        exec_id = self._next_id()
        started = time.time()
        try:
            original = self.check_script(script)
        except (ValueError, ScopeViolation) as exc:
            return ExecResult(
                ok=False, command="", error=str(exc), exec_id=exec_id, script=str(script or "")
            )
        if interpreter != "python3":
            return ExecResult(
                ok=False, command="", exec_id=exec_id, script=original,
                error=f"脚本通道只支持 python3，收到 {interpreter!r}。",
            )
        # 先做回环映射（脚本正文），再生成护栏：护栏里的白名单必须是映射后的地址集合。
        mapped = self.resolve_command(original)
        allowed = set(self.allowed_hosts)
        gateway = self.host_gateway()
        if gateway:
            allowed.add(gateway)
        allowed.add("localhost")
        guard = _SCRIPT_GUARD.format(allow=sorted(allowed))
        payload = base64.b64encode((guard + "\n" + mapped).encode("utf-8")).decode("ascii")
        target = f"/tmp/hexhound-script-{uuid.uuid4().hex[:8]}.py"
        launcher = (
            "import base64 as _b, pathlib as _p;"
            f"_f = {target!r};"
            f"_p.Path(_f).write_bytes(_b.b64decode({payload!r}));"
            "exec(compile(_p.Path(_f).read_bytes(), '<hexhound-script>', 'exec'))"
        )
        if "\n" in launcher:  # 自检：启动器一旦出现换行，上面那条坑就会重现
            return ExecResult(
                ok=False, command="", exec_id=exec_id, script=original,
                error="内部错误：脚本启动器含换行，已拒绝执行（会破坏 shell 解析）。",
            )
        command = f"python3 -c {json.dumps(launcher)}"
        result = self._execute(
            command, timeout=timeout, check_scope=False, check_tool=False,
            script=original, resolve=False,
        )
        result.original_command = original[:2000]
        result.duration = time.time() - started
        if self.verbose:
            print(f"[sandbox {exec_id}] <script {len(original)} chars> -> rc={result.exit_code}")
        return result

    # ---------- WSL 后端 ----------

    def _wsl_exec(self, command: str, *, timeout: int = 120) -> subprocess.CompletedProcess:
        """在 WSL 发行版里执行命令（以 root，便于工具访问需要权限的路径）。

        传参陷阱：`wsl.exe -d X -u root -- bash -lc "<命令>"` 这条链路要穿过
        PowerShell → wsl.exe → bash 三层引号解析，实测带管道/awk/变量的命令会在
        某一层被拆坏（`ip route | awk ...` 直接没执行，返回整行路由输出）。
        所以**任何带管道或引号的命令都改写成临时脚本文件**，让 WSL 通过
        `/mnt/c/...` 直接读——JSON 字符串进、bash 脚本出，中间不经过 shell 解析。
        """
        runtime = self._runtime
        assert runtime is not None and runtime.kind == "wsl"
        needs_file = any(token in command for token in ("|", ">", "<", "'", '"', "$(", "\\n"))
        script = (
            f"cd {self.workdir} 2>/dev/null || cd /root\n{command}\n"
            if needs_file
            else f"cd {self.workdir} 2>/dev/null || cd /root; {command}"
        )
        args = [runtime.path, "-d", runtime.distro, "-u", "root", "--"]
        if needs_file:
            args += ["bash", self._stage_script(script)]
        else:
            args += ["bash", "-lc", script]
        return self._run_host(args, timeout=timeout)

    def _stage_script(self, script: str) -> str:
        """把脚本写到 Windows 临时目录，返回 WSL 侧可读的 /mnt/... 路径。

        用 ASCII 安全的文件名 + UTF-8 内容；WSL 通过 /mnt/c/... 读取，
        完全绕过命令行引号与编码问题（这条路径已实测可靠）。
        """
        import tempfile

        name = f"hexhound-wsl-{uuid.uuid4().hex[:8]}.sh"
        host_path = Path(tempfile.gettempdir()) / name
        host_path.write_text(script, encoding="utf-8", newline="\n")
        resolved = str(host_path.resolve())
        mount = "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")
        self._staged_scripts.append(host_path)
        return mount

    def cleanup_staged(self) -> None:
        """清理本次运行产生的临时脚本。"""
        for path in self._staged_scripts:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        self._staged_scripts.clear()

    def _which_tools(self, runtime: Runtime) -> dict[str, bool]:
        """检查白名单工具是否存在（并行逐个检查）。

        为什么不用 `for t in ...; done` 一把梭：那个内联循环要穿过
        PowerShell → wsl.exe → bash -lc 三层引号，实测 `$t` 会在某一层被提前
        展开，输出全变成 `=0`（明明装了也报没装）。改成每个工具一条独立命令，
        命令里不含 shell 变量，任何一层都没法把它搞坏。
        """
        status: dict[str, bool] = {name: False for name in TOOL_ALLOWLIST}
        if runtime.kind != "wsl" and not self._container:
            return status

        def check(name: str) -> tuple[str, bool]:
            cmd = f"command -v {name}"
            if runtime.kind == "wsl":
                proc = self._wsl_exec(cmd, timeout=45)
            else:
                proc = self._run_host(
                    [runtime.path, "exec", self._container, "sh", "-lc", cmd], timeout=45
                )
            lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            # command -v 成功时会打印路径；失败时退出码非 0（stderr 可能有噪音）
            return name, proc.returncode == 0 and bool(lines)

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=4) as pool:
            for name, present in pool.map(check, list(TOOL_ALLOWLIST)):
                status[name] = present
        return status

    def install_tools(self, script: str | Path | None = None) -> ExecResult:
        """在 WSL 发行版/容器里安装工具链（跑 docker/install-tools.sh）。

        只在 WSL 后端下有意义（容器镜像应当自带工具）。
        """
        runtime = self._runtime
        if runtime is None:
            return ExecResult(ok=False, error="没有可用的执行环境", exec_id=self._next_id())
        source = Path(script) if script else Path(__file__).resolve().parents[2] / "docker" / "install-tools.sh"
        if not source.is_file():
            return ExecResult(
                ok=False, error=f"找不到安装脚本：{source}", exec_id=self._next_id()
            )
        if runtime.kind == "wsl":
            # 通过 /mnt/<drive>/... 让 WSL 直接读宿主文件，避免跨编码传文件
            win_path = str(source.resolve())
            mount = "/mnt/" + win_path[0].lower() + win_path[2:].replace("\\", "/")
            return self.run(
                f"bash {_quote(mount)}", timeout=3600,
                check_scope=False, check_tool=False,
            )
        return ExecResult(
            ok=False,
            error="容器后端不需要安装脚本：请用自带工具的镜像（见 docker/Dockerfile）。",
            exec_id=self._next_id(),
        )

    def fetch_via_host(self, url: str, dest: str, *, timeout: int = 900) -> ExecResult:
        """在**宿主**（Windows）侧下载文件，再送进执行环境。

        为什么需要这条路径（本机实测的坑）：Windows 上常装 Steam++/Watt Toolkit
        这类加速器，它把 github.com 写进 hosts 指向 127.0.0.1，并在本地 443 起反代——
        于是**浏览器和 Windows 命令行都能上 GitHub，但 WSL 不能**（WSL 不读 Windows hosts，
        有自己的 resolv.conf，直连真 GitHub 会被重置）。
        因此在 Windows 跑 HexHound 时，最可靠的下载路径是：宿主下载 → 拷进 WSL/容器。
        """
        runtime = self._runtime
        if runtime is None:
            return ExecResult(ok=False, error="没有可用的执行环境", exec_id=self._next_id())
        if sys.platform != "win32":
            return ExecResult(
                ok=False, error="宿主侧下载仅在 Windows 上可用", exec_id=self._next_id()
            )
        try:
            import tempfile
            import urllib.request

            target = Path(tempfile.gettempdir()) / f"hexhound-dl-{uuid.uuid4().hex[:8]}"
            with urllib.request.urlopen(url, timeout=min(timeout, 300)) as response:
                data = response.read()
            target.write_bytes(data)
        except Exception as exc:  # noqa: BLE001 网络异常转成可读结果
            return ExecResult(
                ok=False, command=f"GET {url}", error=f"宿主下载失败：{exc}",
                exec_id=self._next_id(),
            )
        size_mb = round(len(data) / (1024 * 1024), 2)
        if runtime.kind == "wsl":
            # 通过 /mnt/c/... 让 WSL 直接读宿主文件，避免管道与编码问题
            resolved = str(target.resolve())
            mount = "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")
            result = self.run(
                f"cp {_quote(mount)} {_quote(dest)} && ls -l {_quote(dest)}",
                timeout=300,
                check_scope=False, check_tool=False,
            )
            target.unlink(missing_ok=True)
            if result.ok:
                existing = result.stdout
                result.stdout = f"宿主下载 {url}（{size_mb} MB）→ {dest}\n{existing}"
            return result
        return ExecResult(
            ok=False, error="容器后端请用镜像内的工具（或自行 docker cp）",
            exec_id=self._next_id(),
        )

    def install_binary_via_host(self, name: str, url: str) -> ExecResult:
        """在宿主下载 Go 工具压缩包、解压后把可执行文件装进执行环境。

        用于 GitHub 在 WSL 内不可达、但宿主可达（加速器场景）的机器。
        """
        runtime = self._runtime
        if runtime is None or runtime.kind != "wsl":
            return ExecResult(
                ok=False, error="此安装路径仅支持 WSL 后端", exec_id=self._next_id()
            )
        try:
            import tempfile
            import urllib.request
            import zipfile

            work = Path(tempfile.mkdtemp(prefix="hexhound-tool-"))
            archive = work / "pkg"
            with urllib.request.urlopen(url, timeout=300) as response:
                archive.write_bytes(response.read())
            binary_name = name
            with zipfile.ZipFile(archive) as zf:
                member = next(
                    (n for n in zf.namelist() if n.split("/")[-1] == binary_name), None
                )
                if member is None:
                    return ExecResult(
                        ok=False, error=f"压缩包里没有 {binary_name}",
                        exec_id=self._next_id(),
                    )
                zf.extract(member, work)
                extracted = work / member
            payload = base64.b64encode(extracted.read_bytes()).decode("ascii")
            # 走 base64 传二进制：避免 /mnt/c 的权限位与换行问题
            staged = Path(tempfile.gettempdir()) / f"hexhound-bin-{uuid.uuid4().hex[:8]}.b64"
            staged.write_text(payload, encoding="ascii")
            resolved = str(staged.resolve())
            mount = "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")
            result = self.run(
                f"tr -d '\\r\\n' < {_quote(mount)} | base64 -d > /usr/local/bin/{name} "
                f"&& chmod 0755 /usr/local/bin/{name} && {name} --version | head -1",
                timeout=300,
                check_scope=False, check_tool=False,
            )
            staged.unlink(missing_ok=True)
            return result
        except Exception as exc:  # noqa: BLE001
            return ExecResult(
                ok=False, error=f"{name} 宿主侧安装失败：{exc}", exec_id=self._next_id()
            )

    def build_image(self, dockerfile: str | Path | None = None, tag: str = "hexhound-sandbox:latest") -> ExecResult:
        """用 lib 里的 Dockerfile 构建镜像（docker/podman 后端）。"""
        runtime = self._runtime
        if runtime is None or runtime.kind == "wsl":
            return ExecResult(
                ok=False, error="当前后端不支持构建镜像（需要 docker/podman）",
                exec_id=self._next_id(),
            )
        source = Path(dockerfile) if dockerfile else Path(__file__).resolve().parents[2] / "docker"
        proc = self._run_host(
            [runtime.path, "build", "-t", tag, str(source)], timeout=3600
        )
        return ExecResult(
            ok=proc.returncode == 0,
            command=f"build {tag}",
            exit_code=proc.returncode,
            stdout=(proc.stdout or "")[-4000:],
            stderr=(proc.stderr or "")[-4000:],
            exec_id=self._next_id(),
        )

    # ---------- 预置工具封装 ----------

    def sqlmap(self, url: str, *, extra: str = "", timeout: int = 600) -> ExecResult:
        """只读模式的 sqlmap：探测注入并尝试取库名/版本（不碰数据、不写文件）。

        强制约束 `--risk=1`：risk=2 会启用基于时间的盲注等更重的 payload，
        在真实目标上可能造成明显负载。封装的默认值必须真正生效——
        实测模型会在 extra 里自己加 `--risk=2`，所以这里做去重覆盖，
        让它无法绕过"只读、轻量"这条线（见 _dedupe_sqlmap_flags）。
        """
        command = (
            "sqlmap -u " + _quote(url)
            + " --batch --disable-coloring --flush-session --level=2 --risk=1"
            " --technique=BEU --threads=2 --timeout=15 --retries=1"
        )
        if extra:
            command = _dedupe_sqlmap_flags(command + " " + extra)
        return self.run(command, timeout=timeout)

    def nmap(self, host: str, *, ports: str = "top", extra: str = "") -> ExecResult:
        """端口与服务发现（只做 -sV 的轻扫，不做 -sS 全端口）。"""
        port_flag = "--top-ports 1000" if ports == "top" else f"-p {ports}"
        command = f"nmap -sV -Pn -T4 {port_flag} --version-light --host-timeout 120s {host}"
        if extra:
            command += " " + extra
        # nmap 的裸主机不会被 _BARE_HOST_RE 之外的写法绕过——但 host 形如
        # "127.0.0.1"（无点分域名）时正则抠不到，因此显式再校验一次。
        outside = [h for h in [host.lower()] if h and not scope_allows(self.allowed_hosts, h)]
        if outside:
            return ExecResult(
                ok=False, command=command, exec_id=self._next_id(),
                error=f"拒绝：主机 {outside[0]!r} 不在白名单内。",
            )
        return self.run(command, timeout=300)

    #: nuclei 模板目录候选（手动安装的模板不会被 nuclei 自动发现，必须显式 -t）
    NUCLEI_TEMPLATE_DIRS = (
        "/root/.local/nuclei-templates",
        "/root/nuclei-templates",
        "/opt/nuclei-templates",
        "/usr/share/nuclei-templates",
    )

    #: nuclei 默认模板类目。**实测数据**（对靶场一个端点）：
    #:   http/misconfiguration  508 模板 / 20s
    #:   http/exposures         216 模板 / 33s
    #:   http/default-logins    205 模板 / 15s
    #:   http/cves              数千模板 / 数分钟（要跑全量时用 categories="full"）
    #: 默认这四类是"web 评估投入产出比"最高的；全量 4488 模板要 ~9600 请求 / 146s，
    #: 对多代理 + 有预算的场景不划算。
    NUCLEI_TEMPLATE_CATEGORIES = (
        "http/misconfiguration",
        "http/exposures",
        "http/default-logins",
        "http/exposed-panels",
    )
    #: `categories="full"` 时使用的完整类目
    NUCLEI_FULL_CATEGORIES = (
        "http/cves",
        "http/vulnerabilities",
        "http/misconfiguration",
        "http/exposures",
        "http/default-logins",
        "http/exposed-panels",
        "http/takeovers",
        "http/cnvd",
    )

    def nuclei(self, url: str, *, severity: str = "medium,high,critical",
               templates: str = "", timeout: int = 600,
               categories: tuple[str, ...] | str | None = None) -> ExecResult:
        """模板化扫描（默认只跑 4 个高性价比类目，默认中高危）。

        两个必须的细节：
        1. **显式 `-t`**：nuclei 只在自己配置目录里找模板，手动安装的模板库不会被
           自动发现（实测报 "no templates provided for scan"）。
        2. **收窄类目**：不加子目录会跑全部 4488 个模板（~9600 请求 / 146s），
           对"多代理 + 有预算"的场景不划算。`categories="full"` 可显式要全量。
        """
        base = templates or self._nuclei_templates()
        if not base:
            return ExecResult(
                ok=False, command="nuclei", exec_id=self._next_id(),
                error=(
                    "找不到 nuclei 模板库。Windows 上 GitHub 常只在宿主侧可达"
                    "（加速器场景），运行 `hexhound sandbox templates` 下载安装。"
                ),
            )
        if categories == "full":
            cats: tuple[str, ...] = self.NUCLEI_FULL_CATEGORIES
        elif categories is None:
            cats = self.NUCLEI_TEMPLATE_CATEGORIES
        elif isinstance(categories, str):
            cats = (categories,)
        else:
            cats = tuple(categories)
        command = (
            f"nuclei -u {_quote(url)} -severity {severity} -no-color "
            "-stats=false -timeout 10 -retries 1 -rate-limit 60"
        )
        for category in cats:
            path = category if category.startswith("/") else base.rstrip("/") + "/" + category
            command += f" -t {_quote(path)}"
        return self.run(command, timeout=timeout)

    def _nuclei_templates(self) -> str:
        """探测可用的 nuclei 模板目录（缓存）。"""
        if self._nuclei_dir is not None:
            return self._nuclei_dir
        runtime = self._runtime
        for candidate in self.NUCLEI_TEMPLATE_DIRS:
            if runtime is not None and runtime.kind == "wsl":
                probe = self._wsl_exec(
                    f"test -d {candidate} && find {candidate} -name '*.yaml' | head -1",
                    timeout=60,
                )
                if (probe.stdout or "").strip():
                    self._nuclei_dir = candidate
                    return candidate
        self._nuclei_dir = ""
        return ""

    def install_nuclei_templates(self, source_dir: str | Path | None = None) -> ExecResult:
        """把模板库装到 nuclei 能找到的位置。

        两种来源：
        - 给了 `source_dir`（宿主机上已解压的模板目录）→ 直接拷进去；
        - 没给则在**宿主侧**下载官方模板包再解压（适配"GitHub 只在 Windows 可达"的机器：
          WSL 不读 Windows hosts，直连 GitHub 会被重置）。
        解压交给 WSL 的 tar：Windows 的 tar.exe 处理不了模板里个别特殊文件名。
        """
        import tempfile
        import urllib.request

        runtime = self._runtime
        if runtime is None or runtime.kind != "wsl":
            return ExecResult(
                ok=False, error="模板安装目前只支持 WSL 后端", exec_id=self._next_id()
            )
        dest = "/root/.local/nuclei-templates"
        if source_dir is None:
            work = Path(tempfile.mkdtemp(prefix="hexhound-tpl-"))
            archive = work / "templates.tar.gz"
            url = (
                "https://github.com/projectdiscovery/nuclei-templates/"
                "archive/refs/heads/main.tar.gz"
            )
            try:
                with urllib.request.urlopen(url, timeout=600) as response:
                    archive.write_bytes(response.read())
            except Exception as exc:  # noqa: BLE001
                return ExecResult(
                    ok=False, command=f"GET {url}",
                    error=f"宿主侧下载模板失败：{exc}", exec_id=self._next_id(),
                )
            resolved = str(archive.resolve())
            mount = "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")
            result = self.run(
                "rm -rf /tmp/hexhound-tpl && mkdir -p /tmp/hexhound-tpl && "
                f"tar -xzf {_quote(mount)} -C /tmp/hexhound-tpl --strip-components=1 && "
                f"rm -rf {dest} && mv /tmp/hexhound-tpl {dest}",
                timeout=900, check_scope=False, check_tool=False,
            )
            archive.unlink(missing_ok=True)
        else:
            resolved = str(Path(source_dir).resolve())
            mount = "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")
            result = self.run(
                f"rm -rf {dest} && cp -r {_quote(mount)} {dest}",
                timeout=900, check_scope=False, check_tool=False,
            )
        if not result.ok:
            return result
        # nuclei 只认自己配置目录下的模板：建软链让它发现
        link = self.run(
            "mkdir -p /root/.config/nuclei && "
            "rm -rf /root/.config/nuclei/nuclei-templates && "
            f"ln -s {dest} /root/.config/nuclei/nuclei-templates && "
            f"find {dest} -name '*.yaml' | wc -l",
            timeout=300, check_scope=False, check_tool=False,
        )
        self._nuclei_dir = None
        return link

    def ffuf(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
             *, extra: str = "", timeout: int = 600) -> ExecResult:
        """目录模糊测试（默认用镜像里最小的内置词表）。"""
        command = (
            f"ffuf -u {_quote(url.rstrip('/'))}/FUZZ -w {wordlist} "
            "-mc 200,204,301,302,307,401,403,405,500 -t 20 -timeout 8 -s"
        )
        if extra:
            command += " " + extra
        return self.run(command, timeout=timeout)

    def whatweb(self, url: str, *, timeout: int = 180) -> ExecResult:
        """技术栈指纹（whatweb）。

        **不能用 `-q`**（实测踩过的静默失效，代价是这个工具一直是"有输出但没人看"）：

            $ whatweb -q --no-errors http://127.0.0.1:5000/
            (空输出, exit=0)          ← -q 连结果行一起吞掉

            $ whatweb --no-errors --color=never http://127.0.0.1:5000/
            http://127.0.0.1:5000/ [200 OK] HTML5, HTTPServer[Werkzeug/3.0.1 …], Title[…]

        `--quiet/-q` 的官方说明是 "Do not display brief logging to STDOUT"，
        但实际实现里 brief logging **就是**结果输出本身，于是 `-q` 把
        "你要的结果"和"你不想要的日志"一起吞了。这里改用 `--no-errors`
        （只压错误噪音）+ `--color=never`（不给结果加 SGR 配色）——
        既拿到完整结果，又不必依赖下游清理 ANSI。
        """
        flags = "--no-errors --color=never"
        timeout_flag = f"--open-timeout={self._whatweb_timeout(timeout)}"
        return self.run(
            f"whatweb {flags} {timeout_flag} {_quote(url)}", timeout=timeout
        )

    @staticmethod
    def _whatweb_timeout(timeout: int) -> int:
        """whatweb 的连接超时：不超过整体超时的一半，且至少 5 秒。"""
        return max(5, min(15, int(max(1, timeout) // 2)))

    def curl(self, args: str, *, timeout: int = 120) -> ExecResult:
        """原始 HTTP（用于核对证据）。args 里必须带 URL。"""
        return self.run(f"curl -sS -i --max-time 20 {args}", timeout=timeout)

    def tools_status(self) -> dict[str, bool]:
        """检查容器里实际装了哪些工具（用于决定给 LLM 下发哪些能力）。"""
        if not self.available():
            return {}
        status: dict[str, bool] = {}
        for tool in TOOL_ALLOWLIST:
            result = self.run(f"command -v {tool} >/dev/null 2>&1 && echo ok", timeout=60)
            status[tool] = result.stdout.strip() == "ok"
        return status

    # ---------- 内部 ----------

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"X{self._counter}"

    @staticmethod
    def _host_env() -> dict[str, str]:
        """执行子进程时的环境变量：把「输出编码」这件事钉死。

        为什么需要（实测踩过的坑）：

        - `wsl.exe` 自 Windows 10 1903 起会**嗅探**宿主控制台代码页来决定输出编码：
          在 GBK 控制台下回 UTF-16LE/GBK，在 UTF-8 控制台下回 UTF-8。同一个发行版
          在同一台机器上"有时乱码有时正常"就是这么来的。官方开关是 `WSL_UTF8=1`，
          它强制 wsl.exe 输出 UTF-8。
        - 沙箱里的 Python 脚本（`sandbox_script`）若在 GBK locale 下 `print` 中文，
          会直接 `UnicodeEncodeError` 让脚本中途崩掉——那会被误读成"脚本有问题"。
          `PYTHONIOENCODING=utf-8` + `PYTHONUTF8=1` 把它关掉。
        - `LANG` / `LC_ALL` 影响 coreutils 与部分工具的错误信息语言与编码。

        这些变量对 docker/podman 后端同样无害，因此不分后端统一设置。
        """
        env = dict(os.environ)
        env["WSL_UTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env.setdefault("LANG", "C.UTF-8")
        env.setdefault("LC_ALL", "C.UTF-8")
        return env

    def _run_host(self, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
        """执行宿主侧子进程，**按字节取输出**再自行解码。

        为什么不用 `text=True, encoding="utf-8"`：那等于把"解码"交给
        `subprocess` 的通用回退逻辑，遇到非法字节仍然会出现替换字符甚至乱码，
        而且无法在 UTF-8 / UTF-16LE 之间做二次判断（`wsl.exe -l -q` 就是后者）。
        这里 `capture_output` 拿原始字节，交给 `sanitize.decode_output` 处理：
        非法字节安全替换，UTF-16LE 嗅探，永不抛异常。
        """
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=self._host_env(),
        )
        return subprocess.CompletedProcess(
            args=proc.args,
            returncode=proc.returncode,
            stdout=decode_output(proc.stdout),
            stderr=decode_output(proc.stderr),
        )

    def exec_log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._exec_log)


def _quote(value: str) -> str:
    """shell 单引号转义（防止 URL 里的特殊字符跑出命令边界）。"""
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


#: sqlmap 里"由我们说了算"的参数：出现在 extra 里时以我们的值为准（保留第一次出现）。
_LOCKED_SQLMAP_FLAGS = ("--risk", "--level", "--technique", "--threads", "--timeout")


def _dedupe_sqlmap_flags(command: str) -> str:
    """保证封装的 sqlmap 约束参数不会被调用方重复覆盖。

    实测模型会在 extra 里自加 `--risk=2 --level=3`，而 sqlmap 取"后者胜"，
    于是封装声明的"只读轻量"被悄悄绕过。这里对锁定参数做去重：**只保留第一次出现的值**
    （即封装自己写的那个），后续重复项丢弃并记一条注释便于排查。
    """
    tokens = command.split()
    seen: set[str] = set()
    kept: list[str] = []
    dropped: list[str] = []
    for token in tokens:
        flag = token.split("=", 1)[0]
        if flag in _LOCKED_SQLMAP_FLAGS:
            if flag in seen:
                dropped.append(token)
                continue
            seen.add(flag)
        kept.append(token)
    return " ".join(kept)


def _clip(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    """裁剪过长输出，保留头尾。

    实现委托给 `sanitize.clip_head_tail`——沙箱与报告两处必须用**同一套**裁剪
    语义（省略提示的措辞也一样），否则同一份输出在两处会显示不同的"省略了多少"。
    """
    return clip_head_tail(str(text or ""), limit)


def sandbox_report(sandbox: Sandbox | None) -> dict[str, Any]:
    """生成"容器环境状态"摘要，写进报告与 run.json。

    关键：无论容器可用与否都如实记录——如果没用上容器，
    报告里必须能看出来（下游才不会把纯 Python 探测当成完整覆盖）。
    """
    if sandbox is None:
        return {"enabled": False, "reason": "本次运行未启用容器沙箱"}
    info = sandbox.probe()
    if not info.get("ok"):
        return {"enabled": False, **info}
    return {
        "enabled": True,
        "runtime": info.get("runtime", ""),
        "version": info.get("version", ""),
        "kind": info.get("kind", ""),
        "image": sandbox.image,
        "container": sandbox._container,
        "allowed_hosts": sorted(sandbox.allowed_hosts),
        "tools": {name: ok for name, ok in (info.get("tools") or {}).items() if ok},
        "host_gateway": sandbox.host_gateway() if info.get("kind") == "wsl" else "",
        "host_map_notes": sandbox._host_map_notes[:5],
        "exec_count": len(sandbox.exec_log()),
    }
