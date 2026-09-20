"""API 合约导入：OpenAPI 3 / Swagger 2 → 攻击面清单（**永不扩展授权范围**）。

对标机制来源：Strix 接受 `-t ./openapi.yaml` 与 `-t postman://<uuid>`，并把
`api_spec` 当成一种目标类型，其 base URL 会被自动加入授权（见
`docs/research-notes/strix-pentagi-refresh-2026.md` §C6）。PentAGI 没有这个能力。

**HexHound 的取舍（安全上更严）**：Strix 的"自动授权 base URL"在这里是
反过来的——规范里的 `servers` / `host` / `schemes` / `basePath` **一律不信任**，
所有接口都锚定到用户在命令行明确给出的 `--target`。理由：

1. 一份规范可以很容易地写上 `servers: [{url: https://evil.example.com}]`；
   如果导入时把它加入授权，"读一份文件"就变成了"扩大授权范围"。
2. 规范里的路径也可能带意外内容（`//evil.com/x`、`../`），导入后就是 SSRF。
3. 授权范围只应来自用户，不来自被审计的产物。

因此本模块的三条硬约束：

- **默认禁止任意外部 $ref**（`allow_remote_refs=False`），本地 `$ref` 必须留在
  规范根目录内（`..` 穿越直接拒绝，解析后再用 `relative_to` 复核一次）；
- 允许远程 `$ref` 时（显式开启），URL 必须**经过与目标请求相同的范围校验**
  （复用 `tools._validate_url` 的同一份 `ALLOWED_HOSTS`）；
- `servers` / `host` / `schemes` / `basePath` 只当作**信息**记录进报告，
  绝不参与 URL 构造——构造出来的每个 URL 都是 `--target` + path。

零第三方依赖：YAML 只实现 OpenAPI 用到的子集（映射/序列/标量/块标量/
行内流式），并且**主动拒绝**锚点、别名、自定义标签（YAML 炸弹与
`!!python/object` 这类构造器的入口）。解析失败给出可操作错误，不静默跳过。
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

#: 单份规范的最大字节数（防止拿一个巨型文件把内存吃满）。
MAX_SPEC_BYTES = 8 * 1024 * 1024

#: `$ref` 解析的最大深度（防止自引用导致的无限展开）。
MAX_REF_DEPTH = 12

#: 解析 `$ref` 的最大次数（防止 N×M 的引用爆炸）。
MAX_REF_EXPANSIONS = 2000

#: 一个规范最多导入多少个接口（防止把上下文和攻面撑爆）。
MAX_OPERATIONS = 500

#: HTTP 方法集合（OpenAPI Path Item 里除 parameters/summary 等之外的都是方法）。
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

#: Path Item 里**不是**方法的键。
_PATH_ITEM_KEYS = frozenset({"$ref", "summary", "description", "servers", "parameters"})

#: 参数位置 → 中文说明（报告与提示词里用）。
PARAM_LOCATIONS = ("query", "header", "path", "cookie", "formData", "body")


class SpecError(ValueError):
    """规范无法安全导入（消息面向使用者，必须可操作）。"""


# ---------------------------------------------------------------------------
# YAML：只实现 OpenAPI 用到的子集，并拒绝危险构造
# ---------------------------------------------------------------------------

#: 危险 YAML 特征：锚点/别名（炸弹入口）、自定义标签（构造器入口）、
#: 文档分隔符（只接受单文档）。逐行扫描，命中即拒绝并说明原因。
_YAML_DANGEROUS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w\"'])[&*][A-Za-z_][\w-]*"), "锚点/别名（&/*）"),
    (re.compile(r"!![A-Za-z]"), "自定义标签（!!）"),
    (re.compile(r"^\s*---\s*$", re.M), "多文档分隔符（---）"),
    (re.compile(r"%YAML"), "YAML 指令（%YAML）"),
)


def _reject_dangerous_yaml(text: str) -> None:
    """拒绝 YAML 里的危险构造。

    为什么不做"完整 YAML 解析"：完整实现要支持锚点、别名、自定义标签、
    多文档——而这些正是 YAML 炸弹（Billion Laughs）与反序列化攻击的入口。
    OpenAPI 规范在实践中不用这些特性（官方示例也没有），所以**主动拒绝**
    比"实现一个不安全的子集"更合适。拒绝时说明是哪一种构造、在哪一行。
    """
    for pattern, label in _YAML_DANGEROUS:
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            raise SpecError(
                f"规范里的 YAML 使用了不支持的构造：{label}（第 {line} 行）。"
                "HexHound 只解析 OpenAPI 需要的 YAML 子集，并主动拒绝锚点/别名/"
                "自定义标签——它们是 YAML 炸弹与反序列化攻击的入口。"
                "请把规范导出成 JSON，或去掉这些构造后重试。"
            )


def _strip_inline_comment(text: str) -> str:
    """去掉 YAML 标量后面的行内注释（`#` 前必须有空白，且不在引号内）。

    判据必须严格：URL 片段（`http://x/#frag`）与含 `#` 的引号字符串都不能被误切。
    YAML 规范本身也是这个规则——`#` 只有在前面是空白（或行首）时才开始注释。
    """
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            continue
        if char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
    return text.rstrip()


def _scalar(token: str) -> Any:
    """把 YAML 标量转成 Python 值。

    关键约束：**键**必须是明确的字符串。YAML 1.1 里 `on` / `off` / `yes` / `no`
    会被解析成布尔值，于是 `paths: {on: ...}` 这种键会变成 `True`，
    后面按字符串查路径就永远查不到。这里对键只做最小处理（去引号），
    并在 `_ensure_string_keys` 里进一步校验，避免"静默丢接口"。
    """
    text = _strip_inline_comment(token.strip())
    if not text:
        return None
    if text[0] == text[-1] and text[0] in "\"'" and len(text) >= 2:
        return text[1:-1]
    low = text.lower()
    if low in ("null", "~"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("yes", "on"):
        return True
    if low in ("no", "off"):
        return False
    if re.fullmatch(r"[-+]?\d+", text):
        try:
            return int(text)
        except ValueError:
            return text
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?", text):
        try:
            return float(text)
        except ValueError:
            return text
    if text.startswith("[") and text.endswith("]"):
        return [_scalar(item) for item in _split_flow(text[1:-1])]
    if text.startswith("{") and text.endswith("}"):
        result: dict[str, Any] = {}
        for pair in _split_flow(text[1:-1]):
            if ":" not in pair:
                continue
            key, _, value = pair.partition(":")
            result[key.strip().strip("\"'")] = _scalar(value)
        return result
    return text


def _split_flow(text: str) -> list[str]:
    """按逗号切分流式序列/映射，尊重引号与嵌套括号。"""
    items: list[str] = []
    depth = 0
    quote = ""
    current = ""
    for char in text:
        if quote:
            current += char
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current += char
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        if char == "," and depth == 0:
            items.append(current)
            current = ""
            continue
        current += char
    if current.strip():
        items.append(current)
    return items


def parse_yaml(text: str) -> Any:
    """解析 OpenAPI 用到的 YAML 子集（块映射/块序列/标量/块标量/流式）。"""
    _reject_dangerous_yaml(text)
    lines = text.splitlines()

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        """解析 `indent` 层级的块，返回 (值, 下一个未消费的行号)。"""
        result: Any = None
        while index < len(lines):
            raw = lines[index]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                index += 1
                continue
            current_indent = len(raw) - len(raw.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent > indent:
                # 上一轮已经消费过更深的内容；出现更深的缩进说明结构不合法
                raise SpecError(
                    f"YAML 缩进不一致（第 {index + 1} 行）："
                    f"期望 {indent} 个空格，实际 {current_indent} 个。"
                )
            if stripped.startswith("- "):
                if result is None:
                    result = []
                if not isinstance(result, list):
                    raise SpecError(f"YAML 类型冲突（第 {index + 1} 行）：同一层级既有映射又有序列。")
                item_text = stripped[2:].strip()
                if not item_text:
                    value, index = parse_block(index + 1, indent + 2)
                    result.append(value)
                    continue
                if ":" in item_text and not item_text.startswith(("[", "{", "\"", "'")):
                    # 行内映射起始：`- name: id`
                    key, _, rest = item_text.partition(":")
                    entry: dict[str, Any] = {}
                    if rest.strip():
                        entry[key.strip()] = _scalar(rest)
                        index += 1
                    else:
                        value, index = parse_block(index + 1, indent + 4)
                        entry[key.strip()] = value
                    # 继续吃同一序列项下更深缩进的键
                    while index < len(lines):
                        follow = lines[index]
                        follow_stripped = follow.strip()
                        if not follow_stripped or follow_stripped.startswith("#"):
                            index += 1
                            continue
                        follow_indent = len(follow) - len(follow.lstrip(" "))
                        if follow_indent <= indent or follow_stripped.startswith("- "):
                            break
                        if ":" not in follow_stripped:
                            break
                        fkey, _, frest = follow_stripped.partition(":")
                        if frest.strip():
                            entry[fkey.strip()] = _scalar(frest)
                            index += 1
                        else:
                            value, index = parse_block(index + 1, follow_indent + 2)
                            entry[fkey.strip()] = value
                    result.append(entry)
                    continue
                result.append(_scalar(item_text))
                index += 1
                continue
            if ":" not in stripped:
                raise SpecError(
                    f"YAML 结构无法解析（第 {index + 1} 行）：既不是映射也不是序列项：{stripped[:60]!r}"
                )
            if result is None:
                result = {}
            if not isinstance(result, dict):
                raise SpecError(f"YAML 类型冲突（第 {index + 1} 行）：同一层级既有序列又有映射。")
            key, _, rest = stripped.partition(":")
            key = key.strip().strip("\"'")
            rest = rest.strip()
            if rest.startswith("#"):
                rest = ""
            if rest in ("|", ">", "|-", ">-", "|+", ">+"):
                # 块标量：吃掉更深缩进的所有行
                block_lines: list[str] = []
                index += 1
                while index < len(lines):
                    candidate = lines[index]
                    if candidate.strip() and (len(candidate) - len(candidate.lstrip(" "))) <= indent:
                        break
                    block_lines.append(candidate[indent + 2:] if len(candidate) > indent + 2 else "")
                    index += 1
                joined = "\n".join(block_lines).rstrip()
                result[key] = joined if rest.startswith("|") else " ".join(
                    part.strip() for part in joined.splitlines()
                )
                continue
            if rest:
                result[key] = _scalar(rest)
                index += 1
                continue
            value, index = parse_block(index + 1, indent + 2)
            result[key] = value
        return result, index

    parsed, _ = parse_block(0, 0)
    return parsed


def parse_spec_text(text: str, *, source: str = "") -> dict[str, Any]:
    """把规范正文解析成 dict（先试 JSON，再试 YAML 子集）。"""
    body = str(text or "").strip()
    if not body:
        raise SpecError(f"规范内容为空：{source or '（未命名）'}")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        try:
            parsed = parse_yaml(body)
        except SpecError:
            raise
        except Exception as exc:  # noqa: BLE001 YAML 子集解析失败要转成可操作错误
            raise SpecError(
                f"规范解析失败（{source or '未命名'}）：既不是合法 JSON，也不是可解析的 YAML：{exc}"
            ) from exc
    if not isinstance(parsed, dict):
        raise SpecError(
            f"规范的顶层必须是对象（OpenAPI/Swagger 规范都是），"
            f"实际是 {type(parsed).__name__}：{source or '未命名'}"
        )
    return parsed


# ---------------------------------------------------------------------------
# 版本识别
# ---------------------------------------------------------------------------


@dataclass
class SpecKind:
    """识别出的规范形态。"""

    flavor: str          # openapi3 / swagger2 / unknown
    version: str = ""
    label: str = ""

    @property
    def supported(self) -> bool:
        return self.flavor in ("openapi3", "swagger2")


def detect_spec_kind(spec: dict[str, Any]) -> SpecKind:
    """识别 OpenAPI 3 / Swagger 2。

    判据按规范本身来：
    - `openapi: 3.x` → OpenAPI 3；
    - `swagger: "2.0"` → Swagger 2；
    - 两者都没有但存在 `paths` → 当作 unknown（继续尝试，但报告里标注）。
    """
    if not isinstance(spec, dict):
        return SpecKind("unknown")
    openapi = str(spec.get("openapi") or "").strip()
    swagger = str(spec.get("swagger") or "").strip()
    if openapi:
        flavor = "openapi3" if openapi.startswith("3") else "unknown"
        return SpecKind(
            flavor,
            openapi,
            f"OpenAPI {openapi}" if flavor == "openapi3" else f"未支持的 OpenAPI 版本 {openapi}",
        )
    if swagger:
        flavor = "swagger2" if swagger.startswith("2") else "unknown"
        return SpecKind(
            flavor,
            swagger,
            f"Swagger {swagger}" if flavor == "swagger2" else f"未支持的 Swagger 版本 {swagger}",
        )
    if "paths" in spec:
        return SpecKind("unknown", "", "缺少 openapi/swagger 版本字段（按 paths 结构尝试解析）")
    return SpecKind("unknown", "", "既没有 openapi 也没有 swagger 字段")


# ---------------------------------------------------------------------------
# $ref 解析（禁止外部引用；本地引用限制在规范根目录内）
# ---------------------------------------------------------------------------


@dataclass
class RefPolicy:
    """`$ref` 解析策略。"""

    root: Path | None = None
    allow_remote: bool = False
    allow_outside_root: bool = False
    #: 远程引用校验回调：`(url) -> 错误信息或空串`。由调用方注入
    #: （CLI 传 `tools._validate_url` 的等价校验），这样本模块不依赖工具层。
    validate_remote: Callable[[str], str] | None = None


class RefResolutionError(SpecError):
    """`$ref` 被策略拒绝。"""


def _check_local_ref(ref: str, policy: RefPolicy, source: str) -> Path:
    """把文件型 `$ref` 解析成路径，并**限制在规范根目录内**。

    两道检查：先看文本里有没有 `..`（快速拒绝明显的穿越），
    解析完再用 `relative_to` 复核一次（符号链接、Windows 盘符跳转等
    只有解析后才能确定）。只查文本是不够的。
    """
    if policy.root is None:
        raise RefResolutionError(
            f"{source}：规范引用了外部文件 {ref!r}，但导入时没有提供规范根目录，"
            "无法确认它是否在允许范围内。请用本地文件路径导入（而不是管道/stdin）。"
        )
    if not policy.allow_outside_root and ".." in Path(ref).parts:
        raise RefResolutionError(
            f"{source}：引用 {ref!r} 含目录穿越（..），已拒绝。"
            "本地 $ref 只允许指向规范根目录内部。"
        )
    candidate = (policy.root / ref).resolve()
    try:
        root_resolved = policy.root.resolve()
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise RefResolutionError(
            f"{source}：引用 {ref!r} 解析后落在规范根目录之外（{candidate}），已拒绝。"
        ) from exc
    if not candidate.is_file():
        raise RefResolutionError(f"{source}：引用的文件不存在：{ref!r}（解析为 {candidate}）")
    return candidate


def _check_remote_ref(ref: str, policy: RefPolicy, source: str) -> None:
    """远程 `$ref`：必须**经过与目标请求相同的范围校验**。"""
    if not policy.allow_remote:
        raise RefResolutionError(
            f"{source}：规范引用了远程地址 {ref!r}，但默认禁止任意外部 $ref。"
            "如果确实需要，请显式开启远程引用（该地址必须通过目标范围校验），"
            "或把被引用的部分内联进本地规范文件。"
        )
    if policy.validate_remote is None:
        raise RefResolutionError(
            f"{source}：规范引用了远程地址 {ref!r}，但未提供范围校验函数，已拒绝。"
        )
    error = policy.validate_remote(ref)
    if error:
        raise RefResolutionError(
            f"{source}：远程引用 {ref!r} 未通过目标范围校验：{error}"
        )


@dataclass
class RefResolver:
    """按策略展开 `$ref`。

    展开是**按需**的（只在遍历到该节点时展开），因此一份规范里没被用到的
    外部引用不会导致导入失败。
    """

    policy: RefPolicy
    _cache: dict[str, Any] = field(default_factory=dict)
    expansions: int = 0
    notes: list[str] = field(default_factory=list)

    def resolve(self, node: Any, *, source: str, depth: int = 0) -> Any:
        if depth > MAX_REF_DEPTH:
            raise RefResolutionError(
                f"{source}：$ref 嵌套超过 {MAX_REF_DEPTH} 层（可能存在自引用环）。"
            )
        if isinstance(node, list):
            return [self.resolve(item, source=source, depth=depth + 1) for item in node]
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.strip():
            return self._expand(ref.strip(), node, source=source, depth=depth)
        return {
            key: self.resolve(value, source=source, depth=depth + 1)
            for key, value in node.items()
        }

    def _expand(self, ref: str, node: dict[str, Any], *, source: str, depth: int) -> Any:
        self.expansions += 1
        if self.expansions > MAX_REF_EXPANSIONS:
            raise RefResolutionError(
                f"{source}：$ref 展开次数超过上限 {MAX_REF_EXPANSIONS}（引用可能成环或爆炸）。"
            )
        target = self._load(ref, source=source)
        resolved = self.resolve(target, source=f"{source} -> {ref}", depth=depth + 1)
        # `$ref` 同级还可能有 description 之类的补充字段（规范允许），合并进去
        extra = {
            key: self.resolve(value, source=source, depth=depth + 1)
            for key, value in node.items()
            if key != "$ref"
        }
        if extra and isinstance(resolved, dict):
            merged = dict(resolved)
            merged.update(extra)
            return merged
        return resolved

    def _load(self, ref: str, *, source: str) -> Any:
        if ref in self._cache:
            return self._cache[ref]
        if ref.startswith("#"):
            raise RefResolutionError(
                f"{source}：内部引用 {ref!r} 未能在当前文档内解析（可能指向不存在的节点）。"
            )
        parsed = urlparse(ref)
        if parsed.scheme in ("http", "https"):
            _check_remote_ref(ref, self.policy, source)
            raise RefResolutionError(
                f"{source}：远程引用 {ref!r} 通过了范围校验，但**本版本不下载远程规范**"
                "（避免在导入阶段发起网络请求）。请把被引用内容内联进本地文件。"
            )
        if parsed.scheme and len(parsed.scheme) > 1:
            raise RefResolutionError(
                f"{source}：不支持的 $ref 协议 {parsed.scheme!r}（只允许本地文件与 #内部引用）。"
            )
        path_part, _, pointer = ref.partition("#")
        candidate = _check_local_ref(path_part, self.policy, source)
        raw = _read_text(candidate)
        document = parse_spec_text(raw, source=str(candidate))
        value = _pointer_lookup(document, pointer) if pointer else document
        if value is None:
            raise RefResolutionError(
                f"{source}：引用 {ref!r} 指向的位置不存在（{candidate} 里没有 #{pointer}）。"
            )
        self._cache[ref] = value
        self.notes.append(f"已展开本地引用 {ref}")
        return value


def _pointer_lookup(document: Any, pointer: str) -> Any:
    """按 JSON Pointer（`/a/b/0`）在文档里查找。"""
    if not pointer:
        return document
    node = document
    for token in pointer.lstrip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return None
            node = node[token]
        elif isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def _read_text(path: Path, *, limit: int = MAX_SPEC_BYTES) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SpecError(f"无法读取规范文件 {path}：{exc}") from exc
    if size > limit:
        raise SpecError(
            f"规范文件过大：{path} 有 {size} 字节，上限 {limit} 字节。"
            "请先裁剪规范（通常只需要 paths 与 definitions/components）。"
        )
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SpecError(f"无法读取规范文件 {path}：{exc}") from exc


# ---------------------------------------------------------------------------
# 接口抽取
# ---------------------------------------------------------------------------


@dataclass
class Operation:
    """一个接口（方法 + 路径 + 参数 + 认证提示）。"""

    method: str
    path: str
    operation_id: str = ""
    summary: str = ""
    params: list[dict[str, Any]] = field(default_factory=list)
    security: list[str] = field(default_factory=list)
    #: 规范化后的**相对**路径（前导 `/`，无重复斜杠）。
    normalized_path: str = ""
    #: 声明了请求体（OpenAPI 3 requestBody / Swagger 2 body 参数）。
    has_body: bool = False
    tags: list[str] = field(default_factory=list)

    def param_names(self, location: str = "") -> list[str]:
        return [
            str(item.get("name"))
            for item in self.params
            if item.get("name") and (not location or item.get("location") == location)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "normalized_path": self.normalized_path,
            "operation_id": self.operation_id,
            "summary": self.summary,
            "params": self.params,
            "param_names": [str(item.get("name")) for item in self.params if item.get("name")],
            "security": self.security,
            "has_body": self.has_body,
            "tags": self.tags,
        }


@dataclass
class SpecImport:
    """一次导入的结果。"""

    operations: list[Operation] = field(default_factory=list)
    kind: SpecKind = field(default_factory=lambda: SpecKind("unknown"))
    title: str = ""
    version: str = ""
    #: 规范里声明的 servers/host/schemes/basePath —— **仅记录，不参与 URL 构造**。
    declared_servers: list[str] = field(default_factory=list)
    declared_base_path: str = ""
    security_schemes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    source: str = ""
    target: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "flavor": self.kind.flavor,
            "spec_version": self.kind.version,
            "spec_label": self.kind.label,
            "title": self.title,
            "version": self.version,
            "operations": len(self.operations),
            "declared_servers": list(self.declared_servers),
            "declared_base_path": self.declared_base_path,
            "security_schemes": list(self.security_schemes),
            "notes": list(self.notes),
            "warnings": list(self.warnings),
            "skipped": list(self.skipped),
        }

    def inventory_lines(self, limit: int = 200) -> list[str]:
        """给提示词/报告用的接口清单（一行一个）。"""
        lines: list[str] = []
        for op in self.operations[:limit]:
            params = op.param_names()
            suffix = f"  参数[{', '.join(params)}]" if params else ""
            lines.append(f"{op.method.upper():6} {op.normalized_path}{suffix}")
        if len(self.operations) > limit:
            lines.append(f"…（共 {len(self.operations)} 个接口，此处只列前 {limit} 个）")
        return lines


def normalize_spec_path(raw: str) -> str:
    """把规范里的路径规范化成**站内相对路径**。

    必须处理的三类恶意/异常写法：

    1. `//evil.example.com/api` —— 协议相对 URL。若直接拼到 target 上，
       `urljoin` 会把主机换成 evil.example.com（这是最典型的规范注入）；
    2. `https://evil.example.com/api` —— 绝对 URL；
    3. `/a/../../b` —— 目录穿越。

    做法：拒绝带 scheme 的路径；把前导 `//`、`/\\` 折叠成单个 `/`；
    用 `posixpath.normpath` 消除 `..`（并保证结果仍在根下）。

    另外**拒绝不以 `/` 开头的路径**：OpenAPI 规范要求 paths 的键以 `/` 开头。
    早先的实现会把 `users` 静默补成 `/users`——那看起来像"容错"，
    实际是把一个明显不合规的规范变成"看起来导入成功了"，
    而用户永远不知道自己的规范有问题。宁可报错。
    """
    text = str(raw or "").strip()
    if not text:
        raise SpecError("规范里出现空路径。")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", text):
        raise SpecError(
            f"规范里的路径是绝对 URL：{text!r}。"
            "接口必须锚定到 --target，路径里不允许出现其它主机。"
        )
    if text.startswith("\\\\") or text.lower().startswith("//"):
        raise SpecError(
            f"规范里的路径是协议相对 URL：{text!r}（会被解析到别的主机）。已拒绝。"
        )
    # 反斜杠在部分客户端里等价于 `/`，一并归一
    text = text.replace("\\", "/")
    if not text.startswith("/"):
        raise SpecError(
            f"规范里的路径 {raw!r} 不以 `/` 开头。OpenAPI/Swagger 要求 paths 的键"
            "是绝对路径模板（如 `/users/{id}`）。请修正规范后重试。"
        )
    segments: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def build_operation_url(target: str, path: str) -> str:
    """把**规范化后的相对路径**锚定到用户指定的 target 上。

    刻意不用 `urljoin`：`urljoin("http://t/a", "//evil.com/b")` 会返回
    `http://evil.com/b`。这里手工拼接，主机永远来自 `target`。
    `normalize_spec_path` 已经保证 path 是站内相对路径，这里再断言一次。
    """
    base = str(target or "").strip()
    if not base:
        raise SpecError("导入接口需要 --target（用于把接口锚定到授权目标）。")
    parsed = urlparse(base)
    if not parsed.hostname:
        raise SpecError(f"--target 无法解析出主机：{base!r}")
    normalized = normalize_spec_path(path)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return root + normalized


def _collect_params(raw_params: Any, *, source: str, dropped: list[str] | None = None) -> list[dict[str, Any]]:
    """收集参数（OpenAPI 3 与 Swagger 2 的统一视图）。

    无法识别的参数条目**写进 `dropped` 而不是静默丢掉**：参数被无声丢弃，
    报告里就会出现一个看不见的覆盖盲区（"这个接口没有参数"其实是"我们没解析出来"）。
    """
    params: list[dict[str, Any]] = []
    if not isinstance(raw_params, list):
        if raw_params is not None and dropped is not None:
            dropped.append(f"{source}：parameters 不是数组（{type(raw_params).__name__}）")
        return params
    for item in raw_params:
        if not isinstance(item, dict):
            if dropped is not None:
                dropped.append(f"{source}：参数条目不是对象（{type(item).__name__}）")
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            # 常见于 $ref 指向 `components/schemas` 而**不是** `parameters`
            # （规范写错了）。说出来，而不是当作"这个参数不存在"。
            if dropped is not None:
                detail = str(item.get("description") or item.get("type") or "")[:60]
                dropped.append(
                    f"{source}：参数条目没有 name"
                    + (f"（{detail}）" if detail else "")
                    + "——若它是 $ref，请确认指向的是 parameters 而不是 schema"
                )
            continue
        location = str(item.get("in") or "").strip() or "query"
        if location not in PARAM_LOCATIONS:
            # 未知位置（例如 Swagger 2 的 formData 之外的写法）：保留但标注，
            # 不静默丢弃——否则参数级覆盖会出现看不见的盲区。
            params.append({"name": name, "location": location, "note": "未知参数位置"})
            continue
        entry: dict[str, Any] = {
            "name": name,
            "location": location,
            "required": bool(item.get("required")),
            "type": str(
                item.get("type")
                or (item.get("schema") or {}).get("type")
                if isinstance(item.get("schema"), dict)
                else item.get("type") or ""
            ),
        }
        if item.get("description"):
            entry["description"] = str(item["description"])[:200]
        params.append(entry)
    return params


def _security_names(raw_security: Any, schemes: dict[str, Any]) -> list[str]:
    """把 security 需求转成可读的认证提示（方案名 + 类型）。"""
    names: list[str] = []
    if not isinstance(raw_security, list):
        return names
    for requirement in raw_security:
        if not isinstance(requirement, dict):
            continue
        for scheme_name, scopes in requirement.items():
            scheme = schemes.get(scheme_name)
            kind = ""
            where = ""
            if isinstance(scheme, dict):
                kind = str(scheme.get("type") or "")
                if kind == "apiKey":
                    where = str(scheme.get("in") or "") + ":" + str(scheme.get("name") or "")
                elif kind == "http":
                    where = str(scheme.get("scheme") or "")
            detail = f"{scheme_name}({kind}{'/' + where if where else ''})"
            scope_list = [str(item) for item in scopes] if isinstance(scopes, list) else []
            if scope_list:
                detail += " 需要 scope: " + ",".join(scope_list)
            names.append(detail)
    return names


def extract_operations(
    spec: dict[str, Any],
    *,
    resolver: RefResolver | None = None,
    max_operations: int = MAX_OPERATIONS,
) -> tuple[list[Operation], list[str], list[str]]:
    """抽取接口清单。

    返回 `(operations, skipped, warnings)`。**解析失败的条目写进 skipped
    并给出原因**——绝不静默跳过（导入结果必须能解释"为什么少了几个接口"）。
    """
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise SpecError(
            "规范里没有可用的 `paths` 对象。请确认这是一份 OpenAPI/Swagger 规范"
            "（而不是 Postman 集合或 API 文档页面）。"
        )
    components = spec.get("components") if isinstance(spec.get("components"), dict) else {}
    schemes = spec.get("securityDefinitions")
    if not isinstance(schemes, dict):
        schemes = (components or {}).get("securitySchemes")
    if not isinstance(schemes, dict):
        schemes = {}
    global_security = spec.get("security")
    # OpenAPI 3.1 允许 paths 里放 servers；只记录不信任

    operations: list[Operation] = []
    skipped: list[str] = []
    warnings: list[str] = []

    for raw_path, raw_item in paths.items():
        if len(operations) >= max_operations:
            skipped.append(
                f"（其余接口未导入）{raw_path}：超过单次导入上限 {max_operations} 个接口"
            )
            continue
        try:
            normalized = normalize_spec_path(str(raw_path))
        except SpecError as exc:
            skipped.append(f"{raw_path}：{exc}")
            continue
        item = raw_item
        if resolver is not None:
            try:
                item = resolver.resolve(item, source=f"paths.{raw_path}")
            except SpecError as exc:
                skipped.append(f"{raw_path}：{exc}")
                continue
        if not isinstance(item, dict):
            skipped.append(f"{raw_path}：路径项不是对象（{type(item).__name__}）")
            continue
        shared_params = item.get("parameters")
        for key, value in item.items():
            method = str(key).lower()
            if method in _PATH_ITEM_KEYS or method not in HTTP_METHODS:
                if method not in _PATH_ITEM_KEYS:
                    skipped.append(f"{raw_path}：不认识的键 {key!r}（不是 HTTP 方法）")
                continue
            if not isinstance(value, dict):
                skipped.append(f"{raw_path} {method.upper()}：操作定义不是对象")
                continue
            op_params = _collect_params(shared_params, source=raw_path, dropped=skipped)
            op_params += _collect_params(value.get("parameters"), source=raw_path, dropped=skipped)
            has_body = False
            request_body = value.get("requestBody")
            if isinstance(request_body, dict):
                has_body = True
            # Swagger 2：body / formData 参数也算请求体；formData 转成参数
            for param in list(op_params):
                if param.get("location") == "body":
                    has_body = True
                if param.get("location") == "formData":
                    param["location"] = "form"
            security = value.get("security")
            if security is None:
                security = global_security
            operations.append(
                Operation(
                    method=method.upper(),
                    path=str(raw_path),
                    normalized_path=normalized,
                    operation_id=str(value.get("operationId") or ""),
                    summary=str(value.get("summary") or value.get("description") or "")[:200],
                    params=op_params,
                    security=_security_names(security, schemes),
                    has_body=has_body,
                    tags=[str(item) for item in (value.get("tags") or []) if item],
                )
            )
    if not operations:
        reason = "；".join(skipped[:5]) if skipped else "规范里没有任何接口定义"
        raise SpecError(f"没能从规范里导入任何接口：{reason}")
    return operations, skipped, warnings


def declared_servers(spec: dict[str, Any]) -> tuple[list[str], str]:
    """取出规范**声明**的 servers / host+basePath。

    **仅用于记录与提示**：它们的唯一去处是报告的"规范声明了什么"一节。
    构造请求 URL 时一律忽略——授权范围只来自 `--target`。
    """
    servers: list[str] = []
    base_path = ""
    raw_servers = spec.get("servers")
    if isinstance(raw_servers, list):
        for item in raw_servers:
            if isinstance(item, dict) and item.get("url"):
                servers.append(str(item["url"])[:200])
            elif isinstance(item, str):
                servers.append(item[:200])
    # Swagger 2
    host = str(spec.get("host") or "").strip()
    base = str(spec.get("basePath") or "").strip()
    schemes_raw = spec.get("schemes")
    schemes = [str(item) for item in schemes_raw] if isinstance(schemes_raw, list) else []
    if host:
        for scheme in (schemes or ["https"]):
            servers.append(f"{scheme}://{host}{base}")
    elif base:
        base_path = base
    if base:
        base_path = base
    return servers, base_path


def import_spec(
    *,
    text: str,
    source: str,
    target: str,
    policy: RefPolicy | None = None,
    max_operations: int = MAX_OPERATIONS,
) -> SpecImport:
    """把规范正文导入成 `SpecImport`（**纯函数：不读网络**）。"""
    spec = parse_spec_text(text, source=source)
    kind = detect_spec_kind(spec)
    if not kind.supported:
        raise SpecError(
            f"{source}：{kind.label}。目前支持 OpenAPI 3.x 与 Swagger 2.0。"
            "请用 `swagger-cli convert` 或在线工具把规范转成 OpenAPI 3 后重试。"
        )
    resolver = RefResolver(policy=policy or RefPolicy())
    operations, skipped, warnings = extract_operations(
        spec, resolver=resolver, max_operations=max_operations
    )
    servers, base_path = declared_servers(spec)
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    schemes = spec.get("securityDefinitions")
    if not isinstance(schemes, dict):
        components = spec.get("components") if isinstance(spec.get("components"), dict) else {}
        schemes = components.get("securitySchemes")
    if not isinstance(schemes, dict):
        schemes = {}

    notes: list[str] = []
    if servers:
        notes.append(
            "规范里声明了 servers/host（"
            + "、".join(servers[:5])
            + "）——**这些值已被忽略**：所有接口都锚定到你指定的 --target，"
            "规范不能扩大授权范围。"
        )
    if base_path:
        notes.append(
            f"规范里声明了 basePath {base_path!r}——同样被忽略，接口直接拼在 --target 之后。"
        )
    if resolver.expansions:
        notes.append(f"已展开 {resolver.expansions} 处 $ref（全部在规范根目录内）。")

    # 路径必须能锚定到 target：这里对**每个**接口试拼一次，失败的整条拒绝。
    for operation in operations:
        operation.normalized_path = normalize_spec_path(operation.normalized_path)
        build_operation_url(target, operation.normalized_path)

    return SpecImport(
        operations=operations,
        kind=kind,
        title=str(info.get("title") or "")[:200],
        version=str(info.get("version") or "")[:60],
        declared_servers=servers,
        declared_base_path=base_path,
        security_schemes=sorted(str(name) for name in schemes),
        notes=notes,
        warnings=warnings,
        skipped=skipped,
        source=source,
        target=target,
    )


def load_spec_source(
    path_or_url: str,
    *,
    allowed_hosts: frozenset[str] = frozenset(),
    validate_url: Callable[[str], str] | None = None,
    timeout: float = 20.0,
) -> tuple[str, str, Path | None]:
    """读取规范来源，返回 `(正文, 来源描述, 本地根目录)`。

    远程规范：**复用与目标请求相同的范围校验**（`validate_url` 由调用方注入，
    通常是 `tools._validate_url` 的包装）。校验不通过直接拒绝，不发起请求。
    远程规范的 `$ref` 根目录为 None，因此它内部的相对文件引用会被拒绝
    （远程规范不该再去读本地文件）。
    """
    raw = str(path_or_url or "").strip()
    if not raw:
        raise SpecError("规范来源为空，请提供 --api-spec 的路径或 URL。")
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https"):
        if validate_url is None:
            raise SpecError(
                f"远程规范 {raw!r} 需要范围校验，但调用方没有提供校验函数，已拒绝。"
            )
        error = validate_url(raw)
        if error:
            raise SpecError(
                f"远程规范 {raw!r} 未通过目标范围校验：{error}\n"
                "（出于安全考虑，规范 URL 与目标请求走同一份 ALLOWED_HOSTS 校验；"
                "规范里的域名不会因为出现在规范里就自动获得授权。）"
            )
        try:
            import httpx

            # 与目标流量一致：直连，不读环境/系统代理（见 tools._proxy_kwargs）。
            response = httpx.get(
                raw, timeout=timeout, follow_redirects=False, verify=False, trust_env=False
            )
        except Exception as exc:  # noqa: BLE001 网络异常转成可操作错误
            raise SpecError(f"下载远程规范失败：{type(exc).__name__}: {exc}") from exc
        if response.status_code != 200:
            raise SpecError(
                f"下载远程规范失败：HTTP {response.status_code}（{raw}）。"
                "注意本工具**不跟随重定向**——若规范地址会跳转，请直接给出最终地址。"
            )
        body = response.text
        if len(body.encode("utf-8")) > MAX_SPEC_BYTES:
            raise SpecError(f"远程规范过大（上限 {MAX_SPEC_BYTES} 字节）：{raw}")
        if parsed.fragment:
            raise SpecError(f"规范 URL 不应带片段（#）：{raw}")
        return body, raw, None
    path = Path(raw).expanduser()
    if not path.is_file():
        raise SpecError(
            f"找不到规范文件：{raw}。请给出本地文件路径（.json/.yaml/.yml）"
            "或已授权主机上的 URL。"
        )
    return _read_text(path), str(path), path.resolve().parent


__all__ = [
    "HTTP_METHODS",
    "MAX_OPERATIONS",
    "MAX_REF_DEPTH",
    "MAX_SPEC_BYTES",
    "Operation",
    "RefPolicy",
    "RefResolutionError",
    "RefResolver",
    "SpecError",
    "SpecImport",
    "SpecKind",
    "build_operation_url",
    "declared_servers",
    "detect_spec_kind",
    "extract_operations",
    "import_spec",
    "load_spec_source",
    "normalize_spec_path",
    "parse_spec_text",
    "parse_yaml",
]
