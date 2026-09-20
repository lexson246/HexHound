"""工具链自检：不依赖 LLM，直接驱动 HexHound 的工具层打一遍靶场。

用途：
- 验证「工具能否真的发现漏洞」（对抗 LLM 侧幻觉的基础：工具先要准）；
- 作为回归测试：改了 tools.py / knowledge.py / surface.py 后跑一次，看检测能力有没有退化。

用法：
    python vulnlab/app.py            # 另开一个终端启动靶场
    python examples/tool_selftest.py # 默认打 http://127.0.0.1:5000

输出每个检查项的 PASS/FAIL 与观测到的证据摘要，退出码非 0 表示有失败项。
设计要点：每个检查项用**独立的攻面**（fresh surface），避免前一项的「已试过」记录
把后一项的 payload 全部跳过——那会让自检假装成失败/成功。攻面共享行为在最后一组
检查里显式验证。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.memory import RunArtifacts  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
HOST = BASE.split("//", 1)[-1].split("/")[0].split(":")[0]

results: list[tuple[bool, str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((bool(condition), name, detail))
    flag = "PASS" if condition else "FAIL"
    print(f"[{flag}] {name}" + (f" — {detail}" if detail else ""))


def make_registry(
    role: str,
    worker: str = "T1",
    surface: AttackSurface | None = None,
) -> ToolRegistry:
    """构造一个工具注册表；surface=None 时用独立攻面（默认，避免用例互相污染）。"""
    return ToolRegistry(
        base_dir=Path("."),
        allowed_hosts=frozenset({HOST, "127.0.0.1", "localhost"}),
        timeout=8,
        mode="blackbox",
        role=role,
        worker_id=worker,
        surface=surface if surface is not None else AttackSurface(target=BASE, mode="blackbox"),
        budget=Budget(BudgetLimits(max_tool_calls=2000)),
        artifacts=RunArtifacts(BASE, enabled=False),
    )


def first_line(text: str, keyword: str = "") -> str:
    """取含关键词的第一行作为摘要（便于人读）。"""
    for line in (text or "").splitlines():
        if keyword and keyword in line:
            return line.strip()[:130]
    return (text or "").splitlines()[0].strip()[:130] if text else ""


def main() -> int:
    # ---------------- 侦察类 ----------------
    recon = make_registry("recon", "T1")
    out = recon.execute("crawl", {"url": BASE + "/"})
    check("crawl 抓取首页", "HTTP 200" in out and "/login" in out, first_line(out))
    check("crawl 登记表单参数", "username" in out and "password" in out)
    check("crawl 登记端点与指纹",
          len(recon.surface.endpoints) >= 3 and bool(recon.surface.tech),
          f"endpoints={len(recon.surface.endpoints)} tech={recon.surface.tech}")

    out = recon.execute("enumerate_common",
                        {"base_url": BASE, "tiers": ["framework", "leak"], "limit_per_tier": 10})
    check("enumerate 命中 actuator 配置泄露", "/actuator/env" in out, first_line(out))
    check("enumerate 未命中不误报",
          "/.git/config" not in out.split("命中")[-1], "随机路径基线过滤生效")

    result = recon.execute("read_urls", {"urls": [BASE + "/static/app.js"]})
    secrets = getattr(recon, "last_result", {}).get("secrets") or []
    check("read_urls 发现硬编码密钥", bool(secrets) or "AKIA" in result,
          (secrets or [first_line(result, "敏感")])[0][:110])

    out = recon.execute("discover_endpoints", {"url": BASE + "/", "max_js": 3})
    check("discover 提取前端接口", "/api/user" in out or "/api/order" in out, first_line(out))

    out = recon.execute("check_security_headers", {"url": BASE + "/"})
    check("安全头检查给出结论", "安全头检查" in out, first_line(out))

    # ---------------- 注入类（每类独立攻面）----------------
    def fuzz(
        url: str,
        params: dict,
        categories=None,
        method: str = "GET",
        worker: str = "T2",
    ) -> tuple[str, ToolRegistry]:
        reg = make_registry("injection", worker)
        args = {"url": url, "method": method, "params": params}
        if categories:
            args["categories"] = categories
        return reg.execute("fuzz_params", args), reg

    out, _ = fuzz(BASE + "/reflect", {"name": "hello"})
    check("fuzz 命中反射型 XSS", "[xss]" in out, first_line(out, "xss"))

    out, _ = fuzz(BASE + "/login", {"username": "alice", "password": "x"},
                  ["sqli"], method="POST")
    check("fuzz 命中错误型 SQL 注入", "[sqli]" in out, first_line(out, "sqli"))

    out, _ = fuzz(BASE + "/file", {"path": "secret.txt"})
    check("fuzz 命中任意文件读取", "[path]" in out, first_line(out, "path"))

    out, _ = fuzz(BASE + "/fetch", {"url": BASE + "/"})
    check("fuzz 命中 SSRF", "[ssrf]" in out, first_line(out, "ssrf"))

    out, _ = fuzz(BASE + "/ssti", {"name": "world"})
    check("fuzz 命中 SSTI / 格式化字符串注入", ("[ssti]" in out or "[fmt]" in out), first_line(out, "ssti") or first_line(out, "fmt"))

    out, _ = fuzz(BASE + "/ping", {"ip": "127.0.0.1"})
    check("fuzz 对命令注入给出结论", "[cmd]" in out or "未发现" in out,
          first_line(out, "cmd") or first_line(out, "未发现"))

    out, _ = fuzz(BASE + "/api/user", {"uid": "1"})
    check("fuzz 对 IDOR 参数给出结论", "fuzz 完成" in out, first_line(out, "命中") or first_line(out, "未发现"))

    # ---------------- 基线/注入对比 ----------------
    injection = make_registry("injection", "T5")
    out = injection.execute(
        "compare_responses",
        {
            "url": BASE + "/reflect",
            "method": "GET",
            "params": {"name": "hello"},
            "inject_params": {"name": "<script>alert(1)</script>"},
            "category": "xss",
        },
    )
    check("compare 确认注入差异并给证据编号", "差异" in out and "script" in out, first_line(out, "发现"))

    # ---------------- 复核门与去重 ----------------
    verify = make_registry("verify", "T3")
    out = verify.execute(
        "record_finding",
        {
            "title": "缺少证据的 SQL 注入",
            "severity": "high",
            "confidence": "high",
            "evidence": "仅凭 fuzz 信号",
            "description": "d",
            "remediation": "r",
            "vuln_type": "SQL注入",
            "url": BASE + "/login",
            "verified": True,
            "verification": "重放确认",
        },
    )
    check("复核门拦截无证据的 verified", "候选" in out and "降级" in out, first_line(out, "候选"))

    out = verify.execute(
        "record_finding",
        {
            "title": "缺少复现说明的注入",
            "severity": "high",
            "confidence": "high",
            "evidence": "有证据但没写复现方式",
            "description": "d",
            "remediation": "r",
            "vuln_type": "SQL注入",
            "url": BASE + "/reflect",
            "verified": True,
        },
    )
    check("复核门要求 verification 说明", "verification" in out, first_line(out, "候选"))

    http_out = verify.execute(
        "http_request",
        {"url": BASE + "/login", "method": "POST", "data": {"username": "'", "password": "x"}},
    )
    ref = http_out.split("]", 1)[0].lstrip("[") if http_out.startswith("[") else ""
    check("http_request 返回可引用证据编号", ref.startswith("T3-R"), ref or first_line(http_out))

    out = verify.execute(
        "record_finding",
        {
            "title": "错误型 SQL 注入（登录接口）",
            "severity": "high",
            "confidence": "high",
            "evidence": "单引号触发 SQL 报错并回显完整查询",
            "description": "username 参数直接拼接进 SQL",
            "remediation": "使用参数化查询",
            "vuln_type": "SQL注入",
            "url": BASE + "/login",
            "param": "username",
            "evidence_ref": [ref],
            "verified": True,
            "verification": f"重放 [{ref}]，响应 500 且回显 SQL 错误",
        },
    )
    check("有证据即可入库为已复核", "已记录并复核" in out, first_line(out, "已记录"))

    out = verify.execute(
        "record_finding",
        {
            "title": "SQL 注入（同端点重复上报）",
            "severity": "high",
            "confidence": "high",
            "evidence": "重复上报",
            "description": "d",
            "remediation": "r",
            "vuln_type": "SQL注入",
            "url": BASE + "/login?username=x",
            "param": "username",
            "evidence_ref": [ref],
        },
    )
    check("同一处漏洞重复上报被合并", "合并" in out or "已存在" in out, first_line(out, "已存在"))

    out = verify.execute(
        "record_finding",
        {
            "title": "不同端点的 SQL 注入",
            "severity": "high",
            "confidence": "high",
            "evidence": "另一处注入",
            "description": "d",
            "remediation": "r",
            "vuln_type": "SQL注入",
            "url": BASE + "/api/user?uid=1",
            "param": "uid",
            "evidence_ref": [ref],
        },
    )
    check("不同端点不被误合并", "候选" in out or "已复核" in out, first_line(out, "已登记"))

    # ---------------- 认证 / 越权 ----------------
    auth = make_registry("auth", "T4")
    out = auth.execute("check_default_creds", {"url": BASE + "/login"})
    check("默认凭据探测给出结论", "默认凭据" in out or "未发现" in out,
          first_line(out, "字段") or first_line(out, "未发现"))
    check("默认凭据会记录已测状态",
          any(key[2] == "default_creds" for key in auth.surface.attempts), "attempts 记账正常")

    out = auth.execute("http_request", {"url": BASE + "/api/users", "note": "未授权访问测试"})
    check("未授权接口返回敏感数据（PII 判据）", "mobile" in out or "idcard" in out
          or "敏感" in out, "响应含 PII 或已标注情报")

    out = auth.execute(
        "compare_responses",
        {"url": BASE + "/api/user", "method": "GET", "params": {"uid": "1"},
         "inject_params": {"uid": "3"}},
    )
    check("IDOR 参数枚举产生差异", "差异" in out, first_line(out, "发现"))

    # ---------------- 攻面共享 / 已试去重 ----------------
    shared = AttackSurface(target=BASE, mode="blackbox")
    a = make_registry("injection", "W1", surface=shared)
    b = make_registry("injection", "W2", surface=shared)
    first = a.execute("fuzz_params", {"url": BASE + "/reflect", "method": "GET",
                                      "params": {"name": "hello"}, "categories": ["xss"]})
    second = b.execute("fuzz_params", {"url": BASE + "/reflect", "method": "GET",
                                       "params": {"name": "hello"}, "categories": ["xss"]})
    check("攻面共享：第二个 worker 不再重复发送",
          "本次发出 0 个请求" in second, first_line(second))
    check("攻面共享：告知后者已有命中，可直接复核",
          "共享攻面已有的命中" in second, first_line(second, "共享"))
    check("攻面共享：命中信号被记录", shared.stats()["signals"] > 0,
          json.dumps(shared.stats(), ensure_ascii=False))
    check("攻面共享：端点被登记", shared.stats()["endpoints"] > 0,
          json.dumps(shared.stats(), ensure_ascii=False))

    # ---------------- 输出治理 ----------------
    governor = make_registry("recon", "T6")
    governed = governor.execute("enumerate_common",
                                {"base_url": BASE, "tiers": ["core", "leak"], "limit_per_tier": 60})
    check("大输出被治理（有明确分界提示或体积可控）",
          "[输出治理]" in governed or len(governed) <= 16 * 1024,
          f"{len(governed)} 字符")

    failed = [name for ok, name, _ in results if not ok]
    print()
    print(f"共 {len(results)} 项，通过 {len(results) - len(failed)} 项，失败 {len(failed)} 项")
    if failed:
        print("失败项：" + "; ".join(failed))
        return 1
    print("全部通过：工具层检测能力正常。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
