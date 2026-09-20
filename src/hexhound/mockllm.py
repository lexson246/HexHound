"""无 key 的确定性「脚本 LLM」：驱动完整多代理闭环以验证编排链路。

为什么需要它：
- 真实 LLM 不可用（没 key / key 失效 / 离线）时，仍然要能验证
  「规划 → 并发子代理 → 候选 → 复核 → 合并」是否真的跑通；
- 单元测试不该依赖网络与模型输出，否则编排逻辑回归无法自动化。

实现方式：不假装理解自然语言，而是**按工具返回的观察文本做状态机决策**——
和真实模型看到的输入完全一致，只是决策规则是写死的。因此它验证的是
「编排 + 工具 + 攻面 + 复核门」这一段，而不是模型的智力。
"""
from __future__ import annotations

import json
import re
from typing import Any

from hexhound.llm import LLMUsage

# 常见注入类参数（脚本 LLM 用它挑要打的参数）。
INTERESTING_PARAMS = ("id", "uid", "url", "path", "file", "name", "q", "cmd", "ip", "order_id")


class ScriptedLLM:
    """符合 LLMClient 接口（complete(messages) -> (content, usage)）的确定性替身。"""

    def __init__(
        self,
        plan_tasks: list[dict[str, Any]] | None = None,
        provider: str = "scripted",
        model: str = "scripted-policy",
    ) -> None:
        self.calls = 0
        self.plan_tasks = plan_tasks
        self.last_action = ""
        self.provider = provider
        self._model = model

    # ---------- 与 LLMClient 对齐的属性（编排层会读它做日志/台账）----------

    @property
    def model(self) -> str:
        return self._model

    def describe(self) -> str:
        return f"{self.provider}/{self._model}"

    # ---------- LLMClient 接口 ----------

    def complete(self, messages: list[dict[str, Any]]) -> tuple[str, LLMUsage]:
        self.calls += 1
        system = str(messages[0].get("content", "")) if messages else ""
        usage = LLMUsage(
            prompt_tokens=sum(len(str(m.get("content", ""))) // 4 for m in messages),
            completion_tokens=80,
            total_tokens=sum(len(str(m.get("content", ""))) // 4 for m in messages) + 80,
            cache_hit_tokens=0,
            cache_miss_tokens=100,
        )
        if "<role>你是 HexHound 的编排者" in system:
            return self._plan(), usage
        return self._next(messages, self._role_of(system)), usage

    @staticmethod
    def _role_of(system: str) -> str:
        """从系统提示词判断当前角色（不同角色的剧本不同）。"""
        if "侦察子代理" in system:
            return "recon"
        if "注入验证子代理" in system:
            return "injection"
        if "认证与越权子代理" in system:
            return "auth"
        if "复核子代理" in system:
            return "verify"
        if "审计" in system and "源码" in system:
            return "source"
        return "agent"

    # ---------- 决策 ----------

    def _plan(self) -> str:
        if self.plan_tasks is not None:
            return json.dumps({"thought": "脚本计划", "tasks": self.plan_tasks}, ensure_ascii=False)
        return json.dumps(
            {
                "thought": "先侦察摸清攻面，再按端点并行做注入与认证测试。",
                "tasks": [
                    {
                        "id": "T1",
                        "role": "recon",
                        "objective": "crawl 首页并枚举敏感路径，摸清端点/参数/技术栈",
                        "steps": 8,
                    },
                    {
                        "id": "T2",
                        "role": "auth",
                        "objective": "尝试默认凭据并检查未授权访问的接口",
                        "steps": 6,
                    },
                ],
            },
            ensure_ascii=False,
        )

    def _emit(self, thought: str, action: str, action_input: dict[str, Any]) -> str:
        self.last_action = action
        return json.dumps(
            {"thought": thought, "action": action, "action_input": action_input},
            ensure_ascii=False,
        )

    def _next(self, messages: list[dict[str, Any]], role: str) -> str:
        handler = {
            "recon": self._recon_next,
            "injection": self._injection_next,
            "auth": self._auth_next,
            "verify": self._verify_next,
        }.get(role)
        if handler is None:
            return self._emit("收尾", "finish_task", {"summary": "脚本 LLM 无该角色剧本。"})
        return handler(messages)

    # ---------- 各角色剧本 ----------

    def _recon_next(self, messages: list[dict[str, Any]]) -> str:
        target = self._target(messages)
        last = self._last_observation(messages)
        if not last:
            return self._emit("先爬首页摸清攻击面", "crawl", {"url": target + "/"})
        if "[crawl]" in last:
            return self._emit(
                "枚举常见敏感路径",
                "enumerate_common",
                {"base_url": target, "tiers": ["framework", "leak"], "limit_per_tier": 10},
            )
        if "enumerate_common" in last:
            return self._emit(
                "对发现的前端脚本做接口挖掘",
                "discover_endpoints",
                {"url": target + "/", "max_js": 3},
            )
        if "discover" in last:
            note = self._extract_note(self._all_text(messages))
            if note:
                return self._emit("把可疑点留给注入/认证角色", "leave_note", {"text": note})
            return self._emit(
                "记录敏感路径枚举的覆盖结论",
                "record_coverage",
                {"target": f"{target} 敏感路径枚举", "status": "no_issue_found",
                 "detail": "framework/leak 两档未发现可直接利用的泄露", "owasp": "A05"},
            )
        return self._emit(
            "侦察完成",
            "finish_task",
            {"summary": f"已摸清 {target} 的端点与参数，可疑点已 leave_note 留给注入/认证角色。"},
        )

    def _injection_next(self, messages: list[dict[str, Any]]) -> str:
        last = self._last_observation(messages)
        # 本任务的目标 URL（任务提示词里写明「对 <url> 做定向注入验证」）。
        task_url = self._task_url(messages)
        task_url = self._task_url(messages)
        brief_params = self._params_for_url(messages, task_url) if task_url else {}
        if not last:
            endpoint, params = self._pick_endpoint(messages)
            endpoint = task_url or endpoint
            params = brief_params or params or {"id": "1"}
            method = "POST" if re.search(r"login|signin|auth", endpoint, re.I) else "GET"
            return self._emit(
                f"对 {endpoint} 做定向注入",
                "fuzz_params",
                {"url": endpoint, "method": method, "params": params},
            )
        hit = self._hit_category(last)
        if hit:
            endpoint = task_url or self._pick_endpoint(messages)[0]
            params = brief_params or self._pick_endpoint(messages)[1] or {"id": "1"}
            param = self._pick_param(params) or (next(iter(params), "") if params else "id")
            method = "POST" if re.search(r"login|signin|auth", endpoint, re.I) else "GET"
            if endpoint and param:
                return self._emit(
                    "命中了疑似信号，先做基线对比确认",
                    "compare_responses",
                    {
                        "url": endpoint,
                        "method": method,
                        "params": params,
                        "inject_params": {param: self._payload_for(hit)},
                        "category": hit,
                    },
                )
        if "差异" in last and ("baseline" in last or "injected" in last):
            refs = re.findall(r"\[(\S+-R\d+)\s", last)
            category = self._hit_category(last) or "sqli"
            return self._emit(
                "差异稳定，登记为已复核漏洞",
                "record_finding",
                {
                    "title": f"{category} 注入（脚本 LLM 确认）",
                    "severity": "high",
                    "confidence": "medium",
                    "evidence": last[-300:],
                    "description": "基线/注入响应存在稳定差异，且差异与注入内容直接相关。",
                    "remediation": "对用户输入做参数化查询与输出编码。",
                    "vuln_type": {
                        "sqli": "SQL注入", "xss": "反射型XSS", "path": "任意文件读取",
                        "ssrf": "SSRF", "ssti": "SSTI", "cmd": "命令注入",
                    }.get(category, "注入类漏洞"),
                    "url": self._url_from_observation(last) or task_url,
                    "evidence_ref": refs[:2],
                    "verified": True,
                    "verification": "重放基线/注入两份请求，差异稳定复现。",
                    "counterevidence": "仅本地靶场验证，未确认生产影响面。",
                },
            )
        if "record_finding" in last or "record_coverage" in last:
            return self._emit(
                "本轮注入验证收尾",
                "finish_task",
                {"summary": "已完成本端点的定向注入验证，结论见 record_finding/record_coverage。"},
            )
        if "fuzz 完成" in last or "未发现异常" in last:
            return self._emit(
                "记录本端点已测结论",
                "record_coverage",
                {"target": f"注入测试：{task_url or last.splitlines()[0][:60]}",
                 "status": "no_issue_found", "detail": "定向 fuzz 未发现异常信号", "owasp": "A03"},
            )
        if "compare" in last:
            return self._emit(
                "对比未形成有效差异，记录结论",
                "record_coverage",
                {"target": f"对比测试：{task_url}", "status": "ruled_out",
                 "detail": "基线/注入响应无稳定差异", "owasp": "A03"},
            )
        return self._emit(
            "收尾",
            "finish_task",
            {"summary": "定向注入验证结束（无进一步可测项）。"},
        )

    def _auth_next(self, messages: list[dict[str, Any]]) -> str:
        target = self._target(messages)
        last = self._last_observation(messages)
        if not last:
            login = self._find_login(messages) or (target + "/login")
            return self._emit(
                "先试默认凭据", "check_default_creds", {"url": login}
            )
        if "check_default_creds" in last or "默认凭据" in last:
            api = self._find_api(messages) or (target + "/api/users")
            return self._emit(
                "检查接口是否未授权可读",
                "http_request",
                {"url": api, "note": "未授权访问测试"},
            )
        if "http_request" in last:
            if any(token in last for token in ("mobile", "idcard", "phone", "email", "email", "身份证", "手机号")):
                refs = re.findall(r"\[(\S+-R\d+)\]", last)
                return self._emit(
                    "接口匿名可读到个人敏感数据，登记为已复核",
                    "record_finding",
                    {
                        "title": "未授权访问导致敏感个人信息泄露",
                        "severity": "high",
                        "confidence": "medium",
                        "evidence": last[-300:],
                        "description": "接口无需任何认证即返回用户手机号/身份证等个人信息。",
                        "remediation": "接口增加鉴权与越权校验，最小化返回字段。",
                        "vuln_type": "未授权访问",
                        "url": self._url_from_observation(last),
                        "evidence_ref": refs[:1],
                        "verified": True,
                        "verification": "匿名（不带任何 Cookie）请求该接口，响应直接包含他人个人信息。",
                        "counterevidence": "尚未确认这些字段是否为公开信息。",
                        "owasp": "A01",
                    },
                )
            return self._emit(
                "记录认证与未授权测试结论",
                "record_coverage",
                {"target": "认证与未授权访问", "status": "no_issue_found",
                 "detail": "默认凭据未命中，接口未返回敏感数据", "owasp": "A07"},
            )
        return self._emit("认证测试收尾", "finish_task", {"summary": "认证/越权测试完成。"})

    def _verify_next(self, messages: list[dict[str, Any]]) -> str:
        last = self._last_observation(messages)
        if not last:
            return self._emit("先看候选池", "review_candidates", {"include_tried": False})
        if "review_candidates" in last or "待复核候选" in last or "候选池为空" in last:
            pending = re.findall(r"\[(HH-\d+)\]", last)
            if pending:
                first = pending[0]
                return self._emit(
                    f"重放候选 {first} 的证据请求",
                    "http_request",
                    {"url": self._target(messages) + "/login", "method": "POST",
                     "data": {"username": "'", "password": "x"},
                     "note": f"复核候选 {first}"},
                )
            return self._emit("候选池为空，结束复核", "finish_task", {"summary": "无可复核候选。"})
        if "http_request" in last:
            reproducible = any(
                token in last
                for token in ("SQL 错误", "unrecognized token", "syntax error", "200 OK", "500")
            )
            note = "证据请求已重放，响应仍含异常特征。" if reproducible else "重放未复现原现象。"
            return self._emit(
                "结束复核", "finish_task", {"summary": note + "（脚本 LLM 的保守复核策略）"}
            )
        return self._emit("复核收尾", "finish_task", {"summary": "复核阶段结束。"})

    # ---------- 解析辅助 ----------

    def _last_observation(self, messages: list[dict[str, Any]]) -> str:
        for message in reversed(messages):
            content = str(message.get("content", ""))
            if message.get("role") == "user" and content.startswith("观察结果"):
                return content
        return ""

    def _hit_category(self, text: str) -> str:
        for token in ("sqli", "xss", "path", "ssrf", "ssti", "cmd", "nosqli", "fmt", "redirect"):
            if f"[{token}]" in text:
                return token
        return ""

    def _pick_param(self, params: dict[str, str]) -> str:
        for name in params:
            if name.lower() in INTERESTING_PARAMS:
                return name
        return next(iter(params), "")

    def _find_login(self, messages: list[dict[str, Any]]) -> str:
        text = self._all_text(messages)
        match = re.search(r"(https?://\S*/[^\s]*login[^\s]*)", text, re.I)
        return match.group(1).rstrip("，,）)") if match else ""

    def _find_api(self, messages: list[dict[str, Any]]) -> str:
        text = self._all_text(messages)
        match = re.search(r"(https?://[^\s，,）)]*/api/[^\s，,）)]*)", text)
        return match.group(1) if match else ""

    def _all_text(self, messages: list[dict[str, Any]]) -> str:
        return "\n".join(str(m.get("content", "")) for m in messages)

    def _payload_for(self, category: str) -> str:
        return {
            "sqli": "'",
            "xss": "<script>alert(1)</script>",
            "path": ".env",
            "ssrf": "http://127.0.0.1:1/hexhound-canary-probe-9c1f",
            "ssti": "{{7*7}}",
            "cmd": "; whoami",
            "nosqli": "' || '1'=='1",
            "fmt": "{name.__class__}",
            "redirect": "//example.invalid/hexhound",
        }.get(category, "'")

    def _target(self, messages: list[dict[str, Any]]) -> str:
        """从提示词里取目标 URL（只匹配 URL 允许的字符，避免吃进后面的中文说明）。"""
        match = re.search(
            r"目标：\s*(https?://[-\w.]+(?::\d+)?(?:/[\w./%\-]*)?)",
            self._all_text(messages),
        )
        return match.group(1).rstrip("/") if match else "http://127.0.0.1:5000"

    def _url_from_observation(self, text: str) -> str:
        match = re.search(r"(https?://[-\w.]+(?::\d+)?(?:/[\w./%\-?=&]*)?)", text)
        return match.group(1) if match else ""

    def _task_url(self, messages: list[dict[str, Any]]) -> str:
        """从任务目标里取「对 <url> 做…」中的 URL（子代理被指派的端点在目标里）。"""
        match = re.search(
            r"<objective>\s*(.*?)\s*</objective>", self._all_text(messages), re.S
        )
        objective = match.group(1) if match else ""
        found = re.search(r"(https?://[-\w.]+(?::\d+)?(?:/[\w./%\-?=&]*)?)", objective)
        return found.group(1).rstrip("/") if found else ""

    def _params_for_url(self, messages: list[dict[str, Any]], url: str) -> dict[str, str]:
        """从攻面简报里取该 URL 的已知参数名。"""
        if not url:
            return {}
        text = self._all_text(messages)
        pattern = re.escape(url) + r"(?:\{[^}]*\})?\s+参数\[([^\]]+)\]"
        match = re.search(pattern, text)
        if not match:
            return {}
        names = [name for name in match.group(1).split(",") if name and name != "-"]
        return {name: "1" for name in names[:3]}

    def _extract_note(self, crawl_output: str) -> str:
        """从 crawl 输出里挑一条值得留给注入角色的线索。"""
        for line in crawl_output.splitlines():
            stripped = line.strip()
            if stripped.startswith("POST ") or stripped.startswith("GET "):
                return f"表单可测：{stripped[:160]}"
        for line in crawl_output.splitlines():
            stripped = line.strip()
            if stripped.startswith("http") and ("?" in stripped or "api" in stripped.lower()):
                return f"带参接口可测：{stripped[:160]}"
        return ""

    def _pick_endpoint(self, messages: list[dict[str, Any]]) -> tuple[str, dict[str, str]]:
        """从对话里挑一个带参数的端点（模拟模型的"选目标"决策）。"""
        text = self._all_text(messages)
        # 攻面简报里的「参数[xxx]」行优先。
        for match in re.finditer(r"(https?://[-\w.]+(?::\d+)?\S*)\s+参数\[([^\]]+)\]", text):
            url, params = match.group(1), match.group(2)
            if params and params != "-":
                return url, {name: "1" for name in params.split(",")[:3] if name}
        fuzzed = set(re.findall(r"对 (\S+) 做定向注入", text))
        for match in re.finditer(r"(https?://[-\w.]+(?::\d+)?/[^\s，,）)]*)", text):
            url = match.group(1)
            if url in fuzzed or "?" not in url:
                continue
            query = url.split("?", 1)[1]
            params = {item.split("=")[0]: "1" for item in query.split("&") if item}
            if params:
                return url.split("?", 1)[0], params
        return "", {}

    def _finish_verify(self, text: str) -> str:
        return self._emit(
            "复核完成",
            "finish_task",
            {"summary": "已逐条查看候选；证据不足的不予提升（脚本 LLM 的保守策略）。"},
        )


__all__ = ["INTERESTING_PARAMS", "ScriptedLLM"]
