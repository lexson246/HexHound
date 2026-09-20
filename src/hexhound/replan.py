"""有界动态重规划：只在波次边界、用结构化 patch 表达增删改，且有硬上限。

对标机制来源：PentAGI 的 Refiner 在运行中产出 `subtask_patch`
（add / remove / modify / reorder），并有 `fixSubtaskPatch` 做自修复
（见 `docs/research-notes/strix-pentagi-refresh-2026.md` §C4）。它的做法是
把 patch 写进数据库链上，因此天然可回溯；HexHound 零外置服务，
用「内存里的计划 + trace 里的事件流」达到同样的可审计性。

**HexHound 刻意加上的约束**（PentAGI 没有这几条）：

1. **只在波次边界重规划**。波次内部不动计划——正在执行的子任务其目标被改掉，
   产出就与目标不对应了，报告也说不清"这条结论是哪个目标下的"。
2. **结构化 patch**（add / update / remove），不是让模型重写整份计划。
   重写整份计划会静默丢掉已经派出去的任务，而"丢任务"这件事必须可审计。
3. **硬上限**：每次重规划新增任务数、重规划轮数、总任务数、依赖深度。
   没有上限的"自适应规划"就是收敛不了的烧钱循环。
4. **不允许通过重规划扩大授权目标范围**：patch 里的 URL 必须与攻面里的
   域名同一份白名单——重规划不能成为绕开作用域校验的旁路。
5. **任务 ID 确定性可重放**：patch 携带的 id 要么已存在（update/remove），
   要么由目标内容确定性派生（add）。同一个目标 + 同一份攻面 → 同一组 id，
   因此一次运行可以被逐条复现。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# 上限（全部是硬编码常量，不通过提示词约束——提示词失效时这些仍然生效）
# ---------------------------------------------------------------------------

#: 一次重规划最多新增几个任务。
MAX_NEW_TASKS_PER_PATCH = 3

#: 一次运行最多重规划几轮。
MAX_REPLAN_ROUNDS = 3

#: 一次运行的任务总数上限（初始计划 + 所有重规划新增 + 补扫 + 复核）。
MAX_TOTAL_TASKS = 40

#: 依赖链的最大深度（防止依赖环或长链把调度拖死）。
MAX_DEPENDENCY_DEPTH = 4

#: 允许出现在 patch 里的操作。
PATCH_OPS = ("add", "update", "remove")

#: 允许被 update 修改的字段（**不含 id / role / url**）。
#:
#: 为什么不让改这三个：改 id 会让台账与 trace 对不上；改 role 等于换执行者，
#: 已经跑过的证据归属就错了；改 url 是扩大/改变攻击目标——那必须走"新增任务"，
#: 而不是"把已有任务偷偷指向别处"。
MUTABLE_FIELDS = ("objective", "steps", "depends_on", "priority")


def deterministic_task_id(role: str, url: str, objective: str, *, salt: str = "") -> str:
    """由任务内容派生**确定性** id（同一输入永远得到同一 id）。

    为什么不用自增序号：重放一次运行时，序号取决于"当时派发了多少任务"，
    而内容派生只取决于内容。这让"两次运行的任务 id 一致"成为可验证的性质，
    而不是巧合。前缀 `R` 标明它来自重规划，便于在台账里一眼区分。
    """
    material = f"{role}\x00{url}\x00{objective}\x00{salt}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:8]
    return f"R-{digest}"


# ---------------------------------------------------------------------------
# 计划模型（与 orchestrator.WorkerTask 兼容的最小视图）
# ---------------------------------------------------------------------------


@dataclass
class PlanEntry:
    """计划里的一条任务（重规划视角的最小字段集）。"""

    id: str
    role: str
    objective: str
    url: str = ""
    steps: int = 10
    depends_on: list[str] = field(default_factory=list)
    priority: int = 0
    source: str = "initial"  # initial / replan / sweep / verify

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "objective": self.objective,
            "url": self.url,
            "steps": self.steps,
            "depends_on": list(self.depends_on),
            "priority": self.priority,
            "source": self.source,
        }


@dataclass
class PatchResult:
    """一次 patch 的应用结果（无论成败都返回，供 trace 记录）。"""

    ok: bool
    applied: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "applied": list(self.applied),
            "rejected": list(self.rejected),
        }


class ReplanError(ValueError):
    """patch 本身不合法（结构与上限）。"""


# ---------------------------------------------------------------------------
# patch 解析与校验
# ---------------------------------------------------------------------------


def parse_patch(raw: Any) -> list[dict[str, Any]]:
    """把模型给出的 patch 解析成操作列表。

    接受两种形态（都常见）：
    - `{"ops": [{"op": "add", ...}, ...]}`；
    - 直接是 `[{...}, {...}]`。

    每条操作会被规范化成 `{"op": "add"|"update"|"remove", ...}`。
    结构不对**直接报错**，不做"猜意图"的容错——静默忽略一条操作，
    就等于计划与模型以为的不一致，而报告看不出来。
    """
    if isinstance(raw, dict):
        ops = raw.get("ops")
        if ops is None:
            ops = raw.get("operations")
        if ops is None:
            raise ReplanError(
                "patch 里没有 `ops` 数组。请给出 {\"ops\": [{\"op\": \"add\", ...}]}。"
            )
    elif isinstance(raw, list):
        ops = raw
    else:
        raise ReplanError(f"patch 必须是对象或数组，收到 {type(raw).__name__}。")
    if not isinstance(ops, list):
        raise ReplanError(f"`ops` 必须是数组，收到 {type(ops).__name__}。")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(ops, 1):
        if not isinstance(item, dict):
            raise ReplanError(f"第 {index} 条操作不是对象（{type(item).__name__}）。")
        op = str(item.get("op") or "").strip().lower()
        if op not in PATCH_OPS:
            raise ReplanError(
                f"第 {index} 条操作的 op={op!r} 不受支持，"
                f"只允许 {', '.join(PATCH_OPS)}。"
            )
        entry = dict(item)
        entry["op"] = op
        normalized.append(entry)
    if not normalized:
        raise ReplanError("patch 里没有任何操作。")
    return normalized


def apply_patch(
    plan: list[PlanEntry],
    ops: list[dict[str, Any]],
    *,
    allowed_hosts: frozenset[str],
    target_host: str = "",
    total_tasks: int = 0,
    existing_ids: Iterable[str] = (),
    salt: str = "",
) -> tuple[list[PlanEntry], PatchResult]:
    """把 patch 应用到一个计划上，返回 `(新计划, 结果)`。

    **逐条操作独立判定**：一条被拒不会让整份 patch 失败——但被拒的每一条
    都会进 `result.rejected` 并写明原因，最终写进 trace。
    这样"模型想加 3 个任务、只有 1 个合法"这种情况既不会整体白费，
    也不会让不合法的那个静默消失。
    """
    result = PatchResult(ok=True)
    working = list(plan)
    index_by_id = {entry.id: position for position, entry in enumerate(working)}
    known_ids = set(index_by_id) | {str(item) for item in existing_ids}
    added = 0
    reserved = max(0, MAX_TOTAL_TASKS - max(0, int(total_tasks or 0)))

    def reject(op: dict[str, Any], reason: str) -> None:
        result.rejected.append({"op": op.get("op"), "id": op.get("id"), "reason": reason})

    for op in ops:
        kind = op["op"]
        if kind in ("update", "remove"):
            task_id = str(op.get("id") or "").strip()
            if not task_id:
                reject(op, "缺少 id")
                continue
            if task_id not in index_by_id:
                reject(op, f"计划里没有任务 {task_id!r}（id 必须来自当前计划）")
                continue
            position = index_by_id[task_id]
            if kind == "remove":
                removed = working.pop(position)
                index_by_id = {entry.id: idx for idx, entry in enumerate(working)}
                result.applied.append({"op": "remove", "id": removed.id})
                continue
            changes = op.get("changes")
            if not isinstance(changes, dict) or not changes:
                reject(op, "update 需要 `changes` 对象")
                continue
            entry = working[position]
            blocked = [
                key for key in changes
                if key not in MUTABLE_FIELDS
            ]
            if blocked:
                reject(
                    op,
                    f"不允许修改字段 {', '.join(sorted(blocked))}"
                    f"（可改：{', '.join(MUTABLE_FIELDS)}）。"
                    "改 id/role/url 会让台账、证据归属或攻击目标与已发生的执行对不上——"
                    "那必须走 add 新任务。",
                )
                continue
            if "steps" in changes:
                try:
                    steps = int(changes["steps"])
                except (TypeError, ValueError):
                    reject(op, f"steps 不是整数：{changes['steps']!r}")
                    continue
                if steps < 1 or steps > 30:
                    reject(op, f"steps={steps} 超出允许范围 1..30")
                    continue
                changes["steps"] = steps
            updated = PlanEntry(**{**entry.to_dict(), **changes})
            working[position] = updated
            result.applied.append(
                {"op": "update", "id": task_id, "changes": sorted(changes)}
            )
            continue

        # ---- add ----
        if added >= MAX_NEW_TASKS_PER_PATCH:
            reject(
                op,
                f"本次重规划新增任务已达上限 {MAX_NEW_TASKS_PER_PATCH}"
                "（无上限的自适应规划就是收敛不了的烧钱循环）",
            )
            continue
        role = str(op.get("role") or "").strip().lower()
        if role not in ("recon", "injection", "auth", "verify", "source"):
            reject(op, f"role={role!r} 不是合法角色")
            continue
        objective = str(op.get("objective") or "").strip()
        if not objective:
            reject(op, "缺少 objective")
            continue
        url = str(op.get("url") or "").strip() or str(op.get("target") or "").strip()
        scope_error = check_scope_unchanged(url, allowed_hosts, target_host)
        if scope_error:
            reject(op, scope_error)
            continue
        try:
            steps = int(op.get("steps") or 10)
        except (TypeError, ValueError):
            steps = 10
        steps = max(4, min(steps, 20))
        depends_on = [
            str(item) for item in (op.get("depends_on") or []) if str(item).strip()
        ]
        missing = [item for item in depends_on if item not in known_ids]
        if missing:
            reject(op, f"依赖的任务不存在：{', '.join(missing)}")
            continue
        if len(depends_on) > MAX_DEPENDENCY_DEPTH:
            reject(
                op,
                f"依赖数 {len(depends_on)} 超过上限 {MAX_DEPENDENCY_DEPTH}"
                "（长依赖链会把调度拖死）",
            )
            continue
        task_id = str(op.get("id") or "").strip()
        if not task_id:
            task_id = deterministic_task_id(role, url, objective, salt=salt)
        if task_id in known_ids:
            reject(op, f"任务 id {task_id!r} 已存在（add 不能覆盖已有任务，请用 update）")
            continue
        if reserved <= 0:
            reject(op, f"任务总数已达上限 {MAX_TOTAL_TASKS}")
            continue
        entry = PlanEntry(
            id=task_id,
            role=role,
            objective=objective[:400],
            url=url,
            steps=steps,
            depends_on=depends_on,
            priority=int(op.get("priority") or 0),
            source="replan",
        )
        working.append(entry)
        known_ids.add(task_id)
        index_by_id[task_id] = len(working) - 1
        added += 1
        reserved -= 1
        result.applied.append({"op": "add", "id": task_id, "role": role, "url": url})

    cycle = detect_dependency_cycle(working)
    if cycle:
        result.ok = False
        result.reason = f"应用后出现依赖环：{' -> '.join(cycle)}"
        return plan, result  # 整份回滚：带环的计划无法可靠调度
    if not result.applied and result.rejected:
        result.ok = False
        result.reason = "patch 里的操作全部被拒绝"
    return working, result


def check_scope_unchanged(
    url: str, allowed_hosts: frozenset[str], target_host: str = ""
) -> str:
    """重规划**不能**扩大授权目标范围。

    规则比"在白名单内"更严：新任务的 URL 主机必须与本次授权的目标主机一致。
    理由：白名单里可能同时有多个主机（例如 `127.0.0.1` 与生产域名），
    而本次运行的授权目标是**其中一个**；重规划把任务指到白名单里的另一个主机，
    虽然"在白名单内"，但已经越过了本次用户明确指定的范围。
    返回空串表示通过，否则返回拒绝原因。
    """
    text = str(url or "").strip()
    if not text:
        return ""  # 没给 URL：沿用目标主机，不算扩大范围
    if not text.lower().startswith(("http://", "https://")):
        return (
            f"新任务的 url={text!r} 不是完整 URL。"
            "重规划必须给出明确的目标地址（不能靠重规划引入新主机）。"
        )
    host = (urlparse(text).hostname or "").lower()
    if not host:
        return f"无法从 url={text!r} 解析主机。"
    if host not in allowed_hosts:
        return (
            f"新任务的目标主机 {host!r} 不在白名单内。"
            "重规划不能扩大授权范围。"
        )
    if target_host and host != target_host:
        return (
            f"新任务的目标主机 {host!r} 与本次授权目标 {target_host!r} 不一致。"
            "重规划不能把任务移到授权范围之外（哪怕那个主机也在白名单里）。"
        )
    return ""


def detect_dependency_cycle(plan: list[PlanEntry]) -> list[str]:
    """检测依赖环，返回环上的 id 列表（无环返回空）。"""
    graph = {entry.id: [dep for dep in entry.depends_on if dep] for entry in plan}
    state: dict[str, int] = {}  # 0 未访问 / 1 访问中 / 2 已完成
    stack: list[str] = []

    def visit(node: str) -> list[str]:
        if state.get(node) == 1:
            return stack[stack.index(node):] + [node]
        if state.get(node) == 2:
            return []
        state[node] = 1
        stack.append(node)
        for neighbour in graph.get(node, []):
            if neighbour in graph:
                found = visit(neighbour)
                if found:
                    return found
        stack.pop()
        state[node] = 2
        return []

    for node in graph:
        found = visit(node)
        if found:
            return found
    return []


def ready_tasks(
    plan: list[PlanEntry], completed: Iterable[str] = ()
) -> list[PlanEntry]:
    """返回"可以开始执行"的任务：依赖已满足 **且自己还没完成**。

    `completed` 显式传入而不是存在模块全局变量里：并发子代理共用同一个进程，
    全局可变状态会让两个 worker 互相看到对方的完成集合——那是无法调试的 bug。

    语义上排除已完成的：函数名是"ready"（可执行的），
    把已经跑完的任务再列出来会让调用方重复派发。

    确定性排序：先按 priority 降序，再按 id 升序。没有这一步，
    同一份计划在不同运行里的执行顺序会随字典顺序漂移，"可重放"就不成立。
    """
    done = {str(item) for item in completed}
    present = {entry.id for entry in plan}
    ready = [
        entry for entry in plan
        if entry.id not in done
        and all(dep not in present or dep in done for dep in entry.depends_on)
    ]
    return sorted(ready, key=lambda item: (-item.priority, item.id))


# ---------------------------------------------------------------------------
# 重规划政策（轮数与触发条件）
# ---------------------------------------------------------------------------


@dataclass
class ReplanPolicy:
    """重规划的次数与触发判定。"""

    max_rounds: int = MAX_REPLAN_ROUNDS
    rounds_used: int = 0
    #: 至少要出现多少"新盲区"才值得重规划一次（避免为 1 个端点开一轮）。
    min_new_gaps: int = 2

    def can_replan(self) -> bool:
        return self.rounds_used < max(0, int(self.max_rounds))

    def should_replan(self, before: dict[str, Any], after: dict[str, Any]) -> tuple[bool, str]:
        """基于两次覆盖率闸门快照判断是否值得重规划。

        触发条件只有一条：**盲区在扩大或没有缩小，且有新发现的端点/参数**。
        盲区在缩小说明当前的补扫有效，继续按原计划走即可。
        """
        if not self.can_replan():
            return False, f"重规划轮数已用完（{self.rounds_used}/{self.max_rounds}）"
        new_untouched = int(after.get("untouched", 0)) - int(before.get("untouched", 0))
        new_params = int(after.get("params_unattacked", 0)) - int(
            before.get("params_unattacked", 0)
        )
        if new_untouched < self.min_new_gaps and new_params < self.min_new_gaps:
            return False, (
                f"盲区没有明显增长（端点 {new_untouched:+d}、参数 {new_params:+d}，"
                f"阈值 {self.min_new_gaps}），不需要重规划"
            )
        return True, (
            f"发现新盲区：端点 {new_untouched:+d}、参数 {new_params:+d}"
            "（重规划只在波次边界进行）"
        )

    def take(self) -> None:
        self.rounds_used += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "rounds_used": self.rounds_used,
            "max_rounds": self.max_rounds,
            "min_new_gaps": self.min_new_gaps,
        }


__all__ = [
    "MAX_DEPENDENCY_DEPTH",
    "MAX_NEW_TASKS_PER_PATCH",
    "MAX_REPLAN_ROUNDS",
    "MAX_TOTAL_TASKS",
    "MUTABLE_FIELDS",
    "PATCH_OPS",
    "PatchResult",
    "PlanEntry",
    "ReplanError",
    "ReplanPolicy",
    "apply_patch",
    "check_scope_unchanged",
    "detect_dependency_cycle",
    "deterministic_task_id",
    "parse_patch",
    "ready_tasks",
]
