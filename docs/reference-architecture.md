# 参考架构：Strix 与 PentAGI 的可移植机制

> 本文是 HexHound v0.2 优化的**依据清单**。两份参考项目的完整技术简报保存在
> `research/pentagi/BRIEF.md` 与 `_strix_research/STRIX_BRIEF.md`（含逐条源码出处）。
>
> ⚠️ 注意（研究过程中发现的坑）：网上多数博客描述的 Strix 工具层（`strix/tools/{terminal,python,browser}`
> + `*_schema.xml`）在 `main` 分支上**已不存在**——它已迁移到 OpenAI Agents SDK 的
> `Shell`/`Filesystem` capabilities。任何只读博客写出的 Strix 架构说明都是过期的。
> 本文所有结论均来自源码/官方仓库，不是二手转述。

## 1. Strix（usestrix/strix，Apache-2.0，Python）

| 机制 | 源码事实 | HexHound 的取舍 |
| --- | --- | --- |
| Manager + Workers | `SandboxAgent` + `make_child_factory`，root 与 child 同 class，靠工具集与提示词区分 | ✅ 采纳：`orchestrator.py` 的编排者只拆任务（无工具），子代理按角色裁剪工具 |
| 图/协调器 | `strix/core/agents.py` 的 `AgentCoordinator`（runtime registry + asyncio inbox，`budget_paused` 状态） | ⚠️ 简化：单进程分波并行（ThreadPoolExecutor），不做消息邮箱 |
| 沙箱隔离 | **每个 scan 一个容器**（不是每个 agent），Kali 镜像 + Caido 代理 sidecar；host 侧走 SDK `Shell`/`Filesystem` | ❌ 不采纳：HexHound 保持零 Docker，靠主机白名单 + 只读约束 + 限速 |
| 发现门（核心） | `create_vulnerability_report` 硬校验必填字段：`poc_script_code`、`evidence`、`counterevidence`、`confidence_rationale`、8 项 CVSS 指标；`http_exchange_ids` 会**对着实时代理项目校验，未知编号直接拒绝** | ✅ 全采纳：`record_finding` 的 verified 门 + 证据编号校验 + 反证/置信度理由字段 |
| 负空间追踪 | `VALID_OUTCOMES`（reported / no_issue_found / ruled_out / not_applicable / needs_follow_up）+ `coverage.json` | ✅ 采纳：`surface.record_coverage` + 报告覆盖矩阵 |
| 预算纪律 | `budget_paused` 状态；子代理预算预留 `_SUBAGENT_BUDGET_RESERVE=0.90`；预警带 `(0.70,0.85,0.95)` 注入 `<NOTICE\|URGENT\|CRITICAL>` 收尾指令 | ✅ 采纳：`Budget.WARN_BANDS` + 越线优雅收尾 |
| 重复动作监督 | 同一工具重复调用告警/中止（本家为 3 次告警） | ✅ 采纳：`TaskWorker.REPEAT_WARN=3 / REPEAT_ABORT=5` |
| 输出治理 | `ContextSettings(tool_output_max_tokens=8000, max_output_lines=2000, 50KiB)`；`_with_bounded_result` 头尾截断 + spill | ✅ 采纳（并对齐 PentAGI 分档）：`tools._govern` |
| 去重 | `report/dedupe.py` 用 LLM 判定（同根因+同组件+同修复 = 重复），异常时 fail-open | ⚠️ 改良：改用**确定性指纹**（`dedupe.py`），不花 token 也不会 fail-open |
| 本地查看器 | `strix view`：预构建 SPA + `secrets.token_urlsafe(32)` 会话 cookie，`/api/{runs,run,vulnerabilities,report,transcript}` | ⚠️ 部分：HexHound 沿用 Flask GUI + `~/.hexhound/runs/` 产物目录 |
| CI 退出码 | `0` 干净 / `1` 致命 / `2` 发现漏洞 | ✅ 采纳：`--fail-on <severity>` → 退出码 2 |
| 自述短板 | 无 per-agent 隔离、资源限制可选、dedupe fail-open、prompt 渲染异常静默返回空串、代码审查类发现被迫造 PoC | 据此：HexHound 不做 Docker、去重走确定性、PoC 门只对"需要 http 证据"的类别生效 |

## 2. PentAGI（vxcontrol/pentagi，MIT）

| 机制 | 源码事实 | HexHound 的取舍 |
| --- | --- | --- |
| 角色与编排 | 13 种 agent 类型；**primary agent 没有任何 terminal/file/browser 工具**，只能委派（delegation-only orchestrator） | ✅ 采纳：编排者无工具；角色=工具白名单（`tools.ROLE_TOOLS`） |
| 任务分层 | `flow → task → subtask`；Generator 一次给 `subtask_list`（上限 15），Refiner 给增量 `subtask_patch` | ✅ 采纳轻量版：编排者输出 JSON 任务列表（≤6），到期后由兜底计划补波 |
| 工具调用上限 | `MAX_GENERAL_AGENT_TOOL_CALLS=100` / `MAX_LIMITED_AGENT_TOOL_CALLS=20`；重复调用 3 次告警、7 次中止 | ✅ 采纳：`task_steps` + `REPEAT_WARN/ABORT` + `MAX_TOOL_CALLS` 预算 |
| **输出治理（最值得抄）** | `DefaultResultSizeLimit=16KB`；>16KB 只给 `{terminal,browser}` 做 LLM 摘要（目标 ≤8KB）；>32KB 保留头 16KB + 尾，中间标注省略；参数值截断 1024 字符 | ✅ 全采纳：`GOVERNOR_*` 常量与 `_truncate_args` |
| 提示词工程 | 39 个 `.tmpl`；XML 语义分节（`<container_constraints>`/`<terminal_protocol>`/`<memory_protocol>`/`<delegation_rules>`）；每个专家都有强制收尾工具（`hack_result`/`code_result`/`done`）；动作经济 3–5 次检索；`<engagement_scope>` 8 步自检 | ✅ 采纳：`prompts.py` 按角色 XML 分节 + `finish_task` 强制收尾 |
| 记忆三层 | long-term（pgvector，collection `langchain`，阈值 0.2/top-3 硬编码）+ working context + episodic history；可选 Graphiti/Neo4j | ✅ 零依赖落地：`surface.py`(working) + `memory.TaskLedger`(episodic) + `memory.HostMemory`(long-term JSON) |
| 链式摘要 | `pkg/csum`：section → 超长 body pair → QA 摘要，**只有当结果更小才替换**；`MAX_BP_BYTES=16384` 等硬常量 | ⚠️ 简化：`agent._summarize_steps` 分层摘要（关键动作优先保留） |
| 监督/反思 | reflector 在"无工具调用"、连续 3 次失败、接近迭代上限时触发；execution monitor（mentor）走 adviser | ⚠️ 部分：重复动作监督 + 预算预警；不做 LLM 反思（成本考虑） |
| 可观测性 | Langfuse + OTel；每 agent 的 `CallUsage`（输入/输出/缓存读写/成本） | ⚠️ 简化：进程内 `Budget.Usage` + 报告/界面展示 |
| 自述短板（关键） | **代码层没有 scope 强制**（只有提示词模板，自己也承认后端校验未实现）；**没有结构化漏洞模型**（无 severity/CVSS/evidence/去重）；无速率限制；无费用上限 | 这正是 HexHound 的差异化：白名单在 `tools._validate_url` 里硬拦、结构化 finding + 去重指纹 + 预算上限 + 限速 |

## 3. 三个"抄了但没照抄"的判断

1. **确定性 vs LLM 去重**：Strix 用 LLM 判重、PentAGI 完全没有漏洞模型。HexHound 用
   `(漏洞类别, 归一化路径, 参数)` 指纹——零 token、可测试、不会 fail-open。
2. **零基建 vs 微服务**：PentAGI 需要 Postgres+pgvector+Neo4j+Langfuse 才能跑起来。
   HexHound 的记忆层是 JSON 文件（`~/.hexhound/`），保持 `pip install` 即用。
3. **主机白名单 vs 容器隔离**：Strix 的隔离边界是容器，PentAGI 靠 Docker + Kali 镜像。
   HexHound 不隔离执行环境，因此把安全边界放在**代码层**：白名单校验、不跟随重定向、
   只读验证、限速、预算上限——这也是 PentAGI 自己缺失的那一层。

## 4. 值得继续跟进的点（v0.3 候选）

- Strix 的 `spill store`（超长工具输出落盘 + 按需回读）——HexHound 目前只做截断。
- PentAGI 的 `subtask_patch` 增量计划（运行中动态加/删/改任务）——目前只在波次边界补任务。
- Strix 的 `scope_rules`（代理可维护的作用域规则）——HexHound 的白名单是静态的。
- 两者都缺的：**跨运行 diff**（上次报了什么、这次新报了什么）——`HostMemory` 已经存了历史 findings，做 diff 的成本很低。
