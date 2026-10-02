# 评测（带标准答案）：检出率 / 误报率 / 耗时 / 成本

> 工具：`tools/eval_scenarios.py`｜标准答案：`evals/scenarios.json`｜口径测试：`tests/test_eval_scenarios.py`
>
> 为什么需要它：在此之前只有"能跑通"的验收（`tools/verify_*.py` 证明链路活着），
> 没有"跑得准不准"的量化——改了 payload 库或判定规则之后，没人能回答
> "这次是变好还是变坏"。这份评测就是那个"变好还是变坏"的判据。

---

## 1. 两个层级，刻意分开

| 层级 | 命令 | 花额度 | 衡量什么 |
| --- | --- | --- | --- |
| **引擎层** | `python tools/eval_scenarios.py --tier engine` | 否 | payload 库 + **信号判定规则**（与模型无关，可重复、可回归） |
| **Agent 层（脚本）** | `python tools/eval_scenarios.py --tier agent --llm scripted` | 否 | 整条链子的**管道正确性**（编排/工具/记录/报告）；脚本策略是固定剧本，**不是能力指标** |
| **Agent 层（真实模型）** | `python tools/eval_scenarios.py --tier agent --llm live --allow-live` | **是** | 真实检出能力（必须显式加 `--allow-live`，否则拒绝执行） |

为什么必须分开：把"判定规则准不准"和"模型会不会用工具"混成一个数字，
出了问题无法定位——引擎层 100% 而 Agent 层 12% 与两者都低，处理方式完全不同。

## 2. 指标口径（产物里同时给原始计数，避免只看百分比）

* **检出率** = 命中场景 / 应命中场景。**分母不含"无结论"**：被限流/阻断/请求失败
  记 `inconclusive` 并单独列出——"没测成"绝不等同于"漏报"（这是本项目的核心不变量）。
* **误报率** = 报了信号的"应当安静"场景 / 应当安静场景数。
  两类"应当安静"**分开**：
  * `none`：真的不该有反应（静态资源、首页参数被忽略、payload 被转义）；
  * `reflection_only`：字符串层面确实是反射（例如 `/reflect-csp` 回显了 payload
    但 CSP 禁止内联脚本）——引擎命中它**不算误报**，只有浏览器层能判它可不可执行；
    Agent 把它记成 XSS 才算误报。
* **耗时** = 墙钟；**成本** = 预算账本 token + 估算费用（引擎层为 0）。
* **"命中"怎么算**（Agent 层）：`findings/candidates` 里有 **端点路径 + 类型关键词**
  都对得上的条目；或者覆盖记录里有 `status=reported`、且 detail 的类型关键词也对得上的行
  （`coverage_mentions`，为"回归复核型"运行准备的——那种运行会把"仍成立"写进覆盖记录
  而不重复 `record_finding`）。两条判据都**不从自由文本里猜**：
  任务总结里写了什么不算，`not_tested`/`no_issue_found` 也不算。
  类型关键词这一条是必须的：只认"端点 + reported"时，脚本层那档有两条自相矛盾的记录
  （端点 `/ssti`、结论写"sqli 注入"）被算成命中，检出率虚高到 37.5%（见 §4）。

## 3. 标准答案从哪来

`evals/scenarios.json` 里每个场景都对应 `vulnlab` 的**已知漏洞**，并且都能被
`tools/verify_lab_new_vulns.sh` / `verify_lab_business_logic.sh` **手工复现**
（不经过 HexHound）——这就是"标准答案"的可信度来源，而不是我们自己的工具说了算。

| 场景 | 端点 | 类型 | 期望 |
| --- | --- | --- | --- |
| sqli-login | `/login`（POST username） | SQL 注入（错误型） | signal |
| xss-reflect | `/reflect?name=` | 反射型 XSS（HTML 上下文，会执行） | signal |
| ssti-name | `/ssti?name=` | SSTI（`{{7*7}}` → 49） | signal |
| cmdi-ping | `/ping?ip=` | 命令注入 | signal |
| lfi-file | `/file?path=` | 目录遍历 / 任意文件读取 | signal |
| ssrf-fetch | `/fetch?url=` | SSRF | signal |
| idor-order | `/api/order?order_id=` | 越权读取他人订单（含手机号/地址） | signal |
| unauth-users | `/api/users` | 未授权访问（返回 PII） | signal |
| reflect-csp | `/reflect-csp?name=` | 回显但被 CSP 拦住 | reflection_only |
| reflect-dom | `/reflect-dom?name=` | 转义后进 `<textarea>`（不可执行） | none |
| decoy-static | `/static/app.js?x=` | 静态资源，参数无效 | none |
| decoy-root | `/?q=` | 首页忽略参数 | none |

## 4. 本机实测（2026-10-03，靶场在 WSL `127.0.0.1:5000`）

**引擎层**（`--tier engine`，12 场景，1.2 秒，零额度）：

```
检出率 100.0%（8/8）｜误报率 0.0%（0/3）｜仅反射 1｜无结论 0
```

**Agent 层 / 脚本 LLM**（`--tier agent --llm scripted`，3.4 秒，零额度）：

```
检出率 12.5%（1/8）｜误报率 0.0%（0/4）｜仅反射 0｜无结论 0
```

> 脚本策略是**固定剧本**（爬首页 → fuzz → compare → 记录），它只按自己的路线走，
> 所以 Agent 层这个数字衡量的是"管道跑通且不撒谎"，**不是**"工具找不出这些漏洞"。
>
> 这个 12.5% 是**口径收紧之后**的数字。同样的运行，如果覆盖记录的判据只要求
> "端点对得上 + `status=reported`"，检出率会虚高到 **37.5%**：脚本模型给 `/ssti`、`/file`
> 都写了 `reported`，而 detail 是同一句"sqli 注入（脚本 LLM 确认）"——
> 端点说模板注入、结论说 SQL 注入，一条自相矛盾的记录被算成了命中。
> 所以判据与 finding 一致：**端点路径 + 类型关键词**（`coverage_mentions`，
> 类型只看 detail——target 里的路径本身就常含类型名）。
> 回归：`tests/test_eval_scenarios.py::CoverageScoringTests::test_wrong_vuln_type_on_the_right_endpoint_does_not_count`。

**Agent 层 / 真实模型**（`--llm live --allow-live`，`deepseek/deepseek-flash`，
`--max-tasks 4 --task-steps 8`，费用上限 ¥1.00，2026-10-03 用户授权后跑了两轮）：

| 轮次 | 检出率 | 误报率 | 漏报场景 | 耗时 | token | 估算费用 |
| --- | --- | --- | --- | --- | --- | --- |
| #1（**回归复核型**，见 §4.2） | 75.0%（6/8） | 0.0%（0/4） | idor-order、unauth-users | 351.8s | 1,110,775 | ¥0.4158 |
| #2（隔离记忆后，全新审计） | 75.0%（6/8） | 0.0%（0/4） | xss-reflect、idor-order | 407.2s | 1,116,627 | ¥0.4357 |

两轮的共性：**注入类六项（SQLi / XSS / SSTI / 命令注入 / 文件读取 / SSRF）稳定命中**，
四个"应当安静"的场景**一次都没有误报**（`reflect-dom`、`reflect-csp`、两个诱饵），
授权类**不稳定**（`/api/order` 越权两轮都漏，`/api/users` 一轮中一轮漏）。

### 4.1 live 评测暴露的产品缺口（**未修，供决策**）

跑完两轮后查运行产物（只读，不再花额度），两个漏报都不是"模型没看见"：

1. **`xss-reflect` 漏报是记录问题，不是发现问题**（第 2 轮）：
   攻面里 `/reflect` 的 xss 尝试**已记录 3 条 `signal`**（"payload 原样回显（未转义）"），
   但模型写的覆盖记录是 `no_issue_found`，而它的 detail 里恰恰写着
   "`<script>alert(1)</script>` 与 `<img src=x onerror=alert(1)>` 均原样落进响应体"——
   **一条自相矛盾的记录**：结论说没问题，依据说有问题。
   评审口径下这属于"没测 ≠ 安全"的边界：字符串层反射应当记成**候选**
   （注明"未用浏览器验证可执行性"），而不是中性结论。
2. **`idor-order` 漏报是任务没跑完且没留痕**（两轮都漏）：
   越权任务（`/api/order`）以 `closing_no_finish` 结束——步数用尽且没写结论，
   攻面里既没有 `/api/order` 的 attempt，也没有 `not_tested` 覆盖记录，
   于是覆盖率闸门和报告都看不到这块盲区。

这两条都可以修（都不是"模型能力不够"），但没有动手——它们超出了"跑一次评测"的范围，
等你决定优先级。修法方向：① 覆盖记录与攻面信号一致性校验（有 signal 却写
`no_issue_found` 时拒绝或降级为候选）；② 子任务超步数时把"分配过但没测"的端点
自动写成 `not_tested`。

### 4.2 记忆没隔离：第 1 轮为什么不能当能力数字用（已修）

第 1 轮跑完发现它的计划里写着"回归复核历史漏洞"——因为 `HostMemory` 读的是
**用户真实的 `~/.hexhound`**，而那个靶场我们之前扫过，于是模型一上来就按
"复核已知漏洞"的路线走：诊断显示 auth 子代理**确实找到了** `/api/order` 越权与
`/api/users` 未授权（任务总结里有证据编号），但走"复核"路径没重新记录，
评分口径里就不算检出。

这是**评测工具的缺陷，不是产品缺陷**：评测必须每次从零开始，否则分数取决于
这台机器之前跑过什么、跨机器不可比。修法（已提交）：每次评测**把 `HEXHOUND_HOME`
指到 `.tmp/evals/<ts>/home`**（`tools/eval_scenarios.py::isolate_run_memory`），
配套 4 条隔离用例在 `tests/test_eval_scenarios.py::MemoryIsolationTests`——
其中最关键的一条按评测里的真实调用方式 `HostMemory(host)`（不传 home）断言
"新一轮读不到上一轮的记忆"，而不是只检查环境变量字符串。

**要说清楚的是：修完之后两轮都是 6/8，分数没变。** 修的是"这个数字可信不可信"，
不是"把分数刷上去"——第 1 轮的 75% 恰好与第 2 轮相同，纯属巧合。

同一轮里还顺带改了判分的另一处：覆盖记录写了 `reported` 也算检出
（`coverage_mentions`，端点 + 类型双重匹配，不从自由文本猜），
用于将来真正"回归复核型"的运行。**它没有改变这两轮的任何一条结论**：
离线用新口径复核两轮的产物（不花额度），6 条命中全部来自 findings/candidates，
没有一条是靠覆盖记录记上的。

## 5. 第一次跑就抓到一个真误报（已修）

`reflect-dom` 场景一开始被判成**误报**。查下去是判定规则的问题：

* 靶场把 payload HTML 转义后放进 `<textarea>`；
* payload `javascript:alert(1)` 里**没有任何 HTML 元字符**，转义后依旧"原样可见"；
* 旧规则是"payload 出现在响应里 ⇒ 未转义回显 ⇒ 疑似反射型 XSS"，
  于是把一个必然无害的回显报成了漏洞。

修法（`tools._fuzz_signal` 的 `xss` 分支）：**回显 ≠ 注入**——判据必须是
"payload 含能破出文本上下文的元字符（`<` / `>`）且原样出现"。
回归测试：`tests/test_tools_gates.py::XssSignalRuleTests`（三条：无元字符不算、
未转义算、被转义不算）。

这正是这个评测存在的意义：引擎层从"误报率 33%"变成"误报率 0%"，
而在此之前**没有任何用例**覆盖这一类回显。

## 6. 怎么扩展

* 加场景：往 `evals/scenarios.json` 的 `scenarios` 里加一条（`id` 唯一、
  `expected` 三选一、`signal` 场景必须有 `ground_truth`）；场景文件本身有校验用例
  （`tests/test_eval_scenarios.py::ScenarioFileTests`）。
* 加类型关键词：`tools/eval_scenarios.py` 的 `TYPE_KEYWORDS`
  （Agent 层按"路径 + 类型关键词"匹配标准答案）。
* 想做**跨轮对比**：两次运行的 `results.json` 里 `metrics` 直接相比即可；
  产物默认落在 `.tmp/evals/<时间戳>/`（含 `report.md` 与 `results.json`）。
