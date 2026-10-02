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

**Agent 层 / 脚本 LLM**（`--tier agent --llm scripted`，5.0 秒，零额度）：

```
检出率 12.5%（1/8）｜误报率 0.0%（0/4）｜仅反射 0｜无结论 0
```

> 脚本策略是**固定剧本**（爬首页 → fuzz → compare → 记录），它只按自己的路线走，
> 所以 Agent 层这个数字衡量的是"管道跑通且不撒谎"，**不是**"工具找不出这些漏洞"。
> 真实能力数字要跑 `--llm live`（花额度，需显式 `--allow-live`）——那一步我没有
> 在未经确认的情况下替你跑。

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
