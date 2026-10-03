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
* **误报率** = 报了「该场景诱骗的那一类结论」的应当安静场景数 / 应当安静场景数（判据见 §4.7：占位 `ground_truth` 不能当关键词；同路径的另一类问题不算）。
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
| #3（两个缺口修复后，全新审计） | **87.5%（7/8）** | 0.0%（0/4） | idor-order | 411.0s | 1,256,688 | ¥0.4747 |
| #4（参数推测 + 越权任务后） | **87.5%（7/8）** | 0.0%（0/4） | idor-order | 388.8s | 1,155,944 | ¥0.4073 |
| #5（值发现 + 收尾补授后） | **87.5%（7/8）** | 0.0%（0/4） | unauth-users | 359.5s | 1,222,010 | ¥0.4096 |
| #6（越权任务按端点拆分后） | 75.0%（6/8） | 0.0%（0/4） | xss-reflect、lfi-file | 416.5s | 1,406,876 | ¥0.5409 |

四轮的共性：**注入类六项（SQLi / XSS / SSTI / 命令注入 / 文件读取 / SSRF）稳定命中**，
四个"应当安静"的场景**一次都没有误报**（`reflect-dom`、`reflect-csp`、两个诱饵）。

**第 3 轮说明了什么**：`xss-reflect` 变成命中（第 2 轮那条自相矛盾的覆盖记录被闸门挡住，
证据只能走 finding 那条路），`unauth-users` 连续两轮命中；
唯一剩下的漏报还是 `idor-order`，而且原因已经查清（§4.1 第 2 条）：
端点这次**被发现了**（`/api/order` 在攻面里，1 次枚举尝试），
但字典枚举**不知道参数名**，没有人拿 `order_id` 去试。

**第 4 轮说明了什么**：参数推测那一条**生效了**——`/api/order` 登记了 25 次尝试，
其中 24 次都带着 `order_id`（sqli/cmd/ssti/path/xss/nosqli 各 4 次），
越权任务 `I1` 也真的跑完并交了总结。**但仍然漏报**，原因换了一层（详见 §4.4）：
模型拿 `order_id=1` 去试 → 404 `{"msg":"订单不存在"}` → **把整条端点记成 `ruled_out` 走了**。
参数名猜对了，错在**值**——靶场的订单是 1001/1002，而"不带参数请求会返回默认对象 1001"
这条线索它没利用（枚举那一次其实已经拿到过）。
一次 ¥0.41–0.47、约 6–7 分钟/轮，五轮合计约 ¥2.14。

**第 5 轮说明了什么（两个修法都被实测确认）**：

* **`idor-order` 命中**——`/api/order` 的覆盖行写着 `reported GET /api/order?order_id= 水平越权（IDOR/BOLA）任意读取他人订单`（HH-007）。
  轨迹（trace）正是任务目标要求的那四步：不带参数请求 → 读到默认对象 `order_id=1001/owner=alice` → `compare_responses` 换 1002 → 差异里出现 bob 的手机号与地址 → 记 finding；随后还顺手用 `compare_responses` 排除了候选参数 `id`，并用 `dismiss_signals` 说明「该信号来自枚举阶段的推测登记，实际无差异」——一致性闸门与值发现这两条修法**在同一条轨迹里都生效了**。
* **`closing_no_finish` 从 31% 掉到 0%**（第 4 轮 5/16，第 5 轮 0/17 全部 `done`）：这正是 HANDOVER §10.3 那条验收标准（< 3%）的实现。
* 这一轮的漏报换成了 `unauth-users`：`/api/users` 只有枚举那一次尝试，没有任何结论——原因见 §4.5。

**第 6 轮说明了什么**：

* `idor-order` **连续两轮命中**，`unauth-users` 也回来了（§4.5 的按端点拆分生效：`I1(/api/order)`、`I2(/api/user)`、`I3(/api/users)` 各自跑完并收尾）；
* 全部 19 个子任务 `done`，`closing_no_finish` 连续两轮为 0；
* 这一轮的漏报又换成了 `xss-reflect` 与 `lfi-file`——**两者的信号都在攻面里躺着**（`/reflect` 3 条 xss 信号、`/file` 1 条 path 信号：响应 196 → 1451 字节，内容差异就是那个敏感文件），却没有任何 finding/候选：一个被模型「排除」、一个连覆盖结论都没写。**证据被静默丢弃**，报告读起来像没漏——这是 §4.6 要修的。
* 一次 ¥0.41–0.54、约 6–7 分钟/轮，六轮合计约 ¥2.68（第 6 轮贵 33%，因为越权任务从 1 个变成 3 个）。

### 4.1 live 评测暴露的两个产品缺口（**已修**，见 §4.3）

跑完两轮后查运行产物（只读，不再花额度）。两个漏报都不是"模型没看见"，而是
**系统没让证据变成结论**：

1. **`xss-reflect` 漏报是记录问题，不是发现问题**（第 2 轮）：
   攻面里 `/reflect` 的 xss 尝试**已记录 3 条 `signal`**（"payload 原样回显（未转义）"），
   但模型写的覆盖记录是 `no_issue_found`，而它的 detail 里恰恰写着
   "`<script>alert(1)</script>` 与 `<img src=x onerror=alert(1)>` 均原样落进响应体"——
   **一条自相矛盾的记录**：结论说没问题，依据说有问题。
   评审口径下这属于"没测 ≠ 安全"的边界：字符串层反射应当记成**候选**
   （注明"未用浏览器验证可执行性"），而不是中性结论。
   → 第 3 轮已变成命中。
2. **`idor-order` 漏报：端点未被发现 / 参数名无人知道**（三轮都漏）：
   第 2 轮查 trace 的第一层根因：侦察子代理**显式挑了档位**
   `["core","leak","framework","admin","api"]`，**没带 business 档**；
   而 `/api/order` 正好在 business 档第 68/77 位（默认 `limit_per_tier=40`
   也截不到）。于是那一轮这个端点**连一次尝试都没有**：攻面里没有它，
   覆盖闸门与报告都看不见，"没测"被读成了"没漏"。
   修掉发现层之后，第 3 轮它**确实被发现了**（攻面里 1 个端点、1 次枚举尝试），
   但**仍然漏报**——第二层根因：字典枚举只知道路径、**不知道参数名**，
   于是"拿 order_id 去试越权"这件事只能靠模型自己想到。
   雪上加霜的是：越权任务以 `closing_no_finish` 收尾（它属于"已收尾"终态），
   收尾阶段也不会留下任何"这块没测"的痕迹。

**两条都在 §4.3 里修掉了**（含验收用的用例）；其中 ①（记录闸门）已被第 3 轮实测证实有效，
②的发现层也被第 3 轮证实（端点进了攻面），②的参数层修完**还没有重测**。

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

### 4.3 §4.1 两个缺口的修法（零额度可回归）

**① 覆盖记录不许自相矛盾**（记录层闸门，不是报告层补丁）：
`tools._record_coverage` 写 `no_issue_found`/`ruled_out` 前，先看这个对象上
攻面有没有 `signal` 记录；有就**拒绝写入**，并给出两条出路——
把信号记成候选/finding，或带上 `dismiss_signals="为什么这些信号不成立"` 重发。
排除理由会随覆盖行进报告（`[no_issue_found] /reflect — …（已复核信号后排除：…）`）。
两条边界同样重要：
从 target 里认不出端点时**不拦**（宁可漏拦，也不靠猜去否定模型的结论）；
**发现类命中不算信号**（`DISCOVERY_CATEGORIES`——`enumerate_common` 把"路径存在"
也记成 signal，把它当信号会让每个字典扫出来的端点都被要求解释一遍，闸门退化成噪音）。
用例：`tests/test_coverage_consistency.py`（14 条）。
**第 3 轮实测确认有效**：`xss-reflect` 从漏报变成命中。

**② 业务关键路径不许被"档位选择"漏掉**：
`knowledge.BUSINESS_CRITICAL_PATHS`（12 条只有凭 id 就能读的入口）**无论调用方选哪些档位
都会被探**（`include_critical=false` 可显式关掉；只发 GET，不改数据）。
为什么是"强制"而不是"改成默认档位"：档位是模型挑的，实测它就会挑漏掉整档；
把越权面交给模型的偏好等于让它决定"哪些入口不算数"。
用例：`tests/test_enumerate_hygiene.py::DefaultEnumerationTiersTests`（5 条；核心一条
模拟实测情形——模型点名 5 个档位而不含 business，`/api/order` 仍必须进攻面）。
**第 3 轮实测确认有效**：`/api/order` 进了攻面（1 个端点、1 次枚举尝试）。

**③ 没跑完的子任务要留下"哪些端点因此没结论"**：
`orchestrator._mark_assigned_but_untested`——只要任务**没有以 `done` 收尾**
（含 `closing_no_finish`：它在 `CLOSED_OUTCOMES` 里，原先什么都不留），
就把任务目标里点名、但既没尝试、也没结论的端点写成 `not_tested`（每任务最多 6 条，
数字段折叠后重复的只记一次，按原样写法写）。正常收尾的任务不补，
否则会把"模型有意跳过的低价值路径"写成一堆 `not_tested`，把真盲区淹掉。
用例：`tests/test_orchestrator.py::AssignedButUntestedCoverageTests`（8 条）。

**④ 端点没有参数信息时，参数名靠路径推测 + 确定性派越权任务**（第 3 轮暴露的最后一环）：
字典枚举知道路径、不知道参数，`/api/order` 登记后 `params=[]`，
"拿 order_id 去试"于是只能靠模型自己想到——三轮都没想到。现在：

* `knowledge.suggest_id_params()`：路径名词 → 候选标识参数名
  （`/api/order` → `order_id`/`id`，`/api/user` → `uid`/`id`/`user_id`，
   `/api/v1/invoice/detail` → `invoice_id`/`id`）；
  动作/页面路径（`/login`、`/api/search`、`/`）**返回空**——宁可不猜，
  也不给模型一个凭空捏造的参数名。
* 存进 `Endpoint.suggested_params`，**永不混进 `params`**（那是事实层）；
  提示词里显式标注：`推测参数[order_id,id](按路径名词推测，未验证)`。
* `orchestrator.idor_sweep_tasks()`：对"有推测参数、但那些参数从没被试过、
  也还没有 `reported` 结论"的端点，确定性派一个 auth 任务（`I1`），
  要求先确认哪个参数真的生效，再做 A/B 换 id 对比与匿名访问，
  **每个端点都必须有结论**（ruled_out/blocked 也要写）。
用例：`tests/test_idor_sweep.py`（18 条）。

**零额度验证效果**（脚本 LLM 档，跑一次约 4 秒）：
修 ② 之前 `/api/order` 在攻面里**端点 0 条、尝试 0 次**；修 ② 之后
**端点 1 条、尝试 1 次**（`.tmp/evals/verify-scripted3`）；
修 ④ 之后脚本档里能看到 `I1(auth)` 任务被派出去、目标里带着
`候选参数：order_id、id`（`.tmp/evals/verify-idor`）。
脚本档检出率仍是 12.5%——固定剧本不做身份对比，符合预期；
**④ 的效果要再花一次额度才能测出来**（第 3 轮 87.5%，唯一漏报正是 idor-order）。

**顺带修掉一个会炸整轮运行的真 bug**：`surface.normalize_path` 遇到
"人话"URL（`http://host：crawl 首页`，全角冒号进了 netloc）时 `urlparse` 直接抛
`ValueError`，`_finalise_coverage` 因此崩掉——一个取值函数不该能炸掉一轮审计。
现在砍掉非 ASCII 尾巴后重试，`looks_like_url` 同类输入一律判 False。
回归：`tests/test_coverage_consistency.py::TargetPathsTests`。

**曾经的"还没做"已经做了**：字典发现的端点没有参数信息 → 见 §4.3 第 ④ 条
（推测参数名 + 确定性越权任务），第 4 轮实测确认**参数名那半生效**、值那半还没过。

### 4.4 第 4 轮暴露的第三层根因：值不对被当成"参数不生效"（已修）

`I1`（越权任务）这次的执行轨迹（`live4` trace）：

1. step 1–2：匿名读 `/api/users` → 拿到全量 PII → **正确报成 HH-003 未授权访问**；
2. step 3–6：把 4 步花在 `/order/prepare`（404，错的端点）上试 `order_id`/`id`/`1001`；
3. step 7：`/api/order?order_id=1` → **404 `{"code":1,"msg":"订单不存在"}`**；
4. step 8：写覆盖 `ruled_out`：「试过 id=1、order_id=1001 两个候选参数，均返回 404」——
   **把"值不存在"读成了"参数不生效"**，整条越权面就此关闭；
5. step 9：交总结，任务 `done`。

而靶场 `order_id` 默认值是 `1001`（不带参数请求就返回 alice 的订单，**枚举那次已经拿到过**），
1002 是 bob 的订单——这正是标准答案要的越权。

**修法（§4.3 第 ④ 条的目标文本重写）**：把方法写成不可跳过的四步——
先**不带参数请求一次**、把响应里的真实标识值与属主**抄下来**、再用另一个**有效**标识
做 `compare_responses` 对比、最后测匿名访问；并明确写清
**404 的含义是「值不对」而不是「参数不生效」**，不许据此把整个端点记成 `ruled_out`。
用例：`tests/test_idor_sweep.py::test_objective_teaches_value_discovery_and_404_semantics`。

**同批修掉的另一个老问题（`closing_no_finish`）**：四轮 live 评测共 25 个未收尾子任务，
**100% 的最后一步都花在记录类动作上**（record_coverage 12 / leave_note 11 / record_finding 2），
而所有正常收尾的任务最后一步都是 `finish_task`——模型不是不肯交总结，
是把收尾回合全用在写东西上，写到没步数了。现在：步数用尽且最后一步是**记录类**动作时，
**补授一个只许 `finish_task` 的回合**（上限一次、且必须还有预算；该回合拒绝一切记录与探测动作，
所以不可能变成新一轮扫描）。最后一步若是在**试图探测**（被拒绝）则不补授——再给一轮也只是重复。
用例：`tests/test_context_compression.py::ClosingHandoffTests`（6 条）。

### 4.5 第 5 轮暴露的第四层问题：一个任务列多个端点 = 挑一个交差（已修）

第 5 轮里 `I1` 任务列了 3 个端点（`/api/order`、`/api/users`、`/api/admin/export`），而它把全部 9 步花在**第一个**上：确认越权、记 HH-007、排除 `id` 参数、写覆盖、交总结——**自认为完成就收尾了**，另外两个端点一步没测。`/api/users`（未授权访问场景）因此没有任何结论，成了这一轮唯一的漏报。

**修法**：`idor_sweep_tasks()` 改成**一个端点一个任务**（`I1`/`I2`/`I3`…，各 10 步预算），目标里写明「只做这一个端点，做完为止」。任务粒度=端点，模型就没有"挑一个交差"的余地；某个端点被预算挤掉时，覆盖表里也会留下它的 `not_tested`（第 ③ 条修法）。
零额度验证：脚本档一次运行里 `I1(/api/order)`、`I2(/api/user)`、`I3(/api/users)` 三个任务各自 `done`（`.tmp/evals/verify-perendpoint`）。
用例：`tests/test_idor_sweep.py::test_one_task_per_endpoint`（22 条）。
**它的效果还没有 live 实测**——那是第 6 轮的事。

### 4.6 第 6 轮暴露的第五层问题：信号没人接就消失了（已修）

上面两条漏报的信号都在攻面里：`/file` 的 path 信号带着「响应长度 196 → 1451；内容差异：=== 模拟敏感文件 ===」，`/reflect` 的 xss 信号写着「payload 原样回显（未转义）」——但两者都没有 finding/候选，覆盖表里一个写着 `not_tested`、另一个被 `no_issue_found`（带排除理由）盖住。**没有任何机制要求「有信号就必须有结论」。**

**修法（兜底安全网）**：`orchestrator._auto_register_signals()` 在收尾时做一次确定性收口——凡是**实测有信号、却既没有 finding/候选、也没有 `reported` 覆盖行**的端点，一律登记为**候选**（`status=candidate`、`confidence=unreviewed`、标题带 `[自动]`），并把模型给出的排除理由一并写进描述。要点：

* 只登记**候选**，不是漏洞——候选说的是「有待复核的证据」，不会制造假结论；
* 发现类尝试（`enumerate`）不算信号，否则每个扫出来的端点都会变成候选；
* 同一指纹只登记一条（`dedupe_key` 去重）；
* 评测口径同步诚实化：这种候选算「被发现」，但单独计数（`results.json` 里的 `auto_candidates`，报告行标注「兜底候选 N（模型未下结论）」，per-scenario 说明写「实测信号自动登记为候选（模型未下结论）」）——**平台没让证据消失 ≠ 模型判对了**。

**离线复核（零额度）**：把第 6 轮的 `surface.json` 读回来跑新逻辑，它恰好接住那两条漏报——`/file` → 任意文件读取候选（命中 `lfi-file`）、`/reflect` → 反射型XSS 候选（命中 `xss-reflect`）；另外还登记了一条「缺少安全响应头」的候选（`/` 上，与诱饵无关）。

**效果还没有 live 实测**（那是第 7 轮的事）：按这次离线复核，若第 6 轮就有这道安全网，那两条会作为候选出现——但**不算模型判对了**，报告里两处都会写明。

### 4.7 顺带修掉一个度量 bug：误报判定一直是空转的

静默场景的 `ground_truth` 写的是占位文案「（不是漏洞）」，而判误报用的是`requested_types(scenario)`——它把这段占位文案当成关键词去匹配 finding 文本。那句话永远不会出现在报告里，于是**误报判定从第一天起就没生效过**：在诱饵端点上明确报 SQLi/XSS 也不会被算成误报，agent 层的误报率恒等于 0，是个空转的数字。（引擎层的误报判定走的是记录结果，一直是有效的——第 5 节那个真误报就是它抓出来的。）

修法：静默场景按**它在诱骗哪一类错误结论**判（新增 `CATEGORY_KEYWORDS`，用场景已有的 `category`）：在 `decoy-root` 上报 SQL 注入才算误报；同一路径上的**另一类**问题（首页缺安全响应头、`/static/app.js` 里硬编码密钥）不算——那些诱饵测的是「参数被忽略」，不是「这个页面必须完美」。
判据字段也随之收窄：静默场景只看 `title`/`vuln_type`（结论*声称*的类型），不看描述——实测第 2 轮那条「JS 明文硬编码 SIGN_SECRET」就因为描述里带了「注入」被误判成误报，而那是另一类真问题。

**用修正后的口径离线复核全部六轮**（零额度）：误报 **0 条**（4 个静默场景 × 6 轮），而且判定不再是空转——`tests/test_eval_scenarios.py::QuietScenarioCriterionTests` 钉住了「真在诱饵上声称该类别成立 → 误报」与「同路径另一类问题 → 不算误报」两侧。

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
