# HexHound 优化方案（对标 Strix / PentAGI）

> 本文记录 v0.2 优化的设计依据：先把两个参考项目的可移植机制提炼出来，
> 再逐条映射到 HexHound 的具体改造。写作时用于自检，不作为对外交付物。

## 0. 现状盘点（改造前）

| 维度 | 现状 | 问题 |
| --- | --- | --- |
| 编排 | 单个手写 ReAct 循环，`MAX_STEPS` 平坦计数 | 100 步跑完只出 1 条 finding，长了模型就"绕圈"；没有任务分解，没有并行 |
| 攻击面 | 无共享模型；`crawl`/`discover_endpoints` 结果只存在于对话上下文 | 被上下文压缩吃掉后无法复用，重复爬同一个页面 |
| 发现门 | `fuzz_params` 报"疑似信号"，模型自行决定是否 `record_finding` | 无强制复核，无去重，同一条漏洞可重复入库 |
| 记忆 | 进程内 messages + `_summarize_steps` 截断 | 跨运行为零；截断丢信息 |
| 预算 | 只事后统计 token 与费用 | 无法预算上限，跑飞了才发现 |
| 产物 | 仅报告 Markdown/JSON + 提交包 | 没有可复现的 PoC 脚本 |

## 1. 参考项目提炼

### 1.1 Strix（usestrix/strix）

- **Manager + Workers 分层**：Manager 负责把目标拆成细粒度任务，Worker 是执行具体任务（端口扫描 / 目录爆破 / 响应头分析）的子代理；
  发现新服务时 Manager 会**动态派生新 worker**，主线程继续处理已有面。
- **图执行**：仓库自称"动态执行图 / 多代理协作"，同一目标上的侦察、利用、验证可并行推进。
- **沙箱**：Docker 原生，工具真实执行，环境可复现。
- **发现门（关键）**：**只有在沙箱里真正跑通 PoC、可复现的漏洞才上报**，明确对抗"理论型 CVE 噪音"。
- **产物**：`strix view` 本地面板查看 findings / severity / agent 活动 / 报告 / 历史；`-n` 非交互退出码供 CI 使用。
- **自述短板**：成本（数千次 prompt）、上下文窗口被工具输出淹没、仍可能幻觉。

### 1.2 PentAGI（vxcontrol/pentagi）

- **任务分层数据模型**：`flow → task → subtask → action`，产物在层级间传递，flow 可持久化与续跑。
- **角色分工**：orchestrator 接收目标 → researcher（信息收集 + 已知漏洞库查询）/ developer（攻击策略与代码）/
  executor（在隔离容器里执行命令）。
- **执行隔离**：按任务类型选容器镜像，安全任务默认 Kali 镜像（nmap / Metasploit / sqlmap 等 20+ 工具）。
- **记忆三层**：long-term vector storage（pgvector）+ working context + episodic history；可选 Neo4j/Graphiti 知识图谱存
  「工具—目标—漏洞—技术」的语义关系，跨会话复用。
- **链式摘要（chain summarization）**：选择性压缩较老的对话历史，长任务下压住 token 而不丢关键上下文。
- **工程化**：REST/GraphQL 接口、OpenTelemetry + Langfuse 可观测、每 agent 的模型与 token 计量。
- **自述短板**：部署重（Docker Compose、pgvector/Neo4j、2C4G 起步），单人 / 小项目难落地。

## 2. 移植决策（对 HexHound 的约束）

HexHound 的定位是**单进程、零外部服务、`pip install` 就能跑**的黑盒漏扫 Agent。
因此只移植"机制"，不移植"基建"：Docker 沙箱 → 复用现有主机白名单 + 只读约束；
pgvector/Neo4j → 本地 JSON 记忆文件；Langfuse → 进程内预算与用量面板。

| 参考机制 | 来源 | HexHound 落地 |
| --- | --- | --- |
| 显式攻击面模型（worker 共享的 working memory） | PentAGI 分层产物 + Strix 动态图 | `surface.py`：`AttackSurface` 记录 endpoints/params/forms/tech/findings/attempts，落盘 `~/.hexhound/runs/<host>/surface.json` |
| 分层任务分解 flow→task→subtask | PentAGI | `orchestrator.py`：一次 LLM 规划产出 bounded task 列表（objective/tool hint/step budget） |
| Manager + Workers 并行子代理 | Strix | `worker.py`：TaskWorker 受限工具集 + 独立 step/token 预算，线程池并行 |
| 角色分工（recon / injection / auth / verify） | 两者 | worker 的 `role` 决定工具白名单与提示词 |
| 只上报可复现漏洞 | Strix | 复核门：候选需 `http_request` 证据 + `record_finding(verified=true)`，否则进"待复核"区 |
| 漏洞去重 | 两者 | `dedupe.py`：按 (vuln_type, 归一化 URL 路径, 参数) 指纹合并，保留证据最强者 |
| 链式摘要 | PentAGI | `agent.py`：分层摘要（关键事件优先保留 + 老步骤压缩） |
| 预算上限 | PentAGI 计量 | `budget.py`：`MAX_COST` / `MAX_TOKENS` 越线即优雅收尾 |
| PoC 落盘 | Strix | findings 目录写 `poc/HH-00X.http`（curl 可复现命令 + 原文） |
| 非交互退出码 | Strix CI | CLI `--fail-on high` → 退出码 |

## 3. 交付物

1. 新增模块：`surface.py` / `dedupe.py` / `worker.py` / `orchestrator.py` / `budget.py` / `memory.py`
2. 改造：`tools.py`（surface 接入 + 候选/复核对 + 大量词表 + 并发安全）、`agent.py`（预算钩子 + 链式摘要）、
   `prompts.py`（worker/verifier 角色提示词）、`report.py`（复核状态、PoC、覆盖率）、`cli.py` / `gui.py` 接线
3. 靶场扩容：SSRF / 命令注入 / IDOR / 敏感文件 / 反射 XSS
4. 测试：去重、surface、budget、orchestrator 规划解析、报告渲染

---

## 4. v0.3 追加：从"能编排"到"结果可信"

v0.2 解决了"一个 100 步的平坦循环"，但把三个问题留在了原地：**测得不深、测得不全、说不清这次比上次变了什么**。
v0.3 针对这三点各加一层**确定性**机制（不依赖模型自觉），并对标对象做了一次复盘。

### 4.1 真工具执行（对标 Strix 的沙箱，但不引入 Docker 依赖）

| 项 | 落地 |
| --- | --- |
| 后端自动探测 | `sandbox.py`：`docker` → `podman` → `wsl` 依次探测，取第一个可用；`Runtime.describe()` 如实说明 |
| 工具集 | sqlmap / nmap / nuclei / ffuf / gobuster / nikto / whatweb / curl |
| 一键安装 | `hexhound sandbox install`（apt 优先 + 国内镜像回退）；`hexhound sandbox templates` 拉 nuclei 模板 |
| 证据 | 每次真工具执行记 `T` 编号证据（原始命令 + stdout 摘要），报告附录列出全部命令 |
| 工具门 | `_drop_unavailable_sandbox_tools`：探测不到的工具直接从 schema 摘掉，模型不会"调用一个不存在的工具" |

**网络命名空间是真问题**：WSL/容器与宿主不共享 loopback。做法是先做**作用域校验**（
`ALLOWED_HOSTS` 校验所有 URL/裸域名/裸 IPv4/IPv6），**再**把回环地址改写成宿主可达地址
（WSL 走默认网关、Docker 走 `host.docker.internal`），并在报告里把原始目标写成注释——
顺序反了就等于用改写后的地址绕过白名单。

**只读契约要写进代码**：模型曾自行给 sqlmap 加 `--risk=2 --level=3 --threads=8`（更激进＝更可能写库）。
现在 `_dedupe_sqlmap_flags` 把 `--risk/--level/--technique/--threads/--timeout` 锁定为首次出现值，
`FORBIDDEN_ARGS` 拦危险参数——**契约靠代码保证，不靠提示词**。

### 4.2 覆盖率闸门（对标 Strix 的 coverage 分离）

实测：一次运行登记 12 个端点，只碰了 3 个（25%），其余 9 个只是"列在报告里"——
**报告看着完整、实际漏一半，比不报更危险**（读者会以为"扫过了没问题"）。

- 判据是确定性的：`Surface.touched_endpoints()` = attempts ∪ findings ∪ coverage 三来源并集（URL 归一化）；
- 收尾前强制补扫波（wave 3）：对从未被触碰的端点自动派任务；
- 报告开头钉一行 `端点覆盖：X/Y（N%）` + 单独一节"⚠ 覆盖盲区"列出未测端点。

实测：25% → 55%（补扫生效）→ 100%（修掉"只看 attempts"的判据 bug 后重算）。

### 4.2b 参数级覆盖（端点级判据看不出来的那一类盲区）

端点级覆盖仍有漏洞：**端点被 GET 过一次就算"已覆盖"，但参数从未被试过**。实跑证据：
侦察子代理已经 `GET` 过 `/ping?ip=1` 与 `/ssti?name=x`，两个端点都算已覆盖，报告显示
100%，而命令注入与模板注入根本没测——报告"看起来完整"。

- 判据：`(端点, 参数)` 是否出现在 attempt 记录里（或已出过带 param 的 finding）。
- 参数宇宙有四个来源（缺一个就会静默放行）：`Endpoint.params` / URL query 参数名 / 表单参数 /
  attempt 里出现过的参数。**实测踩过第三个坑**：某次运行侦察只登记了 URL、没登记参数，
  `params_total=0`，报告里参数覆盖那一行整行消失——闸门看起来"通过"，其实什么都没查。
- 后果：强制**注入**补扫波（第二轮闸门），逐参数清单进报告盲区章节；
- 补扫最多两轮，且**只在盲区确实缩小时**才继续第二轮（否则就是收敛不了的烧钱循环）。

实测：参数覆盖 6/14（43%）先暴露盲区 → 注入补扫实测跑出 sqlmap 判定与逐参数
`record_coverage` 结论（`/api/order?id` ruled_out、`/api/search?q` 死路由、`/file?name` 无异常）。

**这一层的收益是可量化的**：加上参数级闸门后重跑同一靶场，同一份代码、
同一批端点，**首次**拿到两条此前 4 次运行都没发现的漏洞——
`/ping?ip=` 命令注入（critical，回显 `uid=0(root)`）与 `/ssti?name=` Jinja2 模板注入
（high，`{{7*7}}` → 49）。两条均已用独立命令复核确认。此前它们一直以
"端点已覆盖"的身份躺在报告里——这正是参数级判据存在的理由。

### 4.3 跨运行 diff（Strix 与 PentAGI 都没有的一层）

- 数据来源：`~/.hexhound/memory/<host>.json`（历次 findings）+ 本次结果 + 本次覆盖集合；
- 四分类：新增 / 仍存在 / 疑似已修复 / 状态未知；
- **核心不变量：没测到 ≠ 已修复**。只有"本次确实碰过该端点"才允许判"疑似已修复"；
- 反向闭环：历史 findings 作为**回归测试目标**注入规划提示词，否则没人会去重测旧端点，diff 永远空转；
- 记忆侧补齐 `param` + `dedupe_key`（旧文件没有 → 退化为"类别+路径"放宽匹配）。

**实测踩到的两个假修复（已修）**：

1. 记忆里存的是旧归类 `path_traversal`（标题含"任意文件读取"），本次归类 `ssrf` → 指纹对不上，
   而 /fetch 的 SSRF **仍然存在**，却被判成"疑似已修复"。这是安全报告里最严重的错误方向。
   修法：**该端点本次仍报出任何问题 → 一律降级为 unknown**，绝不因指纹不匹配就说修好了。
2. 归类规则顺序把 `path_traversal` 排在 `ssrf` 前 → 同一漏洞两次运行归成两类。修法：协议类
   （ssrf）优先于"它读到了什么文件"，并把顺序原因写进注释与测试。
3. **第三个假修复（v0.5 实测补上）**：模型有时用 `record_coverage(status="reported")` 记录
   "这里有问题"，却没有真的调 `record_finding`。diff 若只看 findings，上一轮的同位置结论就会被
   判成"疑似已修复"——而这次其实也看到了问题。修法：把 `reported` 覆盖的端点一并算作
   "本次仍报出问题"；同时把 `not_tested` / `blocked` 从"已覆盖"里剔除（那是"没测"的记录）。

   用真实运行数据做的 A/B（`tools/diff_ab_check.py`，60 条历史 vs 本次 7 条 finding、
   22 个覆盖端点、其中 14 个标 reported）：**旧判据 8 条"疑似已修复" → 新判据 0 条**，
   8 条全部改判 unknown，且都是"本次仍观察到未授权/IDOR"的位置。

### 4.4 v0.5：竞态 / 业务逻辑 / 加密实现（补上"接口形态"这一层）

**为什么之前打不出来**：不是模型不行，是接口形态不行。一次工具调用 = 一个请求，
而竞态**就是**"1 个请求"与"N 个同时请求"的差别；伪造令牌**就是**一个要自己算出来的值。
参考项目怎么做：Strix 有 `skills/vulnerabilities/{race_conditions,business_logic}.md` 两份手册
＋沙箱里跑任意 Python（且上报门强制要求 `poc_script_code`）；PentAGI 的 README 明确把
"agent 自写攻击脚本"列为未实现。

**落地三件**：

1. **`sandbox_script`**（`sandbox.py` + `tools.py`）：脚本 base64 后交给
   `python3 -c "<护栏 + exec>"`——一次性绕开 PowerShell→wsl.exe→bash 三层引号解析。
   作用域查两道：静态扫脚本正文（URL/裸 IP/引号内域名/禁止片段），运行时用前导代码接管
   `socket.getaddrinfo` 与 `socket.socket.connect`（拼接、base64、f-string 都绕不过）。
   护栏白名单是**映射后**的地址集合，所以脚本里照写 `127.0.0.1` 也能在独立 netns 里跑通。
   只对 injection/auth/verify 开放；沙箱无 python3 时工具直接摘掉。
2. **确定性派任务**（`orchestrator.special_class_tasks`）：首跑实测——侦察**确实**发现了
   `/wallet`、也在笔记里写了"用泄露的 jwt secret 伪造令牌"，但没有任何角色执行（0 条结论）。
   于是按攻面特征机械派发：状态变更语义 → 竞态任务；受保护接口 + 泄露源 → 伪造凭据任务。
3. **靶场补端点**（`vulnlab/app.py`）：`/coupon`＋`/wallet`（先查后写竞态）、
   `/api/reset_token`（一次性令牌并发消费）、`/api/jwt_login`＋`/api/admin/export`
   （HS256 弱密钥 + 校验接受 `alg=none`）、可预测会话令牌（`user:tok-user-demo`）；
   `tools/verify_lab_new_vulns.sh` 不经 HexHound 手工复核 5/5 通过。

**实测结果（同一靶场、同一模型）**：

- 加确定性任务前：0 条竞态/伪造类结论（侦察发现了线索但无人执行）；
- 加之后：**2 条 critical 新结论**——「泄露密钥自签 `role=admin` 令牌读管理导出」与
  「`alg=none` 无签名令牌绕过同一接口」，均经复核波确认，证据引用 `T` 编号脚本执行
  （报告附录把脚本渲染成 ```python 代码块，复核者看得到伪造代码本身）。

**随后暴露的四个真问题（全部已修，每条都有实测证据）**：

1. **脚本通道从第一天起就是坏的（静默失效）**：多行护栏经 `json.dumps` + bash 两层解析后，
   换行变成字面量 `\n`，而 `python3 -c` 不解释该转义 →
   `SyntaxError: unexpected character after line continuation character`；
   所有 `sandbox_script` 调用都在失败，却被当成"模型不会用脚本"。
   修法：启动器改成**单行**（只允许分号），护栏+脚本整体 base64 后写入沙箱临时文件再 exec，
   并加"启动器含换行就拒绝执行"的自检与单元测试。
2. **系统代理劫持全部目标流量**：httpx 默认 `trust_env=True`，经
   `urllib.request.getproxies()` 读到 **Windows 注册表里的系统代理**（本机
   `http://127.0.0.1:7892`，环境变量为空），于是每个请求都进代理并返回 **502**
   （实测：`trust_env=True → 502`、`trust_env=False → 200`）。表现是"目标全挂、
   端点状态全是 502"，子代理只能退回沙箱 curl，步数烧光。
   修法：目标流量默认直连，需要代理时显式设 `HEXHOUND_HTTP_PROXY`；
   LLM 调用不受影响（另一个客户端，仍尊重系统代理）。
3. **`/coupon` 这类业务入口从来没被发现过**：通用路径字典里没有任何"会改状态"的词汇，
   而竞态任务以攻面为输入派发——没有 `/coupon` 就没有 S1。修法两条：
   ① 新增 `business` 路径档（77 条）并默认开启；② **读取即登记**——把
   `discover_endpoints` 的提取逻辑抽成 `_harvest_endpoints`，让 `read_urls`
   （模型真的会调）读 JS/HTML 时顺手登记路径。实测从 `app.js` 一次取出
   `/coupon`、`/wallet`、`/api/reset_token`、`/api/jwt_login`、`/api/admin/export`。
4. **竞态任务自身的设计错误**：任务原先写"先串行 1 次、再并发 N 次"，而单次券会被
   **串行那一次消费掉**，随后并发全部被拒 → 得出"没有竞态"。那是测试设计错误，
   不是结论。修法：明确要求"串行基线与并发突发用**两份不同的输入**"，并用单元测试锁住措辞。

**四个修复之后的决定性实跑**：

```
[S1] 竞态任务被派出（攻面里终于有 /coupon）
[OK] [high] /coupon 券码兑换存在并发竞态（TOCTOU），同券可被重复兑换刷余额
     串行 dave：#1 成功 +100、#2 → 409；bob 用 threading.Barrier(N=10) 并发 → 10/10 成功，
     余额 0 → 1000；事后串行再打 → 409。证据 W5-T8 / W5-T9（附录含完整脚本与输出）
[OK] [critical] /actuator/env 泄露 JWT 签名密钥，可伪造任意身份（含 admin）令牌
```

即**竞态与加密实现两类各落一条**。同轮还修掉了证据编号体系不一致的问题：
附录此前渲染的是沙箱内部 `X1/X2…`，而 finding 引用的是 `W5-T8`，按编号查不到——
现在附录只渲染 finding 引用的 `T` 编号证据（并对脚本渲染成代码块）。

**仍然做不到的**：真实目标的竞态窗口需要合适时序与负载（常需 HTTP/2 单包技巧），窄窗口下
10 并发就是打不中；`alg=none` 真实系统少见；弱密钥伪造只在密钥真泄露时成立；业务逻辑仍依赖
模型理解**你的**领域不变量；"并发 N=10 无重复生效"是在该 N 下的负面结论，不等于安全。

### 4.5 与两个参考项目的差异（不吹，只列事实）

| 能力 | Strix | PentAGI | HexHound |
| --- | --- | --- | --- |
| 部署 | Docker | Docker Compose + pgvector/Neo4j | 单进程 / `pip install` |
| 真工具沙箱 | ✔（Docker 原生） | ✔（Kali 容器） | ✔（Docker/Podman/WSL 自动探测） |
| 自定义脚本通道 | ✔（容器内任意 Python） | 未实现（README 自述） | ✔（两层作用域约束 + 证据化） |
| 漏洞类别手册 | ✔（29 类 skill） | 无 | 三类 playbook 写进角色提示词 |
| 结构化漏洞模型 + 确定性去重 | 部分 | 无结构化 finding | ✔（指纹 + 合并计数） |
| 覆盖闸门（负面结论追踪） | ✔ | 无 | ✔（两层判据 + 强制补扫） |
| 跨运行 diff / 回归复核 | 无 | 无 | ✔（四分类 + 不把没测到当已修复） |
| 成本量级 | 数千次 prompt | 重 | 实测 ¥0.07–0.47 / 40–360s / 每轮 |

**仍然做不到的（明确写下来，避免过度承诺）**：业务逻辑漏洞仍依赖模型理解业务语义，窄窗口竞态
可能打不中，加密实现类只覆盖"密钥泄露 / 算法混淆 / 可预测令牌"这几种常见形态（padding oracle、
弱随机数、时序侧信道没有专门支持）；nuclei 模板 0 命中**不等于**目标安全；
XSS 只做到"字符串原样回显"级别，没有真实浏览器执行。
