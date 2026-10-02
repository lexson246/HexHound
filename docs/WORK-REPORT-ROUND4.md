# HexHound — 第四轮工作报告（外部代码评审 P1–P7）

> 面向下一个接手的人（或 AI）。**所有结论都来自本机实测**：每条先复现、再改、
> 再补回归；没测的一律写"未验证"。
>
> 起点：`633fc6e`（范围不限制主机那轮之后）
> 本轮提交：`a255248`（P1–P7 代码修复）→ `6d23f08`（四项验收回归 + 新增用例）
> 本轮目标（用户原话）：按外部评审给出的优先级修 5 个已确认问题，
> 讲清 `max_steps=100` 与 `task_steps=10` 的误解，并补
> 推理强度设置、实际请求配置记录、工具失败统计，以及四项验收回归
> （桌面真正下发扫描工具 / 身份切换后重测 / JSON 请求体 / 候选进入复核）。

---

## 0. 一句话状态

评审点名的 5 个问题全部修完并各有回归；`max_steps` 的疑问是**文档/标签**问题（已改提示）；
推理强度、请求配置记录、工具失败统计都已落地并可在报告里读到；
另外在自查中发现并修掉两个**真实隔离缺陷**（浏览器重定向绕过作用域、坏 NO_PROXY 让客户端起不来）。

| 项 | 状态 | 证据 |
| --- | --- | --- |
| P1 桌面没接上扫描环境 | 已修复 | 共享 `prepare_sandbox()` + 原因落盘 + 桌面链路回归 |
| P2 补扫任务与角色权限不一致 | 已修复（根因同 P1） | 提示词/工具集一致性用例 7 条 |
| P3 登录后链条（身份维度指纹） | 已修复 | 指纹含 method/身份/位置 + 端到端重测用例 |
| P4 JSON/PUT/PATCH 盲点 | 已修复 | 本地回环服务证明 JSON 体真的被注入 |
| P5 `sqlmap` 结论误判 | 已修复 | 正/负样本各 2 条 |
| P6 步数语义（`100` vs `10`） | 已澄清（标签 + 提示） | `runparams` hint + 界面说明 |
| P7 推理强度 / 请求配置 / 失败统计 | 已实现 | `.env` 选项 + trace `llm_config` + 报告行 |
| （自查）浏览器越界重定向被跟随 | 已修复 | 真实浏览器用例：目标服务器**零请求** |
| （自查）坏 `NO_PROXY` 让客户端构造失败 | 已修复 | 中毒环境下客户端可构造 |

测试：**952 passed, 10 skipped**（本轮起点 834 passed, 1 skipped）。
`ruff check src tests tools`：All checks passed。
跳过项都是"环境里没有 playwright 浏览器"或平台专属（DPAPI）用例。

---

## 1. P1：桌面跑起来"一直报未知工具"

### 复现（先确认，不猜）

翻历史运行记录：每一次都是

```json
"sandbox": {"enabled": false, "reason": "本次运行未启用容器沙箱"}
```

配合执行轨迹里的 `错误：未知工具 'sandbox_script' / 'port_scan' / 'web_fingerprint'`
——即那些运行的 `ctx.sandbox` **真的是 None**，模型照提示词去调真工具，拿到一句"未知工具"。
同时 `hexhound sandbox status` 在同一个环境里是**可用**的（WSL Ubuntu-24.04，9 个工具齐全），
说明"环境装好了"与"这次运行用上了"是两件事。

### 根因

CLI 与桌面各写了一份"准备执行环境"的逻辑，条件与文案不一致；而且
**失败原因被丢掉**：`sandbox_report(None)` 只有一句固定的"本次运行未启用容器沙箱"，
既没说是探测失败、还是没工具、还是镜像缺失，也没记 hint。于是事后只能从"未知工具"反推。

### 修复

- 新增唯一的 `sandbox.prepare_sandbox(allowed_hosts, ...) -> SandboxSetup`：
  探测 → 检查工具 → （桌面端）只允许本地镜像 → 返回 `sandbox / reason / hint / tools`。
  CLI 与桌面共用；`SandboxSetup.message()` 是两边共用的同一句话。
- 失败原因随运行落盘：`Orchestrator.describe_sandbox()` 把 reason/hint 写进
  `run.json` 与报告（单代理路径同样写入）。报告里现在是
  `真工具沙箱：**未启用/不可用**（<具体原因>）` + `恢复方式：hexhound sandbox install`。
- 桌面链路回归（`tests/test_gui_state.py`）：驱动真实 `gui._run_audit`，
  断言执行侧注册表**真的有** `sqlmap_scan` / `template_scan` / `sandbox_script`，
  并且注入角色（波次/补扫用的角色）也拿得到——不是只看"参数传了没有"。

---

## 2. P2：补扫任务与角色权限不一致

先用数据确认，而不是凭感觉改：历史里所有"未知工具"都是
`port_scan` / `web_fingerprint` / `sandbox_script`——**全部是依赖沙箱的工具**，
也就是 P1 的下游后果。补扫/波次任务的角色本来就是 `injection`（已核对
`coverage_sweep_tasks` / `param_sweep_tasks`），不存在角色配错。

真正的残留问题是**提示词与工具集不一致**：角色正文是静态文本
（"参数疑似注入时第一选择 sqlmap_scan"、"必须用 sandbox_script 主动打"），
而工具集是按环境**动态裁剪**的。两边不一致时，模型会反复调用不存在的工具。

修复：`prompts.adapt_prompt_to_tools(text, available, optional)`

- 以 `- ` 开头的条目若提到未下发的工具 → 整条（含折行续行）摘掉；
- 只提到缺失工具的**续行** → 删该行，不牵连整条；
- 没有脚本能力时，把"必须用 sandbox_script 主动打"改写为
  "本次没有脚本能力……做不到的必须在 summary 里写明未覆盖"；
- 末尾追加显式清单：`⚠️ 本次运行未下发的真工具：… 这些工具名不可调用`。

不变量（`tests/test_prompts.py`）：**角色提示词正文里不得出现本次未下发的工具名**
（含 `role × 有无沙箱 × 部分工具` 的组合）；反之沙箱可用时真工具必须仍然被广告到。

---

## 3. P3：登录之后的链条

三处一起修（本轮提交里已包含）：

1. **尝试指纹带维度**：`attempt_key = 端点+参数+类别+payload+方法+身份+参数位置`，
   身份用**请求头哈希**表示（同名账号换了会话也允许重测）。
2. **`blocked` 不算"测过"**：401/403 记成 `blocked`，任何身份都允许重测；
   只有 `signal` / `no_signal` 才拦住同身份重发。此前匿名拿到 401 会把
   登录后的重测一起吃掉。
3. **端到端**（`tests/test_request_bodies.py`）：本地回环服务上先匿名跑（被 401 阻断，
   结论写"未完成、不能据此排除漏洞"），再带会话跑一遍，断言第二次**真的发出去了**。

---

## 4. P4：JSON 请求体与 PUT/PATCH

`http_request` / `fuzz_params` / `compare_responses` 都支持 `json={...}`，
`location`（query/form/json）决定注入位置；PUT/PATCH 不再被按 GET 处理。

回归用**本地回环 HTTP 服务**（只监听 127.0.0.1）证明服务端**真的收到了**：

```
POST /api/login  content-type=application/json  body={"username": "'", ...}
PUT  /api/user/1 body 含 payload
PATCH /api/user/1 body 含 payload
```

---

## 5. P5：`sqlmap` 结论误判

原先判定是子串匹配，而 sqlmap 的**否定句**里同样含 `injectable`：
`all tested parameters do not appear to be injectable`、
`GET parameter 'id' does not seem to be injectable`——于是"没注入"被判成"注入成立"。

修复后要求**肯定句式**且同句不含否定词：

- 成立：`identified the following injection point(s)` / `is vulnerable` /
  `GET|POST|… parameter … is|appears to be … injectable`；
- 否定句四类样本全部落到"未确认注入"（`tests/test_tools_gates.py` 正负各 2 条）。

---

## 6. P6：`max_steps=100` 与 `task_steps=10` 的误解

这不是缺陷，是**标签/说明**问题：两者量的是不同的东西。

- `max_steps`：**单代理模式**的步数上限（`ReActAgent(max_steps=…)`）。
  多代理编排下它不参与子任务循环。
- `task_steps`：**每个子任务**的探测步数上限；波次/补扫/复核各任务各自计数，
  且各自另有**至多 2 轮受限收尾**（只允许 `record_finding/record_coverage/leave_note/finish_task`）。
  所以"每个子任务最多约 10 步探测 + 收尾"，多个子任务**累计**才是总步数。

已改：`runparams` 给两个字段加 hint（"仅单代理模式；多代理使用子任务最大步数" /
"每个子任务的探测上限；另有至多两轮受限收尾，各波次步数累计"），
界面在设置面板下方同步显示同一句话。

---

## 7. P7：可观测性（推理强度 / 实际请求配置 / 工具失败统计）

- **推理强度**：`LLM_REASONING_EFFORT`（留空=不发送参数、沿用服务端默认；
  可选 `low/high/max`），只对 DeepSeek 发送 `reasoning_effort` + `thinking:{type:enabled}`；
  非法值直接报错而不是静默忽略。界面 / `.env` / 命令行三处一致。
- **实际请求配置记录**：每次 LLM 调用前把
  `{provider, model, temperature, reasoning_effort(default=server_default)}`
  写进 trace 的 `llm_config` 事件——事后能回答"这次到底发了什么参数"。
- **工具失败统计**（本轮新增）：`ToolRegistry.tool_failure_stats()` 分四类计数：
  `unknown`（想调但没下发＝环境能力缺口）、`crashed`（我们自己的 bug）、
  `returned`（工具返回错误，多为 scope 拒绝）、`budget`（预算拒绝）。
  随 `AgentResult.tool_failures` 汇总进 `run.json` 与报告：
  `工具调用失败：**4 次**｜调用未下发的工具（sandbox_script×2、port_scan×1）｜…`
  这四类**必须分开**：对应的动作完全不同（补环境 / 修 bug / 核 scope / 调预算）。

---

## 8. 自查中发现并修掉的两个真实缺陷

### 8.1 浏览器会跟随越界重定向（作用域泄漏）

`tests/test_xssverify.py` 的两条用例最初是**红的**，追下去发现是真问题：

- `max_redirects=0` 的 `route.fetch()` 拿回 302 后由 `route.fulfill()` 交还浏览器，
  而**浏览器跟随重定向时不会再经过路由拦截器**（实测 route 回调只被调用一次）；
- 于是"重定向到白名单外主机"与"重定向到同一主机的另一个端口"两种情况，
  目标服务器都**真的收到了请求**；后者更严重：cookie 按主机（不按端口）发送，
  等于把登录态交给该主机的另一个端口。

修复：在响应里**摘掉 `Location`**（越界 / 同主机跨源 / 非 HTTP(S) 一律不跟随），
并把拦截原因写进观察记录（`已拦截重定向：…`）。现在两条用例都是绿的：
越界时目标服务器**零请求**，跨端口时另一个端口**零请求**。

### 8.2 坏掉的 `NO_PROXY` 让客户端根本起不来

本机环境里存在 `NO_PROXY=localhost,127.0.0.1,*.local,::1,[::1]`（代理工具写进去的）。
httpx 解析 `[::1]` 这个条目时抛 `InvalidURL: Invalid port: ':1]'`——
**请求还没发出去**，`httpx.Client()` 与 `OpenAI()` 就构造失败。用户观感是
"诊断和模型都起不来，报一个跟网络无关的错"。

修复：诊断客户端与 LLM 客户端**自己解析代理**（`_proxy_for_target`）：
本机目标与命中 `NO_PROXY` 的目标直连、其余走 `effective_proxy()`（含 Windows 系统代理），
不再让 httpx 解析整套环境变量。宽容解析 `NO_PROXY`（`[::1]`、`*.local`、`::1` 都能对上）。

---

## 9. 验证与如何复跑

```bash
# 全量测试（本机：952 passed, 10 skipped）
python -m pytest tests -q

# 四项验收回归（用户点名的那四条）
python -m pytest tests/test_gui_state.py tests/test_request_bodies.py \
                 tests/test_tools_gates.py -q

# 提示词与工具集一致性（P2 的不变量）
python -m pytest tests/test_prompts.py -q

# 浏览器隔离（需要 playwright + 系统 Edge/Chrome）
python -m pytest tests/test_xssverify.py -q

# 代码风格
python -m ruff check src tests tools
```

### 9.1 真工具链路端到端（零模型额度）

单元测试只能证明"参数传下去了"。为了回答"桌面/CLI 到底能不能用真工具"，
新增 `tools/verify_real_tool_chain.py`：用**真沙箱**（WSL Ubuntu-24.04）构建
注入角色的注册表，对 WSL 里的靶场跑真工具，逐项断言。
本机实测（靶场 `tools/start_lab_in_wsl.sh 5000`）：

```
[OK] prepare_sandbox 判定可用 — 真工具沙箱：WSL (Ubuntu-24.04)（可用工具：curl, ffuf,
     gobuster, nikto, nmap, nuclei, python3, sqlmap, whatweb）
[OK] 注入角色持有 sqlmap_scan / template_scan / sandbox_script / raw_command
[OK] sqlmap_scan 真的跑起来了 — [E2E-T1] sqlmap 结果（…，耗时 2s）
[OK] sandbox_script 执行成功 — [E2E-T2] 自定义脚本执行成功（耗时 0s，123 字符）
[OK] raw_command 未报未知工具 — [E2E-T3] 命令成功
[OK] 失败统计里没有'未下发的工具' — {'total': 0, 'tools_available': 23}
[OK] 提示词无缺失工具清单 / 提示词广告了 sqlmap_scan
端到端验证通过：真工具链路可用，无未知工具、无工具异常。
```

这正是用户报的那条故障的反面：**没有一次"未知工具"，工具全部真的执行了**。

打包验证：

```bash
python -m PyInstaller --noconfirm --clean HexHound-desktop.spec   # → hexhound.exe
python -m PyInstaller --noconfirm --clean HexHound.spec           # → dist\hexhound.exe
python tools/verify_desktop_exe.py                                # 21 项启动验收
```

本轮实测：桌面 `hexhound.exe` **21/21 通过**（含双击启动、WebView2 渲染、
端口仅回环、写接口 CSRF 403、关窗口后端口释放、设置不污染真实配置）；
CLI `dist\hexhound.exe sandbox status` 正确识别 WSL 与 9 个工具；
`dist\hexhound.exe doctor` 在本机"系统代理已开启 + NO_PROXY 含 `[::1]`"的真实环境下
链路可达（HTTP 401 未认证探测，不消耗额度）。

---

## 10. 仍未做 / 已知边界（如实列出）

- **GitHub 上的 CI 仍未真实跑过**：本地执行器（`tools/run_ci_locally.py`）7 个作业全绿，
  但需要一个真实仓库 + 凭据才能在 GitHub 上确认；`ubuntu/py3.11` 无法在
  Ubuntu 24.04 上复现（没有 python3.11 包）。
- **桌面窗口关闭即杀线程**：仍然不会写报告（已知边界，报告里会写明"不完整"，
  但窗口关闭是硬杀）。要留成果就用界面上的"停止"按钮。
- **推理强度对非 DeepSeek 提供商不发送**：其它提供商的等价参数各不相同，未做映射。
- **`settings.json` 里仍有一个明文 `api_key` 字段**（`provider_keys` 是 DPAPI 保护的）：
  已记录、未改动（改它要迁移，风险高于收益）。
- **浏览器验证依赖系统 Edge/Chrome**：没有 playwright 浏览器时会跳过相关用例，
  报告里对应结论强度只能到"反射"。
