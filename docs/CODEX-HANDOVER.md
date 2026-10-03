# HexHound 交接文档（给下一个 AI 编码代理 / Codex）

> 写于 2026-10-03，基线提交 **`439e02f`**（分支 `main`，origin = `lexson246/HexHound`，工作树干净）。
> 本文件是**自包含**的：只读这一份 + `docs/WORK-REPORT-ROUND4.md` 就能接手。
> 所有数字都来自本机实测；没测的一律写"未验证"。

---

## 0. 30 秒了解这个项目

HexHound 是一个 **LLM 驱动的黑盒 Web 安全审计 Agent**：编排者把目标拆成子任务，
按角色（recon / injection / auth / verify）派并发子代理，子代理通过工具（内置 HTTP 探测
+ **真工具沙箱**里的 sqlmap/nmap/nuclei/ffuf/自定义脚本）取证，只有带**真实请求证据**的
结论才算"已复核漏洞"，其余进候选池由复核角色处理。交付物是一份 Markdown 报告 +
运行产物目录（攻面/台账/轨迹/PoC）。

- 入口：`hexhound.exe`（Windows 桌面，pywebview + WebView2）、`hexhound`（CLI）、
  `python -m hexhound`。
- 代码：`src/hexhound/`（38 个模块，见 §3 地图）；测试 `tests/`（37 个文件、982 个用例）。
- 靶场：`vulnlab/app.py`（HANDOVER §9 记录为 13 类漏洞，含竞态/业务逻辑/JWT 伪造）。
- 配套文档：本文件（交接）、`docs/CODEX-PROMPT.md`（给 Codex 的启动提示词）、
  `docs/WORK-REPORT-ROUND4.md`（最近一轮修复的复现→根因→验证）、
  `docs/HANDOVER.md`（更早的英文交接，§10/§11 已用 ✅/🔶/❌ 标注状态）。

---

## 1. 现在是什么状态（已实测）

| 项 | 状态 | 证据 |
| --- | --- | --- |
| 测试 | **1062 passed + 71 subtests passed / 1 skipped** | `python -m pytest tests`（别再补 `-q`：`addopts` 已有 `-q`，双重 `-qq` 会让 pytest 连汇总行都不打印） |
| 代码风格 | 干净 | `python -m ruff check src tests tools` |
| 本地 CI 执行器 | **Windows 作业真跑；Linux 作业是 SKIP**（见下） | `python tools/run_ci_locally.py --all` |
| GitHub CI | **8/8 绿** | `python tools/ci_status.py --sha e6e2431` |
| 桌面 exe | 已重建并 21/21 启动验收 | `python tools/verify_desktop_exe.py` |
| 运行中关窗（打包 exe） | **10/10**（10 秒内退出 + 报告落盘） | `python tools/verify_desktop_close_inflight.py` |
| CLI exe | `dist\hexhound.exe`，`sandbox status` 识别 WSL + 9 工具 | 手工跑过 |
| 真工具链路（零额度） | 15/15 | `python tools/verify_real_tool_chain.py` |
| 真编排 + 真工具（零额度） | 15/15 + 软上限 4/4 | `python tools/verify_swarm_with_real_tools.py` |
| 关窗护栏（Flask 层） | 12/12 | `python tools/verify_close_guard.py` |
| **带标准答案的评测** | 引擎层 **检出 100% / 误报 0%**；真实模型档 **75–87.5% / 误报 0%**（六轮、约 ¥2.68：注入六项与越权读订单都命中过，漏报在场景间摆动 = 4 任务 × 8 步预算下的方差）。第 6 轮又暴露"实测信号没人接就消失"，已加**兜底候选**安全网（§6.19），效果待第 7 轮实测 | `python tools/eval_scenarios.py --tier engine`；真实模型档见 `docs/EVAL.md` §4（要 `--llm live --allow-live`，会花额度） |

> 跳过的那 1 个用例是"playwright 已安装"分支的环境性跳过，不是漏测。

> ⚠️ **本机跑不了 Linux 作业**：`tools/run_ci_locally.py` 会把 `runs-on: ubuntu-*`
> 的作业标成 **SKIP**（未执行）——**不要**把它当成通过。这一点被写进汇总额正是因为
> 踩过：早先跳过被印成 `PASS`，于是"没跑 Linux 作业"被当成"Linux 也通过了"，
> 直到 GitHub 上 ubuntu 红了才发现（那次是 `protection_available()` 的平台差异）。
> Linux 作业只有两个可信渠道：GitHub CI，或手工在 WSL 里跑。


最近六轮的提交（老 → 新）：

```
633fc6e  范围不限制主机（ALLOWED_HOSTS=*）与其披露
3bf2288  报告归档路径不一致
af63a11  死系统代理导致"只有挂 VPN 才行"
be63d4a  doctor/自动诊断 + .env 模型名修正
a255248  外部评审 P1–P7（桌面真工具链路、提示词/工具对齐、身份维度、JSON 体、sqlmap 结论、失败统计）
6d23f08  四项验收回归 + 提示词/请求体/失败统计用例
2d294a0  真工具链路端到端脚本
aac9a68  关窗不丢报告 + 中断不谎报完成 + CI 失败可公开诊断
277a414 / a5b4f42 / 75872f1 / 426d7ea / 439e02f
        文档同步、控制台解码统一、墙钟软上限、最后一步留给结论
```

---

## 2. 五条铁律（违反会造成不可逆损失）

1. **禁止 `git reset --hard` / `git clean -fd` / 批量 `git restore`。**工作树里可能有
   未提交的成果；要回退就 `git revert` 或手工改回去。
2. **永远不要打印或提交 `.env` / Cookie / Token / API key。**密钥在
   `~/.hexhound/settings.json`（`provider_keys` 走 DPAPI），CLI 读 `.env`。
   写代码时用 `sk-fake-*` 之类的假值做测试。
3. **不要对未授权目标扫描。** `ALLOWED_HOSTS` 是本项目的核心安全边界；
   用户当前设为 `*`（不限制），那是**他本人的授权声明**，不是让你放开手脚。
   自测只用 `127.0.0.1` 靶场。
4. **不要消耗真实模型额度做验证。**所有回归都能用
   `hexhound.mockllm.ScriptedLLM`（脚本 LLM）+ 本地靶场零成本跑完（见 §5）。
   真要真实运行，先问用户。
5. **不要削弱"没测 ≠ 安全"这条不变量。**未覆盖的端点/参数必须留成
   `not_tested` / `candidate`，报告里如实写"未完成"；任何为了让测试变绿而放宽
   门禁的改动都不接受（`tests/` 里有多处守着这条）。

补充的两条工程纪律（用户明确要求过）：

- **每完成一个可验证的阶段就提交一次**，提交信息里写清"验证了什么、用什么命令验证的"；
  如果那次提交包含别人未提交的改动，要在信息里说明。
- **报告要写实测数字**。"修好了"必须附命令与输出；没验证的一律写"未验证"。

---

## 3. 代码地图（改哪儿先看哪儿）

```
src/hexhound/
├── cli.py            CLI 入口（audit / doctor / sandbox / memory / history / providers）
├── gui.py            Flask + 单文件 SPA（HTML 字符串在模块顶部）、/api/run|stop|status|history…
├── desktop.py        pywebview 宿主：单实例互斥、随机端口、**关窗护栏**（见 §6.3）
├── orchestrator.py   分层编排：规划 → 波次 → 补扫 → 复核 → 汇总；波次时间闸门（硬+软）
├── agent.py          ReAct 子代理循环；步数预算、收尾回合、**最后一步留给结论**
├── tools.py          工具注册表 + 30+ 工具实现 + 角色工具边界 + 工具失败统计
├── sandbox.py        真工具执行层：WSL/Docker 探测（prepare_sandbox）、作用域校验、白名单
├── surface.py        共享攻面：端点/参数/指纹/尝试去重（attempt_key 带 方法/身份/位置）
├── budget.py         五维预算 + 原子占用（reserve_tool_call / reserve_llm_call）
├── supervisor.py     停滞/重复/失败循环监督
├── llm.py            OpenAI 兼容客户端：推理强度、代理解析、错误因果链
├── diagnose.py       doctor：DNS→TCP→TLS→HTTP 分步探测 + 代理/路由事实（不发凭据）
├── prompts.py        编排者与各角色提示词 + **可用性对齐**（adapt_prompt_to_tools）
├── report.py         报告渲染（含"真工具沙箱是否启用 / 工具失败统计 / 范围披露"）
├── history.py        历史运行（**只读磁盘**）+ 状态三判据（见 §6.4）
├── sanitize.py       转义序列清理 + 输出解码（decode_output / **decode_console_output**）
├── memory.py         RunArtifacts（运行产物）、HostMemory（跨运行记忆）、TaskLedger
├── trace.py          追加写的审计轨迹 + 离线重渲染快照
├── mockllm.py        脚本 LLM（零额度验证的核心）
├── browser.py / xssverify.py / screenshot.py   浏览器验证与截图（认证隔离见 §6.5）
└── apispec.py / replan.py / dedupe.py / diff.py / providers.py / config.py / runparams.py …
```

关键测试文件（改对应模块前先跑它们）：

| 模块 | 测试 |
| --- | --- |
| orchestrator / agent | `tests/test_orchestrator.py`、`tests/test_context_compression.py` |
| tools / surface | `tests/test_tools_gates.py`、`tests/test_surface.py`、`tests/test_request_bodies.py` |
| sandbox | `tests/test_sandbox.py`、`tests/test_sandbox_script.py` |
| gui / desktop | `tests/test_gui_state.py`、`tests/test_gui_frontend.py`、`tests/test_desktop_close_guard.py` |
| 提示词 | `tests/test_prompts.py` |
| 网络/代理/诊断 | `tests/test_diagnose.py`、`tests/test_llm.py` |
| 历史/报告 | `tests/test_history.py`、`tests/test_report*.py` |

---

## 4. 怎么把它跑起来

### 4.1 本机环境（当前这台机器已经配好）

- Windows + Python 3.12（系统解释器）+ `.tmp/venv-3.11`、`.tmp/venv-3.12`；
- **WSL `Ubuntu-24.04`**，里面装了 sqlmap/nmap/nuclei/ffuf/gobuster/nikto/whatweb/curl/python3；
  靶场副本在 `/opt/hexhound-lab/`；
- 桌面 exe：根目录 `hexhound.exe`（由 `dist\HexHound-desktop.exe` 复制而来）。

### 4.2 起靶场（真工具验证的前提）

```powershell
# 注意：仓库里的 .sh 是 CRLF，直接 bash 会报奇怪的错，先去掉 \r
wsl -d Ubuntu-24.04 -- bash -lc "tr -d '\r' < '/mnt/c/Users/LeXSon/Documents/ChatGPT/HexHound 2/tools/start_lab_in_wsl.sh' > /tmp/start_lab.sh; bash /tmp/start_lab.sh 5000"
# 验证：200
wsl -d Ubuntu-24.04 -- bash -lc "curl -s -o /dev/null -w '%{http_code}\n' --noproxy '*' http://127.0.0.1:5000/"
# 停止
wsl -d Ubuntu-24.04 -- bash -lc "pkill -f '/opt/hexhound-lab/app.py'"
```

靶场从 Windows 侧也能访问（`http://127.0.0.1:5000`，WSL2 端口转发），但**沙箱命令是在 WSL 里
执行的**，所以真工具打 `127.0.0.1:5000` 指的是 WSL 里的靶场——这就是为什么
`prepare_sandbox(..., map_loopback=False)` 用于本机靶场。

### 4.3 常用命令

```powershell
python -m pytest tests -q                     # 全量测试
python -m pytest tests -q -x -k "sandbox or gui"   # 局部
python -m ruff check src tests tools          # 风格
python tools/run_ci_locally.py --all          # 本地跑 .github/workflows/ci.yml（Linux 作业会 SKIP）
python tools/ci_status.py --sha <sha> --summaries  # 读 GitHub CI 结果 + 失败原因（无需 token）
python tools/run_ci_locally.py --list         # 看有哪些作业
```

**CI 失败怎么读**（两轮踩出来的）：Actions 的原始日志需要认证，公共仓库只有两条
公开通道，两个都已接上——

1. **check-run 注解**：`tools/ci_rerun_report.py` 在失败时既写
   `$GITHUB_STEP_SUMMARY`，也发一条 `::error title=…::<尾部输出>`；
   实测**只有注解读得到**（step summary 不进 `output.summary`）。
2. `tools/ci_status.py --summaries` 把注解与摘要都打出来。

失败时先跑它，别去猜。

测试有个**沙箱/临时目录**的坑：某些用例要求 `TEMP`/`TMP` 落在仓库内可写目录。稳妥起见用：

```powershell
$env:HEXHOUND_TEST_ROOT="$PWD\.tmp\pytest-root"; $env:TEMP="$PWD\.tmp\tmp"; $env:TMP="$PWD\.tmp\tmp"
python -m pytest tests -q
```

（不设也能跑——2026-10-03 全量测试就是这么过的——但设了更保险。）

### 4.4 打包（改完源码要重建，否则桌面端还是旧代码）

```powershell
python -m PyInstaller --noconfirm --clean HexHound-desktop.spec   # → dist\HexHound-desktop.exe
Copy-Item dist\HexHound-desktop.exe hexhound.exe -Force          # 桌面入口就是根目录这个
python tools/verify_desktop_exe.py                               # 21 项启动验收（会真开窗口）
python -m PyInstaller --noconfirm --clean HexHound.spec           # 可选：CLI → dist\hexhound.exe
```

**重建前先确认桌面程序没在运行**（`Get-Process hexhound`）。审计正在跑时不要强杀：
先看 `http://127.0.0.1:<port>/api/status` 的 `running`；要停就点界面"停止"（约 10 秒收尾）。

---

## 5. 零额度验证（改完东西**必须**跑这些）

真模型调用要花钱，用户明确不希望被无故消耗。下面四个脚本都用脚本 LLM + 本地靶场，
不需要 API key，也不产生流量到外部目标：

| 脚本 | 验证什么 | 期望 |
| --- | --- | --- |
| `tools/verify_real_tool_chain.py` | 注入角色的注册表真的能用真工具（sqlmap/脚本/命令） | 全 OK，失败统计无 `unknown`/`crashed` |
| `tools/verify_swarm_with_real_tools.py` | **真实编排**里真工具被执行 + 软上限生效 | 全 OK，run.json 沙箱已启用，`sqlmap` 出现在工具日志 |
| `tools/verify_close_guard.py` | 关窗护栏：中断后报告/运行记录/历史判定 | 12 项全 OK |
| `tools/eval_scenarios.py --tier engine` | **带标准答案的检出率/误报率**（12 场景，见 `docs/EVAL.md`） | 检出 100% / 误报 0%（本机基线） |
| `tools/verify_poc_selfcheck.py` | 生成的 PoC 能在 WSL 里自校验（需先有一份含 findings 的运行） | 按需 |

前三个都要求 §4.2 的靶场在跑，否则 `prepare_sandbox` 之后的真工具调用会全部连不上
（**这是最容易误判的一点**：靶场没起时 sqlmap 1 秒就返回，看起来像"跑过了"）。

---

## 6. 真实事故与它们的守卫（别把它们改回去）

> 每一条都是**复现过的**，并在 `tests/` 或 `tools/verify_*.py` 里有用例守着。
> 改相关代码前先读对应小节。

### 6.1 桌面"一直报未知工具"（P1）

**症状**：子代理反复调用 `port_scan` / `web_fingerprint` / `sandbox_script`，每次拿回
"未知工具"；`run.json` 里 `sandbox.reason` 永远是那句"本次运行未启用容器沙箱"。

**根因**：CLI 与桌面各写了一份沙箱准备逻辑，且失败原因被吞掉。

**守卫**：`sandbox.prepare_sandbox()` 是唯一实现（CLI/桌面共用），返回
`sandbox/reason/hint/tools`；`Orchestrator.describe_sandbox()` 把原因写进 run.json 与报告。
回归：`tests/test_gui_state.py::test_desktop_hands_real_tools_to_the_injection_role`。
**改沙箱准备逻辑时不要绕过这个函数**，也不要把 reason 换成固定文案。

### 6.2 提示词承诺了不存在的工具（P2）

**症状**：角色提示词写着"首选 sqlmap_scan""必须用 sandbox_script"，而沙箱不可用时
工具集里根本没有这些名字 → 模型白烧步数。

**守卫**：`prompts.adapt_prompt_to_tools(system, available, optional)` 按注册表**实际**
工具集摘条目、末尾显式列出"本次未下发的真工具"。
不变量测试：`tests/test_prompts.py`（正文不得出现未下发的工具名；可用的必须仍被广告）。

### 6.3 关桌面窗口丢掉整轮成果

**症状**：审计跑到一半直接关窗口 → 进程退出、daemon 线程被杀，**连部分报告都没有**；
而按界面"停止"却会正常写报告。

**守卫**：`desktop.install_close_guard()` 拦截**第一次**关窗 → 请求停止 → 等报告写完
（`HEXHOUND_CLOSE_GRACE`，默认 45 秒）→ 自己 `destroy()`；**第二次**不拦（不能让人关不掉）。
`main()` 的 finally 里再兜底一次。回归：`tests/test_desktop_close_guard.py` +
`tools/verify_close_guard.py`。

### 6.4 中断的运行被记成"已完成"

**症状**：用户按停止时编排器只是跳出波次循环、然后照常收尾 → `finish_reason="finish"`
且 `snapshot.json` 照样生成 → 历史里显示"已完成"，而报告正文写着"不完整"。

**守卫**：`Orchestrator._user_stopped()` 区分"用户停止"与"预算/闸门收尾"（前者
`finish_reason="cancelled"`）；`history._status_of()` 三条判据（报告中断标记 → 记录的
收尾原因 → 缺快照），`PARTIAL_FINISH_REASONS` 里任一都算"未完成"。
**新增终态记得同步这个集合**（`soft_timeout` 就是这么加进去的）。

### 6.5 浏览器把越界重定向也跟了（作用域泄漏）

**症状**：白名单外主机、以及"同主机另一个端口"都**真的收到了请求**；后者更糟——
cookie 按主机（不按端口）发送，等于把登录态交给别的端口。

**根因**：浏览器跟随重定向时**不会再经过路由拦截器**（实测 route 回调只被调用一次）。

**守卫**：`browser._redirect_target_allowed()` + 在响应里**摘掉 `Location`**
（越界 / 同主机跨源 / 非 HTTP(S) 一律不跟随），拦截原因写进观察记录。
回归：`tests/test_xssverify.py::RedirectPolicyTests` 与两个真实浏览器用例。

### 6.6 坏掉的 `NO_PROXY` 让客户端起不来 + 中文 Windows 的 GBK

**症状 A**：环境里 `NO_PROXY=...,[::1]`，httpx 解析该条目时抛
`InvalidURL: Invalid port: ':1]'`——**请求还没发出去**，`httpx.Client()` 与 `OpenAI()`
就构造失败，`doctor` 和所有模型调用一起挂。
**守卫**：`diagnose.effective_proxy()` + `llm._proxy_for_target()` 自己解析代理
（本机/`NO_PROXY` 命中则直连），不吃 httpx 的环境变量解析。

**症状 B**：`route` / `ipconfig` / `docker` / 无头 Edge 在中文 Windows 上输出 GBK，
`subprocess.run(..., text=True)` 按 UTF-8 解会在读取线程抛 `UnicodeDecodeError`，
输出被截断且只留一条 threading 警告。
**守卫**：`sanitize.decode_console_output()`（严格 UTF-8 → 系统代码页 → GBK → 兜底替换，
NUL 存在时交给 `decode_output` 择优）。**顺序不能反**：先按 cp936 试会把 UTF-8 中文
静默解成乱码，而且一个替换字符都不产生，判不出来。
**新写 `subprocess.run` 时**：能捕获字节就用 `decode_console_output`，否则**必须**写
`encoding=...`（`text=True` 单独用就是上面这个 bug）。

### 6.7 真工具网络的另外两条

- **目标流量默认直连**（`trust_env=False`）：系统代理会把整轮扫描打成 502。
  要代理就用显式配置；LLM 调用与目标流量是两套。
- **死代理自动绕开**：`llm._dead_proxy_detail()` 检测到"配了代理但端口连不上"时直连并
  在 `network_note` 里说明（事故现场：`ProxyEnable=1` + 死端口 → 7.3 秒后
  `APIConnectionError`、0 token；用户观感是"只有挂 VPN 才行"）。

### 6.8 关窗护栏在真机上"关不掉"（打包 exe 专项验收才抓到）

**症状**：Flask 层的关窗用例全绿，但打包 exe 里"运行中关窗"后进程永不退出，
日志停在"关窗护栏已挂上"。

**根因两条**（都在 pywebview 的线程模型上）：

1. 原设计"取消第一次关闭 → 收尾完由**工作线程** `window.destroy()`"不成立——
   窗口方法必须由 GUI 主线程调用，工作线程里调用既不生效也不报错（异常被吞）；
2. 在 `closing` 回调里调 `evaluate_js()` 会**自锁**——该回调同步跑在 UI 线程上
   （`Event(window, True)`），而 `evaluate_js` 又要等 UI 线程。

**守卫**：关窗**一律放行**，但放行前 `state.stop_current()`（置停止标志 +
中断正在跑的沙箱命令），报告由 `main()` 的 finally 等出来（`HEXHOUND_CLOSE_GRACE`）。
回调里**不碰页面**。回归：`tests/test_desktop_close_guard.py`（单元）+
`tools/verify_desktop_close_inflight.py`（真机 10 项）。

**排查工具**：`HEXHOUND_DESKTOP_LOG=<file>` 会把启动/关闭里程碑写文件——
windowed 构建没有控制台，这是"双击没反应"唯一的线索。

### 6.9 限流会被误判成"已修复"（外部评审第 1 条）

**误判链**：429 → 记成 `no_signal` → 同组合被去重跳过 → 端点算"本次覆盖过"
→ 跨运行 diff 判 **fixed**。

**守卫**：`tools._is_throttled()`（429/503，或 4xx/5xx + `Retry-After`）在
fuzz / compare / auth / creds / headers 全按"受阻、未完成"处理；
`Surface.mark_throttled()` 让被限流的端点**不算覆盖**（diff 只能给 unknown）；
报告披露"目标限流 N 次"。回归：`tests/test_rate_limit.py`（8 条）。

### 6.10 密钥保存会清空别的提供商密钥（外部评审第 2 条）

**根因**：`/api/provider_key` 直接 `json.loads(settings["provider_keys"])`，
而该字段落盘是 DPAPI **密文** → 解析失败退化成 `{}` → 只写新 provider。

**守卫**：唯一的服务端入口 `gui._store_provider_key()`（先解密合并；
解不开密文**拒绝保存**；空串=删除）；`_save_settings(..., provider_keys=...)`
是服务端独占参数，**客户端 payload 里的 `provider_keys` 一律忽略**；
页面不再回填明文密钥（只显示掩码 + "留空=不修改"）。
回归：`tests/test_provider_key_store.py`（9 条，按平台分别断言）。

### 6.11 运行级状态与子任务状态不一致（外部评审第 3 条）

**症状**：注入子任务 `failed`，整轮记 `finish`，历史显示"已完成"。
**守卫**：`_aggregate()` 按"失败子任务 > 模型端点故障 > 预算/软上限/用户停止 > finish"
定运行级 `finish_reason`，并在总结里点名。回归：
`tests/test_orchestrator.py::RunStatusMatchesTaskStatusTests`（5 条）。

### 6.12 评测跑成了"回归复核"，分数取决于这台机器以前跑过什么

**症状**：第一次真实模型评测（`--llm live`）的计划里写着"回归复核历史漏洞"，
子代理找了、也写在总结里了，但没重新 `record_finding`，评分算成两条漏报。
**根因**：`HostMemory` 解析 `data_home()` → 用户真实的 `~/.hexhound`，而这个靶场之前扫过。
**守卫**：`tools/eval_scenarios.py::isolate_run_memory()` 把 `HEXHOUND_HOME` 指到
`.tmp/evals/<ts>/home`；`tests/test_eval_scenarios.py::MemoryIsolationTests`（4 条）——
关键是按评测里的真实调用方式 `HostMemory(host)`（不传 home）断言新一轮读不到上一轮记忆，
而不是只检查环境变量字符串。评测结论必须与开发机的历史无关。

**顺带修正的口径**：回归复核型运行会把"仍成立"写进覆盖记录（`status=reported`）而不重复
`record_finding`，所以判分也认这种**结构化**命中（`coverage_mentions`：只认
`status=reported` + target 命中端点路径，不从自由文本里猜）。

### 6.13 覆盖记录把实测信号洗成"无问题"（live 评测发现）

**症状**：`/reflect` 上攻面已记录 3 条 `signal`（"payload 原样回显（未转义）"），
覆盖记录却写 `no_issue_found`，而它的 detail 里正是那个未转义回显——
报告同时说"测到反射"和"测过没问题"，读者只会看到后者。
**守卫**：`tools._record_coverage` 在写 `no_issue_found`/`ruled_out` 前查该对象上的 signal，
有就**拒绝**并给两条出路（记成候选/finding，或带 `dismiss_signals` 说明为什么不成立）；
理由写进覆盖行（`（已复核信号后排除：…）`）。target 认不出端点时不拦——
宁可漏拦，不靠猜否定结论。回归：`tests/test_coverage_consistency.py`（13 条）。

**同一批还修了一个会炸整轮运行的真 bug**：`surface.normalize_path()` 遇到人话 URL
（`http://host：crawl 首页`，全角冒号进了 netloc）时 `urlparse` 抛 `ValueError`，
直接把 `_finalise_coverage` 干崩。现在砍掉非 ASCII 尾巴重试，`looks_like_url` 判 False。

### 6.14 档位由模型挑，于是整个越权面被漏掉（live 评测发现）

**症状**：两轮真实模型评测都漏了 `/api/order` 越权。查 trace：侦察子代理显式挑了
`["core","leak","framework","admin","api"]`，**没带 business 档**；
`/api/order` 在 business 档第 68/77 位（默认 `limit_per_tier=40` 也截不到）——
端点**根本没被发现**，攻面里是空的，报告读起来像"这个面没漏洞"。
**守卫**：`knowledge.BUSINESS_CRITICAL_PATHS`（12 条只读、凭 id 就能读的入口）
**无论调用方选哪些档位都会探**，非 ASCII 说明写在工具描述里；
`include_critical=false` 才关。零额度验证：脚本档一次运行里
`/api/order` 从 0 端点/0 尝试 → 1/1。回归：
`tests/test_enumerate_hygiene.py::DefaultEnumerationTiersTests`（5 条）。

**配套**：没以 `done` 收尾的任务（含算"已收尾"的 `closing_no_finish`），
把它点名却没碰过的端点写成 `not_tested`（`_mark_assigned_but_untested`，每任务 ≤6 条）。
回归：`tests/test_orchestrator.py::AssignedButUntestedCoverageTests`（8 条）。

### 6.15 字典发现端点时"参数名靠猜"，于是越权面整块漏掉（live 评测发现）

**症状**：第 3 轮 live 评测 87.5%（7/8），唯一漏报 `idor-order`。
查产物：`/api/order` **已经进攻面**（发现层上一批修好了），但 `params=[]`——
字典只知道路径。于是"拿 `order_id` 去试"只能靠模型自己想到，三轮都没想到。
**守卫**：`knowledge.suggest_id_params()`（路径名词 → 候选标识参数名）+
`Endpoint.suggested_params`（**推测值单独一栏，永不混进 `params`**）+
`orchestrator.idor_sweep_tasks()`（确定性派 `I1(auth)` 任务）。
界面与提示词必须能分辨：`参数[...]` 是探到的，`推测参数[...](按路径名词推测，未验证)` 是猜的。
回归：`tests/test_idor_sweep.py`（19 条）。

**顺带把闸门的边界磨精确**：`enumerate_common` 会把"路径存在（200/403）"也记成
`outcome=signal`，而那不是漏洞信号——`surface.DISCOVERY_CATEGORIES` 把这些发现类尝试
排除在"实测信号"之外，否则每个扫出来的端点写"没问题"都会被拒，闸门退化成噪音。

- **目标流量默认直连**（`trust_env=False`）：系统代理会把整轮扫描打成 502。
  要代理就用显式配置；LLM 调用与目标流量是两套。
- **死代理自动绕开**：`llm._dead_proxy_detail()` 检测到"配了代理但端口连不上"时直连并
  在 `network_note` 里说明（事故现场：`ProxyEnable=1` + 死端口 → 7.3 秒后
  `APIConnectionError`、0 token；用户观感是"只有挂 VPN 才行"）。

### 6.16 值不存在被当成"参数不生效"，整条越权面被关掉（live 评测发现）

**症状**：第 4 轮 live 评测 87.5%，唯一漏报还是 `idor-order`。查 `I1` 的 trace：
匿名读 `/api/users` 拿到了 PII（正确报了 HH-003），接着 4 步浪费在错的端点上，
然后 `/api/order?order_id=1` → 404 `{"code":1,"msg":"订单不存在"}`，
于是写覆盖 `ruled_out`：「试过 id=1、order_id=1001 两个候选参数，均返回 404」——
**把"值不存在"读成了"参数不生效"**。靶场的订单是 1001/1002，
而且**不带参数请求**就返回默认订单 1001（枚举那次已经拿到过）。
**守卫**：`idor_sweep_tasks` 的目标文本重写成不可跳过的四步——
先不带参数请求一次 → 把响应里的真实标识值与属主抄下来 → 用另一个**有效**标识做
`compare_responses` 对比 → 再测匿名访问；并写明 404 是「值不对」不是「参数不生效」，
不许据此把端点记成 ruled_out。回归：
`tests/test_idor_sweep.py::test_objective_teaches_value_discovery_and_404_semantics`。

### 6.17 写完记录就没步数交总结（`closing_no_finish` 31–43%）

**症状**：四轮 live 评测 65 个子任务里 25 个落在 `closing_no_finish`（系统代写总结）。
**根因（25/25 的取证）**：**每个未收尾任务的最后一步都是记录类动作**
（record_coverage 12 / leave_note 11 / record_finding 2），
而所有正常收尾的任务最后一步都是 `finish_task`——模型不是不肯交总结，
是把收尾回合全花在写东西上，写到没步数了。
**守卫**：`agent._ClosingState.needs_handoff`——步数用尽且最后一步是**记录类**动作时，
**补授一个只许 `finish_task` 的回合**（上限一次、必须还有预算；该回合拒绝记录与探测动作，
所以不可能变成新一轮扫描）。最后一步若是在**试图探测**（被拒绝）则不补授。
回归：`tests/test_context_compression.py::ClosingHandoffTests`（6 条）。

---

### 6.18 一个任务列多个端点 = 模型挑一个交差（live 评测发现）

**症状**：第 5 轮的 `I1` 列了 3 个端点，模型把全部 9 步花在第一个（`/api/order`）上——确认越权、记 HH-007、排除另一个参数、写覆盖、交总结——然后**自认为完成就收尾**，另外两个端点一步没测；`/api/users`（未授权访问场景）因此成了那一轮唯一的漏报。
**守卫**：`idor_sweep_tasks()` 改成**一个端点一个任务**（`I1`/`I2`/`I3`…，各 10 步），目标里写明「只做这一个端点，做完为止」。零额度验证：脚本档里三个任务各自 `done`。
回归：`tests/test_idor_sweep.py::test_one_task_per_endpoint`。

### 6.19 实测信号没人接就消失了（live 评测发现）

**症状**：第 6 轮漏了 `xss-reflect` 与 `lfi-file`，而两者的信号都在攻面里：
`/reflect` 3 条 xss 信号（payload 原样回显未转义）、`/file` 1 条 path 信号（响应 196 → 1451 字节，内容差异就是那个敏感文件）。一个被模型「排除」、一个连覆盖结论都没写——**报告读起来像这两个面没漏**。
**守卫**：`orchestrator._auto_register_signals()`——收尾时凡是"有非发现类信号、却没有 finding/候选/`reported` 覆盖行"的端点，一律登记为**候选**（`[自动]` 前缀、`confidence=unreviewed`、附上模型的排除理由）。只登记候选（不是漏洞），`enumerate` 的发现类命中不算信号，同指纹去重。
评测口径同步：这种候选算"被发现"但**单独计数**（`auto_candidates` 字段 + 报告里的"兜底候选 N（模型未下结论）"）——平台没让证据消失 ≠ 模型判对了。
离线复核：第 6 轮产物跑新逻辑正好接住那两条漏报。回归：`tests/test_auto_candidates.py`。

### 6.20 误报判定一直是空转的（度量 bug，已修）

**症状**：agent 层的"误报率 0%"从第一天起就是空转的数字——静默场景的 `ground_truth` 是占位文案「（不是漏洞）」，被 `requested_types` 当成关键词去匹配 finding 文本，而那句话永远不会出现在报告里。**在诱饵端点上明确报 SQLi/XSS 也不会被算误报。**（引擎层的误报判定走记录结果，一直有效——`reflect-dom` 那个真误报就是它抓的。）
**守卫**：静默场景按它在诱骗的 `category` 判（`CATEGORY_KEYWORDS`），且只看 `title`/`vuln_type`（结论声称的类型），不看描述——第 2 轮那条"JS 硬编码 SIGN_SECRET"曾因描述里带「注入」被误判成误报。
修正后离线复核六轮：误报 **0 条**，且判定非空转。回归：`tests/test_eval_scenarios.py::QuietScenarioCriterionTests`。

## 7. 还没做的（按优先级，全部有验收标准）

> 与 `docs/WORK-REPORT-ROUND4.md` §13 一致；HANDOVER.md §10/§11 有 ✅/🔶/❌ 标注。

| # | 事项 | 现状 | 验收标准 |
| --- | --- | --- | --- |
| 0 | ~~**带标准答案的多场景评测**（检出率/误报率/耗时/成本）~~ **已完成** | `tools/eval_scenarios.py` + `evals/scenarios.json`（12 场景，标准答案来自 vulnlab 的已知漏洞）+ 口径测试。引擎层实测 检出 100% / 误报 0%；Agent 层脚本 LLM 12.5%（是管道指标，不是能力指标）；**真实模型那一档已跑两轮**：75% / 误报 0%，¥0.4158 + ¥0.4357，351.8s + 407.2s（`--tier agent --llm live --allow-live`） | 详见 `docs/EVAL.md` §4 |
| 0b | ~~**覆盖记录与攻面证据自相矛盾**（live 评测发现）~~ **已修** | 攻面记了 3 条 `signal`（未转义回显），覆盖记录却写 `no_issue_found` | 记录层闸门：有 signal 时拒绝写 `no_issue_found`/`ruled_out`，除非带 `dismiss_signals`（理由随覆盖行进报告）。`tests/test_coverage_consistency.py`（13 条） |
| 0c | ~~**子任务没跑完不留"没测过"的痕**（live 评测发现）~~ **已修** | 真根因更狠：侦察子代理自己挑档位时漏了 `business`，而 `/api/order` 在 business 档第 68/77 位——**端点根本没被发现**；`closing_no_finish` 又算"已收尾"，于是一片空白 | ① `knowledge.BUSINESS_CRITICAL_PATHS`（12 条只读、凭 id 就能读的入口）**无论选哪些档位都探**（`include_critical=false` 可关）；② 没以 `done` 收尾的任务，把它点名却没碰过的端点写成 `not_tested`。零额度验证：`/api/order` 从 0 端点/0 尝试 → 1/1 |
| 0d | ~~**字典发现的端点没有参数信息**~~ **已修（参数名那半）** | `/api/order` 登记时参数为空，"该用 `order_id` 测"只能靠模型猜——三轮 live 评测都没想到。第 4 轮修完：`/api/order` 拿到 25 次尝试、其中 24 次带 `order_id`，`I1` 任务正常收尾，**但仍漏报**——模型试 `order_id=1` 得到 404「订单不存在」，把整条端点记成 ruled_out | ① `knowledge.suggest_id_params()` 按路径名词给候选（`/api/order` → `order_id`/`id`；`/login` 这类动作路径**不给**）；② 存进 `Endpoint.suggested_params`，**永不混进 `params`**，提示词里标成 `推测参数[...](未验证)`；③ `orchestrator.idor_sweep_tasks()` 确定性派 `I1(auth)` 任务（先确认真实参数名，再 A/B 换 id 对比，每端点必须有结论）。`tests/test_idor_sweep.py`（18 条） |
| 1 | `closing_no_finish` 占比 | 约 10%（模型不主动交总结，系统代写）；已把**最后一步**预留给收尾动作 | 一次真实运行里该终态 < 3%；或证明为什么降不下去 |
| 2 | 关窗 45 秒上限 | `HEXHOUND_CLOSE_GRACE`；沙箱命令现在可被中断（实测 10 秒内退出） | 已在打包 exe 上验收（10/10）；剩余是把上限调到"不急不躁"的默认值 |
| 3 | `memory/<host>.json` 无修剪 | 陈旧条目每次 diff 都以 `unknown` 复现 | `tests/test_diff.py` 加"已解决条目不再出现"；`hexhound memory` 报出修剪了什么 |
| 4 | 非 DeepSeek 的推理参数 | 只对 DeepSeek 发送 `reasoning_effort` | 按提供商映射 + 矩阵测试断言请求体 |
| 5 | 首次 GitHub CI 的红点 | `2d294a0` 的 windows/py3.12 红过一次，**原因未定位** | 复发时用 `tools/ci_status.py --summaries` 读注解 |
| 6 | `reports/` 被 gitignore | 报告不进仓库 | 需要长期留存时搬进 `docs/` |

---

## 8. 改代码的推荐流程

1. **先读这里 + `docs/WORK-REPORT-ROUND4.md`**，再动代码；不要凭印象重构。
2. **复现优先**：写一个最小复现（脚本放 gitignore 的 `.tmp/`，或直接做成失败用例），
   确认现象后再改。
3. 改完**跑相关单测** → `python -m pytest tests -q` → `python -m ruff check src tests tools`。
4. 涉及编排/工具/沙箱的改动，**再跑 §5 的零额度脚本**（靶场要先起）。
5. 改了源码要**重建 exe**（§4.4），否则用户双击的还是旧代码。
6. **提交**：一个可验证的阶段一次；信息里写清"修了什么、怎么验证的、实测数字"。
7. 推送后**看 CI**：`python tools/ci_status.py --sha <sha>`；红了先看 check-run 摘要。
8. 文档同步：`README.md` + `README_ZH.md` + 相关 `docs/*.md`（用户明确要求过）。

---

## 9. 一页速查

```powershell
# 状态
git log --oneline -5 ; git status --short
python -m pytest tests -q
python tools/ci_status.py

# 靶场（真工具验证前提）
wsl -d Ubuntu-24.04 -- bash -lc "tr -d '\r' < '/mnt/c/Users/LeXSon/Documents/ChatGPT/HexHound 2/tools/start_lab_in_wsl.sh' > /tmp/start_lab.sh; bash /tmp/start_lab.sh 5000"

# 零额度端到端
python tools/verify_real_tool_chain.py
python tools/verify_swarm_with_real_tools.py
python tools/verify_close_guard.py

# 本地 CI / 打包
python tools/run_ci_locally.py --all
python -m PyInstaller --noconfirm --clean HexHound-desktop.spec
Copy-Item dist\HexHound-desktop.exe hexhound.exe -Force
python tools/verify_desktop_exe.py
```

用户配置（勿改）：`~/.hexhound/settings.json`（桌面设置，`max_steps=100`、`task_steps=10`、
`swarm=1`）、仓库 `.env`（CLI：`LLM_MODEL=deepseek-flash`、`MAX_STEPS=30`、`ALLOWED_HOSTS=*`）。
**注意**：多代理模式下 `max_steps` 不生效，真实上限是"每子任务 `task_steps` + 至多两轮收尾"。


