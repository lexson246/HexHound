# 给 Codex 的启动提示词（直接复制粘贴）

> 用法：把下面 **「提示词正文」** 整段复制给 Codex（在仓库根目录
> `C:\Users\LeXSon\Documents\ChatGPT\HexHound 2` 打开会话）。
> 需要它一次只做一件事时，把 §「本轮任务」换成对应条目即可。

---

## 提示词正文

你是接手 **HexHound** 项目的编码代理。这个仓库在
`C:\Users\LeXSon\Documents\ChatGPT\HexHound 2`，分支 `main`，origin 是
`lexson246/HexHound`。上一个代理刚做完第四轮修复，基线提交 `439e02f`，工作树干净。

**第一步（必做，别跳）**：读这两份文件，它们自包含：

1. `docs/CODEX-HANDOVER.md` —— 交接文档：当前状态、代码地图、五条铁律、
   六个真实事故与它们的守卫、还没做的事、推荐流程、一页速查。
2. `docs/WORK-REPORT-ROUND4.md` —— 第四轮工作报告：每条修复的复现→根因→验证。

读完先用三条命令确认基线（把输出贴给我）：`python -m pytest tests`、
`python -m ruff check src tests tools`、`python tools/ci_status.py`。
期望是 **992 passed + 50 subtests passed / 1 skipped**、ruff 干净、CI 8/8 绿。
（`pytest` 别再补 `-q`：`addopts` 里已经是 `-q`，双重 `-qq` 会让它连汇总行都不打印。）
数字对不上就先查原因，不要在我给的任务上继续。

### 铁律（违反会造成不可逆损失，任何情况下都不许破）

1. **禁止** `git reset --hard`、`git clean -fd`、批量 `git restore`。
   需要回退就用 `git revert` 或手工改回去。
2. **禁止**打印、提交、回显 `.env` / Cookie / Token / API key。
   测试一律用 `sk-fake-*` 这类假值。
3. **只对已授权目标测试**。`ALLOWED_HOSTS=*` 是用户本人的授权声明，不是让你放开手脚；
   你自己验证请只用本机靶场 `127.0.0.1:5000`。
4. **不要消耗真实模型额度**。所有回归都能用 `hexhound.mockllm.ScriptedLLM`（脚本 LLM）+
   本地靶场零成本跑完（见交接文档 §5）。真要真实运行，先问我。
5. **不许削弱"没测 ≠ 安全"**：未覆盖的端点/参数必须留成 `not_tested` / `candidate`，
   报告如实写"未完成"。为了让测试变绿而放宽门禁的改动一律不接受。

### 工作方式（用户明确要求过）

- **先复现再改**：写最小复现（放 gitignore 的 `.tmp/`）或先写一个失败的用例，确认现象。
- **每完成一个可验证的阶段就提交一次**；提交信息里写清"改了什么、用什么命令验证的、
  实测数字是多少"。若该提交包含别人未提交的改动，要说明。
- **改了源码必须重建 exe**（否则用户双击的还是旧代码）：
  `python -m PyInstaller --noconfirm --clean HexHound-desktop.spec` →
  `Copy-Item dist\HexHound-desktop.exe hexhound.exe -Force` → `python tools/verify_desktop_exe.py`。
  重建前先确认桌面程序没在运行。
- **推送后看 CI**：`python tools/ci_status.py --sha <sha>`，红了先看 check-run 摘要
  （Actions 原始日志需要认证，摘要由 `tools/ci_rerun_report.py` 写入）。
- **文档同步**：改了行为就同步 `README.md` + `README_ZH.md` + 相关 `docs/*.md`。
- 报告口径：**只有实测过的才能说"修好了"**；没验证的写"未验证"。

### 本轮任务（按顺序做，一次只用一条，做完停下等我确认）

1. **`closing_no_finish` 收敛**（交接文档 §7 第 1 条）
   现状：约 10% 的子任务模型不主动交总结、由系统代写；已把**最后一步**预留给收尾动作
   （`agent._ClosingState.restricted()`），但真实占比的下降**尚未验证**。
   做法建议：用真实运行数据核对（`~/.hexhound/runs/*/run.json` 的 `tasks[].outcome`，
   注意**按日期**分组——旧数据里 `max_steps` 很多，那是收尾回合上线前的历史）；
   如果占比没降，找出模型在最后一步仍然调用探测动作的原因并修。
   验收：一次真实运行里 `closing_no_finish` < 3%，或给出"为什么降不下去"的实测解释。
   **跑真实运行前先问我**（要花额度）。

2. **关窗 45 秒上限**（§7 第 2 条）
   现状：`HEXHOUND_CLOSE_GRACE`（默认 45 秒）内没写完报告就直接退出；单次 `sqlmap`
   可能跑几百秒。目标：关窗时能中断**当前工具调用**而不是干等。
   验收：`tests/test_desktop_close_guard.py` 增加用例（当前工具调用被请求中断后，
   报告在 45 秒内落盘）；`tools/verify_close_guard.py` 仍全绿。

3. **`memory` 自动修剪**（§7 第 3 条）
   现状：`memory/<host>.json` 单调增长，陈旧条目每次 diff 都以 `unknown` 复现。
   目标：连续 N 次未见 + 上次未复现的条目自动降级/标注为已解决，并在 `hexhound memory`
   输出里说明修剪了什么（**不许静默丢数据**）。
   验收：`tests/test_diff.py` 新增"已解决条目不再出现"用例；CLI 输出可核对。

4. **打包 exe 上的运行中关窗**（§7 第 7 条）
   现状：关窗护栏只在 Flask 层端到端验证过（`tools/verify_close_guard.py`）。
   目标：在**打包 exe** 上实测一次"运行中关窗 → 报告落盘"，并把步骤固化成脚本
   （可以扩展 `tools/verify_desktop_exe.py`）。需要真实运行的额度时先问我。

5. **CI 红点定位与防御**（§7 第 6 条）
   背景：`2d294a0` 的 `test (windows-latest / py3.12)` 红过一次，原因至今未定位
   （当时拿不到日志）。目标：让"未来再红"必定有可读原因——检查
   `$GITHUB_STEP_SUMMARY` 那条链路是否覆盖所有失败步骤（不只那一个 job），
   并在交接文档里写清怎么读。

### 汇报格式（每次做完一条）

```
任务：<编号与标题>
结论：已修复 / 部分完成 / 阻塞（说清阻塞在什么外部条件）
改动：<文件 + 一句话>
验证：<命令> → <实测输出摘要>（数字要具体）
提交：<sha> <一句话>（已推送：是/否）
未验证 / 风险：<如实写，没有就写"无">
```

### 不要做的事

- 不要重构与任务无关的模块；不要顺手改提示词措辞、工具描述、预算默认值——
  这些都有测试与实测依据，改动要先说明理由。
- 不要新增第三方依赖（CI 只装 `[dev]`，桌面端只装声明的 extras）。
- 不要为了"跑通"而把靶场以外的地址写进配置或测试。
- 不要在没有实测的情况下宣布某条"已修复"。
