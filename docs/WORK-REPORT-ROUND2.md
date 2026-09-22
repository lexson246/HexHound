# HexHound — 第二轮工作报告（接 8cb2843 基线）

> 面向下一个接手的人（或 AI）。**全部数字都是实测的**，没测的就写"未验证"。
> 本文记录的是 8cb2843 之后的 9 个提交：做了什么、怎么验证的、还差什么。
>
> 基线：`8cb2843 chore: capture project handover baseline`（254 passed）
> 本轮结束：`847c166`（**653 passed, 1 skipped**）
>
> ⚠ **本文的数字是本轮结束时的快照，不是当前状态。** 后续轮次又改了代码与测试：
> 当前状态见 [`docs/WORK-REPORT-ROUND3.md`](WORK-REPORT-ROUND3.md)
> （现在 `python -m pytest` = 756 passed / 1 skipped）。
> 正文里出现的 653 / 674 都以"本轮快照"理解，不要当成今天的数字。


---

## 0. 一句话状态

六项最小闭环（ANSI/UTF-8/WhatWeb、受限收尾回合、原子预算 + 墙钟护栏、
溢写存储、离线 trace/report 证据链、OpenAPI/Swagger 导入）**全部落地并有测试**；
外加三项计划外但必要的补齐：**有界动态重规划 + 监督器**、**浏览器 XSS 分级验证**、
**业务逻辑靶场**。CI、lint、行尾一致性也补上了。
**需求里的验收标准全部达成**（业务逻辑那条经 8 次真实运行后确认，
记录见 §4.1——这个过程本身修掉了四层工程缺陷）。

测试：**674 passed, 1 skipped**。`ruff check src tests`：All checks passed。

---

## 0.1 先读这一段：8 次真实运行换来的教训

"Agent 测不出业务逻辑漏洞"最初看起来是**模型能力**问题，实际是**四层工程缺陷**
叠在一起。按这个顺序排查，比先怀疑模型有效得多：

1. **入口不可发现** —— 靶场首页把 `/cart` 写成了纯文本而不是 `<a href>`；
   又或者规划者根本不排侦察任务（攻面为空 → 一切以攻面为输入的确定性派发全失效）。
2. **预算不够** —— 业务逻辑任务要串完"登录 → 加购 → 四种缺陷各测一遍 → 逐条记录"，
   14 步在第 13 步就用光了，只完成前置侦察。
3. **协作断裂** —— 会话由 auth 角色拿到，而 injection 角色既**看不到**它
   （`auth_profiles` 被浅拷贝），也**没有工具**去切换身份（`use_account` 不在它的工具集里）。
4. **判据误杀** —— 我自己新加的停滞监督器把"GET 探路 → POST 登录 → POST 加购 →
   GET 目录（1602 字符）"判成"连续 8 步无进展"并中止了任务。

**还有一层是靶场自身的**：服务端知道商品真实单价，却没有任何途径让 Agent 知道
SKU 是什么（首页不列、app.js 没有、`/catalog` 与 `/products` 都 404），
于是它识别出了"价格由客户端决定"却构造不出"1299 元的商品以 0.01 元成交"的最终对比。
**入口发现不了的漏洞等于不存在**——这与 HANDOVER 里 `/coupon` 从没被发现是同一类失效。

---

## 1. 提交清单（每个都可单独回滚）

| 提交 | 内容 |
| --- | --- |
| `e0434c1` | ANSI/OSC/UTF-8 清理；**whatweb `-q` 静默失效修复**（见 §3 第 1 条） |
| `7b57644` | 受限收尾回合（≤2 轮，白名单动作）；原子预算扣减；单调时钟；波次时间闸门 |
| `eadf9d3` | 溢写存储（有界、按运行隔离、opaque 句柄、分页/字面量搜索、三级配额） |
| `7e3db6e` | trace.jsonl + snapshot.json；离线重渲染；脱敏；旧格式迁移 |
| `4551c90` | OpenAPI 3 / Swagger 2 导入（作用域安全，不信任 servers） |
| `344e183` | 有界动态重规划（只在新盲区时触发、波次边界、硬上限）+ 停滞监督器 |
| `2c31eae` | 浏览器 XSS 验证：反射 / DOM / **执行** 三级判据 |
| `8c5f6f1` | 业务逻辑靶场（价格篡改 / 负数数量 / 跳过步骤 / 重复提交） |
| `847c166` | CI + lint 清零 + 行尾一致；修 3 个真实运行暴露的缺陷 |

新增模块：`sanitize.py` `spill.py` `trace.py` `apispec.py` `replan.py`
`supervisor.py` `xssverify.py`。
新增测试文件：`test_sanitize.py` `test_budget_concurrency.py` `test_spill.py`
`test_trace.py` `test_apispec.py` `test_replan.py` `test_xssverify.py`
`test_business_logic.py`。

---

## 2. 怎么验证的（可复现）

```powershell
python -m pytest                 # 653 passed, 1 skipped
python -m ruff check src tests   # All checks passed
python examples/tool_selftest.py # 31/31（不需要 key）
$env:SWARM_MOCK="1"; python examples/swarm_demo.py   # 离线跑完整个编排
```

WSL 里的靶场侧验证（需要先把 `vulnlab/app.py` 拷进 `/opt/hexhound-lab/`——
**WSL 里那份是独立副本，改 Windows 侧不会自动同步**）：

```bash
cp '/mnt/c/.../vulnlab/app.py' /opt/hexhound-lab/app.py
wsl -d Ubuntu-24.04 -u root -- bash /mnt/c/.../tools/verify_lab_new_vulns.sh        # 5/5
wsl -d Ubuntu-24.04 -u root -- bash /mnt/c/.../tools/verify_lab_business_logic.sh   # 7/7
```

新增的 XSS 对照组（`/reflect-text`、`/reflect-dom`、`/reflect-csp`）用真实
浏览器验证：装了 Playwright 后 `tests/test_xssverify.py::RealBrowserTests`
会真跑（本机实测 9 项通过，用系统 Edge）。**四个端点字符串级别一样，
只有 `/reflect` 判为 `executed`**——这就是"反射 ≠ 执行"的实证。

---

## 3. 本轮修掉的真实缺陷（都不是读代码想出来的）

1. **`whatweb -q` 把结果一起吞了**（实测）：`whatweb -q --no-errors` 输出为空、
   退出码 0，于是 `_web_fingerprint` 一直返回"无输出"，技术栈面从未被填充。
   实测对比：`-q` → 空；`--no-errors --color=never` → 完整指纹行。
   顺带修了分段解析（原实现按 `,` 切且合并 stderr，一条 WSL 警告就能把
   值截成 `Werkzeug: 3.0.1]\n\nwsl: …`）。

2. **重规划里的 `AttributeError` 打挂整次 audit**（实测）：`_replan_brief` 读了
   `task.outcome_label`，而它只是 `to_dict()` 的派生字段。异常从波次边界
   冒到 CLI，**那次运行已经发现了路径穿越与 SSRF 却以 exit 1 结束、报告都没写**。
   现在 `_run_replan_round` 整轮包了兜底：出错记 `replan_error` 事件并返回空列表。

3. **trace 记录的 `kind` 撞名**（实测）：`**Verdict.to_dict()` 里的 `kind` 与
   `TraceRecorder.record(kind=...)` 撞参数名 → `TypeError`，把两个子任务
   标成"未预期错误中断"。编排事件的 `kind` 同样会撞。

   三条回归测试在 `tests/test_replan.py::RealRunRegressionTests`，且**都用非空
   `done` 列表**——早先的测试传 `done=[]`，那几行根本没被执行到。
   第 2 条已用"临时还原修复"验证过：会重现一模一样的 AttributeError。

4. **`gui.py` 调用从未导入的 `_build_llm_pool`** → 从 GUI 启动审计必定 NameError。
   （这解释了 HANDOVER 为什么把 GUI 列为"未验证"。）

5. **业务逻辑端点根本没被发现**（踩了三次，是本轮最贵的一个坑）。
   一开始是靶场首页把 `/cart` 等写成了纯文本而不是 `<a href>`，爬虫抓不到；
   改成真链接后**仍然**发现不了——真正的根因更深：

   > `business_logic_tasks()` / S1 / K1 这些确定性派发**全部以攻面为输入**。
   > 攻面里没有 `/cart`，就没有业务逻辑任务。而攻面里有没有 `/cart`，
   > 完全取决于"这一轮有没有哪个子代理真的去 crawl 首页"。
   > 规划者是 LLM——它看到历史记忆里的回归目标时，**完全可能一个 recon 都不排**。
   > 实测：一次排了 4 个任务全是回归复测，一次排了 2 个，两次都没有爬首页，
   > 两次 `/cart` 都不在攻面里。

   修法：新增 `Orchestrator._ensure_recon()` 作为**确定性兜底**——计划里没有
   侦察任务就补一个（名额满了就改写一个最不具体的任务），且侦察目标里
   **点名**业务入口（`/cart`、`/order*`、`/coupon`、`/wallet`、`/reset*`）
   与 `business` 词表档位。与"有带参端点却没注入任务就补一个"同一个思路：
   **报告的可信度不能依赖模型这次心情好不好。**
   同时把 B1 任务的步数预算从 `3*端点数+8`（实测只有 14 步）提高到
   `4*端点数+10`：B1 必须串完"拿到会话 → 加购 → 四种缺陷各测一遍 → 逐条记录"，
   14 步时它在第 13 步用尽预算，只完成前置侦察就结束了
   （覆盖记录里留下的正是 `not_tested`「步数耗尽前仅完成前置侦察」——
   **测不完**与**测不出**在报告里长得一样，但成因完全不同）。

6. **靶场自身的两个边界被 `or` 吞掉**：`data.get("qty") or 1` 把 `qty=0` 变成 1、
   `data.get("price") or catalog` 把 `price=0` 变成目录价——而 0 正是攻击者会试的值。
   改成 `is None` 判断，并加测试锁住。

7. **编码类**：`decode_output` 嗅探 UTF-16LE（`wsl.exe -l -q` 会回它）；
   `WSL_UTF8=1` + `PYTHONIOENCODING` 钉死子进程编码；
   `examples/swarm_demo.py` 曾在 GBK 控制台因打印 `¥` 崩在最后一行——
   控制台初始化已挪到包导入时（覆盖示例脚本等入口）。

---

## 4. 明确未达成 / 未验证的事项（**不要当成已完成**）

1. ~~**【未达成】「Agent 至少能发现一个新增业务逻辑漏洞」**~~ → **已达成（已验证）**。
   靶场侧人工脚本 7/7（§2），Agent 侧在最终一次运行里**复核确认了 3 条业务逻辑漏洞**：

   | 编号 | 严重度 | 结论 | 证据 |
   | --- | --- | --- | --- |
   | `HH-012` | high | **价格篡改**：`/cart` 与 `/order/confirm` 接受客户端 `price`，不按目录价重算 | `W5-R5/R6/R7`：SKU-1002 目录价 1299.0 → 加购 `price=0.01` → 合计 `0.01` → 下单 `ORD-1001` 该行 `paid_price=0.01`，**少付 1298.99** |
   | `HH-013` | high | **负数数量未校验**：`qty=-5` 让购物车合计变负 | 覆盖记录与 finding 均含前后状态对比 |
   | `HH-014` | high | **缺失幂等**：同一购物车可重复下单，生成多张订单且不清空购物车 | 同上 |

   每条都通过了复核门（`verified`），且带完整请求/响应（`R` 编号）、影响量化、
   复现步骤、CVSS/CWE 与截图证据——满足需求里"finding 必须包含完整请求、响应、
   影响和可复现步骤"这一条。

   **为此跑了 8 次真实运行（约 ¥2.3）**，每次暴露的都是**下一层**问题，
   逐条记录在下面（这些修复本身的价值不小于那条验收标准）：

   | 次 | 结果 | 真实原因 | 修法 |
   | --- | --- | --- | --- |
   | 1 | exit 1，无报告 | 我自己新代码的两个缺陷（§3.2/§3.3） | 修 + 回归测试 |
   | 2 | 8 条结论，无业务逻辑 | 靶场首页把 `/cart` 写成**纯文本**，爬虫抓不到 | 改成 `<a href>` |
   | 3 | 10 条结论，无业务逻辑 | 规划者一个 recon 都没排（攻面为空） | 加 `_ensure_recon` 兜底 |
   | 4 | 8 条结论，无业务逻辑 | B1 派发了但**14 步不够**，只够"确认端点 + 登录" | 步数提到 `4*端点+10` |
   | 5 | 15 个子任务 | B1 到了 `/cart`、页面自曝四类缺陷、也拿到了会话，仍未测 | 会话共享（见 §3.5，两层缺陷） |
   | 6 | 3 条待复核候选 | 结论**认出来了**但构造不出最终对比：**靶场没有任何途径知道 SKU**（首页不列、app.js 没有、`/catalog` 与 `/products` 都 404） | 靶场补公开的 `/catalog` 目录 |
   | 7 | B1 被 `supervisor_abort` | **我自己的停滞判据误杀**：前 7 步（GET 探路 → POST 登录 → POST 加购 → GET 目录 1602 字符）每步都在推进，但旧判据只看"record_* 动作 + 少数中文进展词" | 补两条与领域无关的进展信号（状态改变型请求、观察文本 ≥400 字符） |
   | 8 | **3 条业务逻辑漏洞已复核** | — | — |

   **仍然要记住的教训**：这 8 次里有 5 次卡在**发现与协作**上，只有 1 次是模型能力问题。
   "Agent 测不出业务逻辑"最初看起来像能力问题，实际是四层工程缺陷叠在一起
   （入口不可发现 → 没有侦察 → 步数不够 → 会话不共享 → 判据误杀）。
   下一次遇到"某类漏洞测不出来"时，先按这个顺序排查，不要先怀疑模型。


2. **README.md / README_ZH.md 尚未同步本轮行为变化**。需要补：
   `--api-spec` / `--api-spec-remote-refs` 两个参数、溢写句柄与 `spill_read`、
   `trace.jsonl`/`snapshot.json` 与离线 `report`、浏览器 XSS 三级判据与
   Playwright 可选、业务逻辑靶场与两个验证脚本、收尾回合与新的终态文案。
   中英文必须同步（这是项目自己的约束）。

3. **PyInstaller 产物已重建**（本轮完成）：`python -m PyInstaller --noconfirm --clean
   HexHound.spec` → `dist/hexhound.exe`（87 MB）→ 拷到根目录。
   实测 `hexhound.exe --version` / `providers` / `audit --help` 均正常，
   且新的 `--api-spec` 参数已出现在帮助里（说明打进去的是当前代码，不是旧产物）。
   注意：PowerShell 里 `.\hexhound.exe providers 2>&1 | Select-Object -First 3`
   会因为管道被提前关闭而报 `[exit code: 1]`——那是 **PowerShell 的行为**，
   不是程序失败（`providers *> $null; $LASTEXITCODE` 实测为 0）。

4. **GUI 自动化测试仍缺**（本轮只修了那个 NameError，没加测试）。
   CI 里也没有 GUI 冒烟测试。

5. **CI 未在真实 GitHub runner 上跑过**：工作流是本机写的，只做过本地的
   等价命令验证（ruff/pytest/tool_selftest/swarm_demo/CLI 冒烟）。
   首次推送后要确认 ubuntu 与 windows 两个矩阵都绿。

6. **`--api-spec` 的远程规范只做了校验与拒绝路径**：本版本**不下载远程规范**
   （明确报错说明），远程 `$ref` 同理。这是刻意的（导入阶段不发网络请求），
   但如果确实需要，得再实现。

7. **浏览器验证只覆盖了 GET 注入**；POST 表单/JSON 体的 XSS 需要扩展。
   另外 `channel="msedge"` 是本机默认，跨平台需要按环境调整。

8. **覆盖率记录会被当成端点登记**：报告里出现过
   `/cart（受保护，值得进一步探测）` 这种带自然语言后缀的假端点。
   属于数据卫生问题（coverage 的 target 字段直接进了端点表），
   会让"端点覆盖"数字虚高。需要过滤或分离。

---

## 5. 与 Strix / PentAGI 的差距（本轮之后）

参考依据：`docs/research-notes/strix-pentagi-refresh-2026.md`（记录了两边的
commit SHA，全部结论来自源码/官方文档，不是二手介绍）。

| 能力 | Strix | PentAGI | HexHound 现状 |
| --- | --- | --- | --- |
| 工具输出治理 | 落盘 + 通用 shell 读回 | 摘要或截断 | ✅ 落盘 + **专用分页/搜索工具**（无 shell 也能读回） |
| 预算强制 | 预留比例 + 暂停态 | 只记账、无上限 | ✅ 原子扣减 + 单调时钟 + 波次闸门（并发测试锁死） |
| 收敛 | 阶梯收尾指令 | 强制 reflector 窗口 | ✅ 受限收尾回合（白名单动作）+ 停滞/失败循环监督 |
| 动态规划 | 无（只有扁平 todo） | `subtask_patch` | ✅ 有界 patch（只在波次边界、硬上限、不可扩范围） |
| 审计/可观测 | 磁盘优先可重放 | OTel + Langfuse | ✅ trace.jsonl + snapshot，**零外部服务**；无 OTel/Langfuse |
| API 规范导入 | ✅ `-t openapi.yaml` / Postman | ❌ | ✅ OpenAPI3/Swagger2（**不信任 servers**，比 Strix 更严） |
| 浏览器验证 | ✅ CDP + eval | ⚠ 只有截图/抓取 | ✅ 三级判据（反射/DOM/执行）+ 截图/console/网络证据 |
| 业务逻辑 | ✅ 9KB skill 手册 | ❌ | ⚠ playbook + 靶场 + 确定性派发**都有**，但**端到端未验证**（§4.1） |
| 部署 | Docker | Compose + pgvector/Neo4j | ✅ 单进程 `pip install` |

仍然做不到的（如实记录）：窄窗口竞态在真实目标上仍可能打不中；
加密实现类只覆盖"密钥泄露 / 算法混淆 / 可预测令牌"；
nuclei 模板 0 命中**不等于**安全；业务逻辑仍依赖模型理解**你的**领域不变量。

---

## 6. 下一步建议（按优先级）

1. **重跑业务逻辑验证并给出结论**（§4.1）——这是唯一未达成的验收标准。
   建议 `--max-tasks 3 --task-steps 12 --max-cost 0.8`，重点看 `B1` 任务。
2. **重建 `hexhound.exe`**（§4.3）——现在的产物对应旧代码。
3. **同步 README/README_ZH**（§4.2）。
4. GUI 冒烟测试 + 把 CI 真跑一次（§4.4/4.5）。
5. 浏览器验证扩展到 POST；真实目标上的 XSS 复测。

---

## 7. 本轮踩到、值得记住的坑

- **WSL 里的靶场是独立副本**：只改 Windows 侧的 `vulnlab/app.py` 不会生效，
  必须 `cp` 过去再重启；`fuser -k 5000/tcp` 是可靠的停法（按端口，不按命令行）。
- **Flask 的 `render_template_string` 会自动转义，f-string 不会**：
  写"未转义输出"的对照组时必须显式 `markupsafe.escape`，否则测的不是你想测的东西。
- **`data.get("x") or default` 会吞掉 0 和 ""**：边界值测试要特别注意，
  否则"0 件 / 0 元"这类关键输入根本到不了业务逻辑。
- **PowerShell 读 UTF-8 文件默认按 GBK 解**：用
  `python -c "..."` 或设置 `$env:PYTHONIOENCODING="utf-8"` 再看中文，
  否则会把正常文件误判成乱码。
- **`from __future__ import annotations` 会推迟注解求值**：`F821 undefined name`
  在注解里不会立刻炸，但类型检查与运行时工具（如 `get_type_hints`）仍会踩到。
