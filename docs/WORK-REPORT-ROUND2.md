# HexHound — 第二轮工作报告（接 8cb2843 基线）

> 面向下一个接手的人（或 AI）。**全部数字都是实测的**，没测的就写"未验证"。
> 本文记录的是 8cb2843 之后的 9 个提交：做了什么、怎么验证的、还差什么。
>
> 基线：`8cb2843 chore: capture project handover baseline`（254 passed）
> 本轮结束：`847c166`（**653 passed, 1 skipped**）

---

## 0. 一句话状态

六项最小闭环（ANSI/UTF-8/WhatWeb、受限收尾回合、原子预算 + 墙钟护栏、
溢写存储、离线 trace/report 证据链、OpenAPI/Swagger 导入）**全部落地并有测试**；
外加两项计划外但必要的补齐：**有界动态重规划 + 监督器**、**浏览器 XSS 分级验证**、
**业务逻辑靶场**。CI、lint、行尾一致性也补上了。

**一条验收标准明确未达成**，见 §4：Agent 还没能发现新增的业务逻辑漏洞。

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

1. **【未达成】「Agent 至少能发现一个新增业务逻辑漏洞」**。
   为此跑了 **5 次真实运行**（约 ¥1.3）。靶场侧已用人工脚本证明四类缺陷真实存在
   （`tools/verify_lab_business_logic.sh` **7/7**），但 Agent 侧仍未测出来。
   逐次的真实原因（每一个都已修，但每次暴露的是**下一层**问题）：

   | 次 | 结果 | 真实原因 | 修法 |
   | --- | --- | --- | --- |
   | 1 | exit 1，无报告 | 我自己新代码的两个缺陷（§3.2/§3.3） | 修 + 回归测试 |
   | 2 | 8 条结论，无业务逻辑 | 靶场首页把 `/cart` 写成**纯文本**，爬虫抓不到 | 改成 `<a href>` |
   | 3 | 10 条结论，无业务逻辑 | 规划者一个 recon 都没排（攻面为空） | 加 `_ensure_recon` 兜底 |
   | 4 | 8 条结论，无业务逻辑 | B1 派发了但**14 步不够**，只够"确认端点 + 登录" | 步数提到 `4*端点+10` |
   | 5 | 15 个子任务 | B1 到了 `/cart`、**页面自曝**四类缺陷、也拿到了会话，仍未测 | 见下 |

   **第 5 次的具体卡点（已定位、已部分修复、仍需再验一次）**：
   - `B1` 到 `/cart` 拿到 401，自己试了常见口令 / SQL 绕过 / actuator 泄露的口令 /
     `/api/jwt_login` **全都不通**；
   - 而**同一轮**的 `T3(auth)` 用 SQLi 绕过 `/login` **成功**并拿到了
     `Set-Cookie: hh_session=alice:tok-alice-demo`（证据 R23）；
   - 根因：`ToolRegistry.__init__` 把 `auth_profiles` 做了浅拷贝，
     于是编排器"注入同一个字典、一处登记处处可见"的共享语义**被破坏了**；
     而且只有 `check_default_creds` 会登记会话，**其它任何方式**（包括 SQLi 绕过）
     拿到的会话都不会被共享。
     → 已修：注册表不再拷贝（改成按引用持有，与 surface/budget 一致）；
       新增 `_capture_session()`，任何响应下发的 `Set-Cookie`/token 都登记为账号 C。
   - **仍未修完的一环**：`_login_success_reason()` 存在，但只在
     `check_default_creds` 里被调用——`http_request` 发起的登录不会走"判定成功"
     这条路径，因此第 5 次那次的会话**没有被自动登记**（报告里 `账号 C` 出现 0 次）。
     下一步就是把它接上，并且让 `use_account` 能列出**已有哪些账号**（现在模型
     不知道 C 存在就不会去用）。
   - 另一个次要问题：报告里出现了 `/cart（受保护，值得进一步探测）` 这种**带自然
     语言后缀的假路径**（来自 coverage 记录被当成端点登记），属于数据卫生问题。

   **不要跳过这一步直接写"已完成"**：下一次接手时按上面两条改完，
   重跑一次（建议 `--max-tasks 4 --task-steps 16 --parallel 4 --max-cost 1.0`），
   看 `B1` 的覆盖记录里是否出现 `价格篡改 / 负数数量 / 跳过步骤 / 重复提交`
   四类的**实际结论**（而不是 `not_tested`/`blocked`）。

   **已经确定成立的部分**（可以作为已完成报告）：
   - 靶场四类缺陷真实存在 → 人工脚本 7/7；
   - 确定性派发链路通了 → `/cart` 进攻面后 `B1` 被派出并执行（run6/run7 均可见）；
   - Agent 能**认出**这是一条下单链路、并说出要测哪四类（run6/run7 的 B1 目标与
     执行记录里都写明了"页面自曝：/cart 接受客户端价格且不校验数量"）；
   - 会话共享的机制缺陷已定位并修掉了一半（见上）。

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
