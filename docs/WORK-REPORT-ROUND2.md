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

5. **业务逻辑端点根本没被发现**：`/cart` 等在靶场首页里写成了纯文本而不是
   `<a href>`，爬虫抓不到 → `business_logic_tasks()` 按攻面派发，于是什么都没派。
   已改成真链接。**教训与 HANDOVER 早先记的一致：发现不了的业务入口等于没测。**

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
   靶场侧已用人工脚本证明四类缺陷真实存在（7/7），但两次真实 Agent 运行
   都**没有**报出业务逻辑漏洞：
   - 第 1 次运行：被 §3 第 2/3 条缺陷打挂（exit 1，未出报告）。
   - 第 2 次运行（¥0.2851 / 206s / 8 条已复核）：**没有测到 `/cart`**，因为
     当时靶场首页那几个端点是纯文本、爬虫发现不了。已修发现性，**但修复后
     没有重跑**（电量原因停在这里）。
   下一次接手时应当先做这一件事：确认 `/cart` 进入攻面 → 看到 `B1` 任务被派发
   → 看它是否真的能测出价格篡改/负数数量。**不要跳过这步直接写"已完成"。**

2. **README.md / README_ZH.md 尚未同步本轮行为变化**。需要补：
   `--api-spec` / `--api-spec-remote-refs` 两个参数、溢写句柄与 `spill_read`、
   `trace.jsonl`/`snapshot.json` 与离线 `report`、浏览器 XSS 三级判据与
   Playwright 可选、业务逻辑靶场与两个验证脚本、收尾回合与新的终态文案。
   中英文必须同步（这是项目自己的约束）。

3. **PyInstaller 产物未重建**：`hexhound.exe` 仍是 8cb2843 时的构建。
   改了 `cli.py`/`gui.py`，所以它**已经过期**。重建命令：
   `python -m PyInstaller --noconfirm --clean HexHound.spec` 然后
   `Copy-Item dist\hexhound.exe .\hexhound.exe -Force`。

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
