# HexHound — 第三轮工作报告（接 `847c166` 之后）

> 面向下一个接手的人（或 AI）。**所有数字与结论都来自本机实测**；
> 没测的一律写"未验证"，不把"没测"说成"安全/修好了"。
>
> 起点：`5b7f1e3`（round 2 之后的继续提交，工作树里还有未提交的前端/打包改动）
> 本轮提交：`431141e`（P0 四个缺陷）→ `3a243b5`（P1 桌面端工作流）
> 本轮目标（用户原话）：**"修复已确认的可靠性问题，补齐桌面端工作流程，保持实现简单。"**

---

## 0. 一句话状态

四个**已确认的 P0 缺陷**全部修复，每个都先复现、再修、再补回归测试；
桌面端补齐了**完整预算护栏**与**可重启查看的任务历史**；
桌面版 exe 重新构建并跑了 **19 项启动验收**（全通过）。

| 项 | 状态 | 证据 |
| --- | --- | --- |
| P0-1 保存配置清空已保存的密钥 | 已修复 | 复现脚本 + 6 个测试 |
| P0-2 非法认证 JSON 静默变成匿名 | 已修复 | 复现脚本 + 7 个参数化测试 |
| P0-3 普通弹窗被当成 XSS 执行（确认级误报） | 已修复 | 真实浏览器复现脚本 + 端到端回归测试 |
| P0-4 本机接口回传明文密钥、无 CSRF 防护 | 已修复 | 8 个端口级测试 + 打包版实测 403 |
| P1 桌面端预算护栏只生效 2/5 | 已修复 | 18 个解析/边界测试 |
| P1 任务历史（重启后仍可查看） | 已实现 | 13 个模块测试 + 打包版实测读取磁盘历史 |
| 桌面版 exe 双击可用 | 已验证 | `tools/verify_desktop_exe.py` 19/19 |

测试：**756 passed, 1 skipped**（本轮起点 676 passed, 1 skipped）。
`ruff check src tests tools`：All checks passed。

> 补完轮之后是 **786 passed, 1 skipped**（见 §7）。

---

## 1. 四个 P0 缺陷：复现 → 修复 → 回归

### P0-1 任何一次"保存配置"都会清空已保存的密钥

**复现**（`.tmp/repro_p0.py`，修复前）：

```
after saving one key   : {'deepseek': 'sk-fake-0001'}
after ordinary save    : {}          ← 密钥消失
BUG PRESENT: True
```

**根因**：`_save_settings` 用 `DEFAULTS` 重建整个字典，而设置面板的普通表单里
根本没有 `provider_keys` 字段（密钥就存在这个键里）。

**修复**：以磁盘现值作基底，只覆盖 payload 里**真的出现**的键（`None` = 显式清空）；
加 `_SETTINGS_LOCK` 把并发保存串行化；写入改为同目录临时文件 + `os.replace` 原子替换。

**修复后**：`after ordinary save : {'deepseek': 'sk-fake-0001'}`，`BUG PRESENT: False`。

### P0-2 认证配置写错 → 静默变成"匿名评估"

非法 JSON 直接返回 `{}`，于是"Cookie 没解析成功"在报告里会变成
**"这些接口匿名也能读"**——把配置错误写成访问控制缺陷。这是最危险的错误方向。

**修复**：非法 JSON / 顶层不是对象 / 值不是字符串 / 值是空串 → `ValueError`，
报错**只含字段名与类型，绝不回显值**（值就是 Cookie/Token）；
`/api/run` 在**启动之前**校验，以 400 + 明确原因返回，任务不启动。

### P0-3 XSS 确认级误报：普通弹窗被当成"执行了"

**复现**（`.tmp/repro_p0_3.py`，本地临时测试页；修复前）：

```
/dialog-textarea  level=executed  confirmed=True      ← payload 在 <textarea> 里，根本没执行
                  signals=['页面弹出了对话框（1 个）', '对话框内容包含 payload']
                  dialogs=['请输入用户名']              ← 页面自己的提示，与载荷无关
BUG PRESENT: True
```

**两个缺陷**：

1. 看到任何 dialog 就记一条执行信号，**与本次载荷无关**（页面自己弹的校验提示也算）；
2. `'对话框内容包含 payload'` 检的是函数参数 `payload`（默认空串），
   而 `"" in 任何文本` 恒真——所以每个普通弹窗都会被标注成"内容包含 payload"。

**修复**（两条独立要求）：

1. 每次验证生成**随机 nonce** 标记，DOM 标记属性/全局变量的**值必须等于本次 nonce**
   才算证据（上一次验证残留、页面自己写的同名标记都不算）；
2. 对话框只在**内容可归因**（含本次载荷原文或本次 nonce）时才算执行证据，
   基线页面本来就弹的弹窗另行扣除；无法归因的弹窗写成"不作为执行证据"的说明。

**修复后**：

```
/dialog-textarea  level=dom       confirmed=False   ✅ 假阳消失
/dialog-exec      level=executed  confirmed=True    ✅ 真执行仍识别（信号带本次 nonce）
/clean-textarea   level=dom       confirmed=False   ✅ 对照不变
BUG PRESENT: False
```

### P0-4 本机控制面：明文密钥回传 + 任何网页都能驱动本机

`/api/providers` 为了"一键填入密钥框"回传**明文** `keys`；同时所有有副作用的
接口（启动审计、写白名单、写 `.env`、弹登录窗口）都没有会话校验——
一个恶意网页就能让本机去消耗真实模型额度。

**修复**：

* `/api/providers` 只回**掩码**与"是否已保存"；密钥只在服务端按 provider 取用；
* 拒绝把界面回显的**掩码**当密钥存回来（否则之后每次请求都拿一个必然失败的假密钥，
  而界面还显示"已保存"）；
* 每次启动生成**会话令牌**并渲染进页面，非 GET 请求必须携带
  （跨站页面读不到令牌，也无法在无预检的情况下设置自定义头）；
* 校验 `Host` / `Origin` 只能是本机（同时挡掉 DNS rebinding）；
* 错误文本展示前统一打码（提供商的鉴权报错经常原样回显 `sk-...`）。

**实测**（打包后的 exe 上同样生效）：无令牌 `POST /api/save` → **403**；
带令牌 → 200 并落盘。

### 附带修掉的运行生命周期问题（P1-5 的前置）

* 中断不再丢成果：停止是过渡态 `stopping` → `cancelled`；中断时**照常写报告**，
  保留已完成的步骤与用量，并在总结与界面写明"报告不完整"，未测区域**不写成安全**；
* 运行期间（含收尾期）拒绝重复启动（409），界面按钮同步禁用——
  否则两个审计线程会同时写同一份攻面与产物目录。

---

## 2. 桌面端工作流补齐

### 2.1 预算护栏与 CLI 统一（此前桌面端只生效 2/5）

桌面端原先自己又拼了一套 `Config`/`Budget`，CLI 支持的五个上限里只有
`max_cost` / `max_tool_calls` 生效，`max_tokens` / `max_llm_calls` / `max_seconds`
**被静默丢弃**，界面上也没有输入框——用户以为设了护栏，其实没有。

现在：新增 `src/hexhound/runparams.py` 作为**唯一**字段定义（标签 + 单位 + 范围 + 默认值）：

* 界面输入框由 `field_specs()` 渲染，后端由 `parse_fields()` 解析；
* 预算出口统一走 `budget.limits_from_config`（与 CLI 同一条路径）；
* 语义写死并测试：预算字段 `0`/留空 = 不限制；其它字段 `0`/负数 = 报错；
  非法/非有限/超范围 = 报错且**一次报出全部问题**；报错带标签与单位；
* 运行开始时把"生效中的护栏"写进执行记录，不用等跑完才知道上限生效没有。

### 2.2 任务历史（重启后仍可查看）

新增 `src/hexhound/history.py`（只读磁盘）+ `/api/history`、`/api/history/<run>`
+ 报告页的"历史运行"面板。列出目标、时间、状态、发现/端点、token 与费用、报告可用性，
点开即可看那次运行的报告。

两条硬约束由测试守着：

* **不调模型、不访问目标**（测试里把 `LLMClient` 与 `socket.connect` 换成"一碰就失败"）；
* 报告优先用当时写下的 `report.md`，缺失时才用 `snapshot.json` 离线重渲染，
  并在报告开头写明是重建的；运行目录名来自 URL，路径穿越一律拒绝。

审计收尾时会把报告副本写进本次运行目录——默认输出路径 `reports/report.md`
会被下一次运行覆盖，否则"历史里看到的"就不是当时那份。

---

## 3. 桌面版 exe：构建与验收

```
产物：dist/HexHound-desktop.exe  →  项目根 hexhound.exe（90,349,638 字节）
构建：python -m PyInstaller --noconfirm HexHound-desktop.spec
PE 子系统：2（WINDOWS_GUI）← 双击不会弹黑色控制台窗口
```

`tools/verify_desktop_exe.py`（19 项全通过，隔离目录，不碰真实配置与历史）：

| 检查 | 结果 |
| --- | --- |
| 双击式启动（无参数）后进程存活并监听本地端口 | OK |
| 内嵌 WebView2（我们自己的 msedgewebview2 子进程） | OK |
| 没有另开外部浏览器进程（无 msedge/chrome/firefox 子进程） | OK |
| 控制台页面 200、关键控件齐全、会话令牌已渲染 | OK |
| `/api/status` 为 idle、`/api/history` 可用 | OK |
| 无令牌写操作被拒（403）／带令牌成功（200 且落盘） | OK |
| 原生窗口创建（标题 HexHound） | OK |
| 关闭窗口后进程全部退出、端口释放 | OK（约 10 秒，含 WebView2 收尾） |
| 重启后配置仍可读（上次保存的目标回填） | OK |
| 重启后读到磁盘上的历史运行 + 能看报告原文 | OK |
| 第二次关闭也干净退出 | OK |

> 途中踩到的**验收脚本**竞态（不是应用问题）：`taskkill`（不带 `/F`）就是发
> WM_CLOSE，窗口还没建出来时没人接收，关闭动作会被丢掉。脚本先等窗口就绪再关。

---

## 4. CI 门禁

* `lint`：ruff 范围扩到 `tools`；
* `gui`（新）：显式装 Flask + Playwright + chromium，跑界面与浏览器验证层，
  并设 `HEXHOUND_REQUIRE_GUI=1`——**依赖缺失是失败，不是跳过**
  （一个"缺依赖就静默跳过"的界面测试层等于没有测试层）；
* `desktop`（新，Windows）：真的构建桌面版 exe → 校验 PE 子系统为窗口 →
  同时构建 CLI 版并校验它是控制台子系统 → 打包入口分发测试 →
  本机控制台冒烟；完整启动验收（`tools/verify_desktop_exe.py`）标记为 advisory，
  因为 GitHub runner 是否具备可交互桌面会话与 WebView2 **在本机无法预先证实**
  （这点明确写进了 workflow 注释，不假装它是硬门禁）。

> **未验证**：这些 workflow 改动**没有在 GitHub 上跑过**（本机无 runner）。
> 每个 job 里用到的命令都在本机手工执行过并成功，但"CI 编排本身"属于未验证项。

---

## 5. 本轮踩到的坑（给下一个接手的人）

1. **`importorskip` 会吞掉"必须运行"的要求**：它抛的 `Skipped` 继承自
   `BaseException`，`except Exception` 抓不到。要用显式导入 + 自己的策略函数。
2. **`channel="chromium"` 不是合法频道名**：浏览器冒烟测试因此静默跳过过。
   现在按候选顺序尝试（自带 chromium → msedge → chrome），并按环境变量语义解释。
3. **onefile 打包是父子两个进程**：父进程（引导器）不持有端口，
   只盯启动时拿到的 PID 会误判成"没起来"。
4. **空白字符串是最隐蔽的"恒真谓词"**：P0-3 的第二条缺陷就是
   `"" in 任何文本 == True`。项目里已有 `_appears()` 显式挡空载荷，
   但同一文件里另写的一行没挡——**同一约束要在每个使用点守住**。
5. **"界面回显值"被当成"真实值"存回去**是通用错误模式（掩码、占位符、`(已保存)`），
   接口层要显式拒绝，而不是指望界面不出错。
6. **"我已经隔离了"必须是被证明的性质，不是假设**：第一次跑桌面验收时，用的 exe
   还没有 `HEXHOUND_SETTINGS_PATH` 支持，于是"隔离"没生效、**真实配置被写了进去**。
   现在验收脚本自己在开始前取一次真实配置指纹、结束时再取一次做对比，
   并断言隔离文件确实生成——把隔离变成验收项之一。

---

## 6. 明确未完成 / 未验证的事项

> **本节已按"补完轮"更新**（同一轮目标的收尾，详见 §7）。下表第三列是现在的状态。

| 事项 | 状态与原因 | 现状（补完后） |
| --- | --- | --- |
| 报表工作区进阶（筛选、详情分栏、导出、跨运行对比） | 原：未开始（用户列为"按收益推进"） | **已完成** → §7.1 |
| 浏览器验证层只覆盖 GET（POST 表单型 XSS） | 原：未变 | **已完成** → §7.2 |
| 覆盖率记录里混入自然语言后缀的端点表 | 原：未修；既有数据质量问题 | **已修复**（根因是"展示文本被当数据"）→ §7.3 |
| CI workflow 在 GitHub 上真实执行 | 本机无 runner，**仍未验证** | 部分缓解：静态校验工具 §7.4；**并已用本机执行器把 7 个作业全跑绿** §8 |
| 桌面版真机"肉眼"验收 | 原：没有人眼截图确认 | **已完成**（含一处截图假象的澄清）→ §7.5 |
| Windows DPAPI 保护本机密钥（静态加密） | 原：未做（明文存在 settings.json） | **已完成** → §7.6 |
| WSL 靶场侧脚本重跑 | 原：未跑 | **已跑通**：5/5 与 7/7 → §7.7 |

---

## 7. 补完轮（把 §6 的未完成项做完）

起点 `c19f515` → 本轮 6 个提交（见文末）。**每个都先复现/验证再改，并补回归测试。**

测试：**786 passed, 1 skipped**；`ruff check src tests tools`：All checks passed。

### 7.1 报表工作区（筛选 / 详情 / 导出 / 跨运行对比）

前端仍是一份内联 HTML/CSS/JS，**没有引入构建链或新依赖**。

* `GET /api/findings?run=current|<目录名>`：本次运行读内存，历史运行从
  `snapshot.json` → `surface.json` 读回（都没有才是 404——"没留下发现"与"读不出来"是两件事）；
* `GET /api/export?run=...&format=json|markdown`：导出**发现清单**（附件下载），
  格式与来源可预测；Markdown 把"已复核"与"待复核候选"分开，并写明候选项不是确认漏洞、
  未列出的位置不代表安全。**完整报告仍走另一个入口**（查看完整报告 / `/api/history/<run>`）；
* `GET /api/compare?with=<目录名>`：复用 `diff.diff_findings`，界面明确区分
  "本次新增 / 仍存在 / 疑似已修复 / 无法判定"，并写明"没测到的一律进无法判定，
  不能说成已修复"；
* 前端：状态/等级/关键词筛选 + "显示 N / 共 M 条" + 点击卡片出详情面板 +
  导出链接跟随选中运行 + 对比结果四分组。

### 7.2 表单型（POST）XSS 验证

`observe()` 增加 `method="POST"`：在**首次导航**上做请求改写
（`route.continue_(method="POST", post_data=...)`），把 `page.goto()` 的 GET 换成表单 POST——
这是浏览器里唯一能"让服务端处理一次 POST 并把响应渲染出来"的做法。
`verify_xss(..., method="POST", fields={...})` 会带上真实表单需要的其它字段
（csrf/用户名…），基线用同样字段、只把注入字段置空；**POST 必须给 `param`**，
否则工具直接报错说清缺什么，而不是给一个看着像结论的 `absent`。

实测（本地临时测试页 + 真实浏览器）：`/form-echo` → executed；
`/form-textarea` → dom（不误判执行）；`/form-get-only` → 405 且非 executed
（证明 POST 真的发出去了）；`fields` 里的其它字段确实到达服务端。

### 7.3 覆盖率表里的"假端点"（数据卫生）

**先复现**：本地临时测试页跑 `enumerate_common` → `BUG PRESENT: True`，
`http://127.0.0.1:5012/admin（受保护，值得进一步探测）` 被登记成端点与探测路径。

根因比"后缀没剥掉"更基础：该工具把自己**给人看的命中文本**用 `split("  ")[-1]`
反解回 URL——展示与数据共用一个字符串。带内容特征的命中更糟：`[-1]` 取到的是
`特征: <title>…` 整段文字。

修法两层：① 命中记录改成 `(展示文本, 真实 URL)` 成对保存；
② 攻面入口新增 `looks_like_url()`，`add_endpoint` / `add_extra_paths` /
`normalize_endpoint` 一律拒绝含空白、控制字符或全角括号的"人话"（合法 URL 与
百分号编码路径不受影响）。修复后同一复现：`BUG PRESENT: False`。

### 7.4 CI：能把"编排写错"提前到本地发现

`tools/check_ci_workflow.py` 固化可确定的检查：工作流可解析、每个作业有 `runs-on`、
步骤里引用的仓库文件存在、`pip extras` 在 pyproject 里真的有定义、
`HEXHOUND_*` 环境变量代码里真的有人读。当前 26 项检查全过。

**静态校验只能查引用**；"作业里的命令到底跑不跑得通"由 `tools/run_ci_locally.py`
真跑（见 §8——它第一次运行就抓出了 5 个会 CI 变红的问题）。

**依然未验证**：GitHub runner 上的真实执行（跑一次才知道）。工具输出里明写了
"不能替代真跑一次 CI"，避免被当成"CI 已验过"。

### 7.5 桌面版窗口肉眼验收（含一处澄清）

用 `PrintWindow(PW_RENDERFULLCONTENT)` 抓**打包后 exe 的真实窗口**：原生标题栏
"HexHound"、无浏览器地址栏/标签页、内容即控制台；整屏 BitBlt 另抓一张，确认窗口
此刻被前台浏览器遮挡——所以 PrintWindow 才是对的方法。

窗口画面右缘**看似被切**，按窗口实际尺寸（1281×780）渲染同一页面复核：
水平溢出 **0px**、4 张指标卡全部完整可见 ⇒ 是 WebView2 在 PrintWindow 下合成不全的
**截图假象，不是布局问题**。为把这类"看起来像 bug"的东西固定下来，前端测试新增断言：
提示条（fixed 定位）必须在视口内。

逐页看图：工作台 / 报告 / 视觉分析 / 设置弹窗 / 390px 移动版均正常。
看图时发现并修掉一处**过期文案**：设置弹窗还写着"密钥以明文保存在本机"。

### 7.6 密钥落盘加密（Windows DPAPI）

新增 `src/hexhound/secretstore.py`：`CryptProtectData`（用户级、ctypes、零新依赖），
密文以 `dpapi:` 前缀存回 `provider_keys` 字段；非 Windows 平台**不假装加密**并说明原因。

三条硬约束都有测试：迁移不丢密钥（旧明文照读，下次保存自动转密文）、
换机器/换用户解不开时**明确报错并给出原因**（绝不静默当成"没配过"）、
调用方语义不变（读出来/写进去仍是字符串）。已是密文不重复加密。

### 7.7 WSL 靶场脚本重跑

```
verify_lab_new_vulns.sh      → 5 项符合预期，0 项异常（竞态 ×2 + 认证实现 ×3）
verify_lab_business_logic.sh → 7 项成立，0 项异常（价格篡改/负数数量/跳过步骤/重复提交/状态一致性）
```
两个脚本都是纯 HTTP，不调用模型、不消耗额度；只改本地靶场内存状态并在结束前重置。

---

## 8. CI 真的跑起来了（本机执行器，不依赖 GitHub）

§6/§7.4 一直留着一条"CI 未在 runner 上真跑过"。用户的要求是"没有 runner 就下载一个"——
于是先试了标准答案，再落到能真正给出结论的方案上。

### 8.1 试过的两条路（以及为什么第一条不通）

1. **自托管 GitHub runner（`actions/runner`）**：需要绑定一个 GitHub 仓库 + 注册令牌。
   本仓库**没有 git remote**、机器上没有 `gh`、没有 `GITHUB_TOKEN`——
   没有可绑定的目标，也没法在不经过用户登录的情况下创建。
   （这是唯一能验证"GitHub 自己的编排"的方式，需要用户提供仓库与凭据。）
2. **`act`（本机执行 GitHub Actions）**：在 WSL 里装了 Docker 29.1.3 + act 0.2.89，
   拉下了 runner 镜像（2.3GB，走国内镜像站），`act -l` 能正确识别 5 个作业。
   但本机网络**大文件传输会中途卡死**（pypi 索引 46MB 传到 173KB 就停、
   `actions/setup-python` 下载 Python 卡住十几分钟不动）。act 因此无法跑完任何作业。

### 8.2 落地方案：`tools/run_ci_locally.py`

直接按 `.github/workflows/ci.yml` **在匹配的操作系统上执行每一步**：
Linux 作业在 WSL 的真 Ubuntu 24.04 里跑，windows 作业在 Windows 上跑；
`env:`（含把 key 清空那几条）照搬；平台不匹配的作业**拒绝执行**（跑了只会给出误导性结果）。
两处刻意与 CI 保持一致的处理：

* 仓库根目录的 `.env` 在跑作业时**临时移开**（GitHub 上没有这个文件，它是 gitignored），
  否则 `self-check` 里那句 `grep "还没有选择模型提供商"` 会因为本机 `.env`
  推出了提供商而假失败；结束时无论成败都会恢复；
* `uses:` 步骤（checkout / setup-python）跳过并打印出来——本地已在仓库里、
  解释器已就位，对应 runner 上由 action 提供的那部分。

### 8.3 结果：矩阵全绿（本机）

| 作业 | 平台 | 结果 |
| --- | --- | --- |
| lint | ubuntu（WSL 24.04） | **通过** |
| self-check | ubuntu | **通过** |
| gui（真实浏览器层） | ubuntu | **通过** |
| test（ubuntu / py3.12） | ubuntu | **通过** |
| desktop（构建 + PE 校验 + 启动验收 21 项） | windows | **通过** |
| test（windows / py3.12） | windows | **通过** |
| test（windows / py3.11） | windows | **通过** |
| test（ubuntu / py3.11） | — | **未跑**：Ubuntu 24.04 仓库里没有 python3.11，需要外部解释器 |

**仍然不等价于 GitHub**：runner 镜像的预装工具、权限、缓存、网络都不同。
但"作业里的每条命令在干净的对应系统上能跑通"这件事，现在有实测而不是推断。

### 8.4 这一轮 CI 真实跑出来的 5 个问题（都已修）

1. **新测试文件在收集阶段就 ERROR**：`test_enumerate_hygiene.py` 依赖 werkzeug、
   两个 GUI 测试文件依赖 flask，而 flask 属于 `[lab]` extra——
   `test` 作业只装 `[dev]`，于是在 GitHub 上会**整个作业变红**（收集期报错）。
   修法：枚举工具测试改用标准库 `http.server`（不再依赖 flask）；
   GUI 测试在**收集阶段**判断依赖，缺了就跳过（`HEXHOUND_REQUIRE_GUI=1` 时失败）。
2. **替身 flask 泄漏到别的测试文件**：`test_gui_state.py` 在缺 flask 时把
   `Flask = object` 的假模块塞进 `sys.modules`，于是 `test_providers` 的界面用例
   `import flask` 成功、`Flask(__name__)` 抛 `TypeError`——本该 12 个 skip 变成 12 个 ERROR。
   修法：给替身打标记（`__hexhound_flask_stub__`），依赖检查同时辨认"真身还是替身"
   （提取到 `tests/_gui_deps.py` 共用）。
3. **写死 `channel="msedge"`**：靶场层测试在 Linux 上必然
   `Chromium distribution 'msedge' is not found`；只要靶场在跑就会挂整层。
   修法：探测可用频道（自带 chromium → msedge → chrome）。
4. **DPAPI 断言在 Linux 上不成立**：我上一轮写的"文件里不能出现明文"只在 Windows 成立。
   修法：按平台**分别断言**（Windows 要求密文；非 Windows 明确断言"如实明文 + 给出原因"），
   而不是让断言在别的平台上无声消失。
5. **CI 步骤依赖 Git 的 coreutils**：`python -m pytest -q -rs 2>&1 | tail -20`
   里的 `tail` 在 GitHub 的 windows runner 上恰好存在（Git for Windows 在 PATH），
   其它 Windows 环境没有。修法：去掉管道，直接 `pytest -q -rs`。


