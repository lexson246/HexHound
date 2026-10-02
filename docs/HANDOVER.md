# HexHound — handover to Codex

> **⚠ 本文件描述的是 `8cb2843` 基线。** 基线之后已经落地了两轮工作。
> 阅读顺序：**[`docs/WORK-REPORT-ROUND3.md`](WORK-REPORT-ROUND3.md)**（最新：四个 P0 缺陷的
> 修复与证据、桌面端验收、预算护栏与任务历史、报表工作区、POST 表单型 XSS、
> 密钥 DPAPI 落盘加密、CI 门禁；**§6 是"未完成事项"清单、§7 是补完记录**）→
> [`docs/WORK-REPORT-ROUND2.md`](WORK-REPORT-ROUND2.md)（新增的 7 个模块、每项行为变化的
> 验证方式、7 个真实运行暴露的缺陷、明确未达成的事项）。
> 下面的内容仍然有效（架构、约束、陷阱、验证协议），但有三处已过时：
>
> 1. §0 第 1 条说"这不是 git 仓库"——**已过时**，现在是 git 仓库，
>    基线提交 `8cb2843`，round 2 结束于 `847c166`，round 3 见 ROUND3 报告。
>    **不要修改或覆盖基线提交。**
> 2. §7 表格里"whatweb 乱码 / `sandbox_script` 静默失败"两条——**已修复**，
>    见 `docs/WORK-REPORT-ROUND2.md` §3。
> 3. §9 的实测数字是 2026-09-20 的快照（254 passed）。**测试数字请以实际运行为准**
>    （`python -m pytest`，当前 786 passed / 1 skipped），不要引用本文里的 254。
>
> 另有三处**行为约定**在 round 3 变了，读旧文档时要留意：
> 本机控制面要求会话令牌与 Host/Origin 校验；`/api/providers` 不再回传明文密钥
> （Windows 上密钥以 DPAPI 加密落盘）；浏览器 XSS 验证默认载荷带**随机标记值**，
> 执行证据必须与本次标记相符。


Audience: an AI coding agent picking this repo up cold. Everything below was verified on
2026-09-20 in this working copy; where something is *not* verified, it says so explicitly.

Working copy: `C:\Users\LeXSon\Documents\ChatGPT\HexHound 2` (Windows 11 host, Python 3.12.10,
`hexhound` installed editable). Line counts and test counts in this document were measured, not
remembered.

---

## 0. Six things that will bite you first

1. ~~**This is not a git repository.**~~ **已过时 —— 现在是 git 仓库。**
   `git log --oneline` 从 `8cb2843 chore: capture project handover baseline` 开始，
   之后是本轮的工作提交。**基线提交不可修改/覆盖**；每个阶段一个提交，
   便于逐条回滚。`.gitignore` 仍然正确（忽略 `.env`、`reports/`、`build/`、`dist/`、`*.db`），
   并新增了 `.gitattributes` 统一行尾（见 `WORK-REPORT-ROUND2.md` §3）。
   —— 除此之外本文其它内容仍然适用于当前代码，但**测试数字已变**（见文首提示）。
2. **`.env` contains a live LLM API key** and the production target allowlist
   (`ALLOWED_HOSTS=lingdayun.cn,127.0.0.1,localhost`). Never print it, never commit it, never
   widen `ALLOWED_HOSTS` without the user asking.
3. **The Windows registry has a system proxy** (`http://127.0.0.1:7892`) and *no* proxy env vars.
   `httpx` defaults to `trust_env=True` and reads that registry setting, which silently sends every
   request to the proxy and returns **502 for every target**. This is already fixed in
   `tools._proxy_kwargs()` — **do not remove it**, and if you add a new HTTP client for target
   traffic, pass `trust_env=False`.
4. **`sandbox_script` launches a script through `python3 -c "<one line>"`.** The launcher must
   contain **no newline** — newlines survive `json.dumps` + bash as a literal `\n` and `python3 -c`
   does not interpret that escape, so every call dies with `SyntaxError` (this wasted an entire
   implementation round). Payload goes in base64. There is a self-check and a test for this; keep both.
5. **The lab runs inside WSL** (`Ubuntu-24.04`, `/opt/hexhound-lab`), while HexHound itself runs on
   Windows. The WSL2 localhost relay occasionally answers 502; the app never logs those. Restart the
   lab with `tools/start_lab_in_wsl.sh` (it kills by *port*, not just by command line) and prefer
   `hexhound sandbox lab` or the WSL IP if you see it.
6. **"Not tested" is never reported as "fixed."** This is the single most important product
   invariant, enforced in `diff.py` and locked by tests. If you touch the diff, coverage gate or
   reporting, read §6 and keep it true.

---

## 1. What this project is

An AI-driven vulnerability-hunting agent for **authorized** black-box web assessment. It is not a
scanner: an LLM orchestrator decomposes the engagement, role-scoped sub-agents (recon / injection /
auth / verify) run concurrently against a shared attack-surface model, and only findings whose
evidence has been *replayed* reach the conclusion section.

Honest capability statement (also in `README.md`, keep it honest when you change things):

| Works | Does not work |
| --- | --- |
| Injection classes with real tool proof (sqlmap), path traversal, SSRF, SSTI, IDOR/missing auth, secret leaks, JWT/`alg=none` forging, race conditions on check-then-act endpoints | Business logic that needs *your* domain invariants, narrow race windows, race conditions in production under real timing, crypto flaws beyond "leaked secret / algorithm confusion / predictable token" (no padding-oracle, weak-RNG, timing work) |
| Evidence with reproducible commands + `T`-numbered tool executions | XSS beyond "the string is reflected verbatim" — **no browser execution** |
| Two-layer coverage (endpoints *and* parameters) with blind-spot sections | Guarantees of any kind: `nuclei` 0 hits ≠ safe (public templates only) |

Docs already in the repo:
- `README.md` — English, user-facing, contains the measured numbers.
- `README_ZH.md` — the Chinese twin; keep the two in sync when you change behaviour.
- `docs/optimization-plan.md` — the design record: what was copied from Strix/PentAGI and why, plus
  every bug found by live runs (including the four that took the race/JWT features from "written" to
  "actually works").
- `docs/reference-architecture.md`, `docs/research-notes/strix-brief.md`,
  `docs/research-notes/pentagi-brief.md` — source-level research on the two reference projects
  (what they do, what they lack, what was deliberately *not* copied).

---

## 2. Repo map

Package root `src/hexhound/` (line counts measured):

| Module | Lines | Role |
| --- | --- | --- |
| `orchestrator.py` | 1276 | Planning, wave execution, worker supervision, coverage gates, **deterministic special-class task dispatch** (`special_class_tasks`), aggregation |
| `tools.py` | 2589 | All tools + role allowlists (`ROLE_TOOLS`), request cache, output governor, evidence recording, `sandbox_script` tool |
| `sandbox.py` | 1315 | Docker/Podman/WSL detection, scope enforcement, loopback mapping, tool wrappers, **script channel** (static scan + in-process runtime guard) |
| `surface.py` | 774 | Shared `AttackSurface`: endpoints/params/attempts/findings/candidates/coverage, `touched_endpoints`, `reported_endpoints`, `unattacked_params` |
| `report.py` | 519 | Markdown + JSON report, diff section, coverage/blind-spot sections, tool-evidence appendix |
| `memory.py` | 533 | Per-host JSON memory (cross-run), run artifacts, PoC writer, task ledger, `forget()` |
| `knowledge.py` | 627 | Path wordlists (`PATH_TIERS`: core/leak/admin/framework/api/**business**), payloads, PII patterns, OWASP mapping |
| `cli.py` | 1048 | `audit/report/providers/sandbox/memory/setup/gui` commands |
| `gui.py` | 1226 | Flask GUI (settings panel, live run view) |
| `prompts.py` | 191 | Role prompts incl. the race/business-logic/crypto playbooks |
| `agent.py` | 349 | ReAct loop, budget hooks, layered context compression, `AgentResult` |
| `diff.py` | 249 | Cross-run classification (new/persisting/fixed/unknown) — see §6 |
| `budget.py`, `llm.py`, `providers.py`, `config.py` | 210/233/287/356 | Budget bands, LLM client + per-role pool, 12 provider presets, env config |
| `dedupe.py`, `butian.py`, `submission.py` | 111/126/94 | Fingerprinting, Butian submission fields, package export |
| `browser.py`, `screenshot.py`, `vision.py`, `login.py` | 69/59/37/76 | Playwright/vision/manual-login extras (optional deps) |
| `desktop.py`, `console.py`, `mockllm.py` | 102/34/386 | Desktop entry, GBK-safe console markers, scripted LLM for tests/demos |

Other places that matter:

- `tests/` — 15 files, **254 tests**, all passing. `python -m pytest` from the repo root.
- `tools/` — dev/probe scripts (see §8). Several were written specifically to *disprove* my own
  claims; keep them working.
- `vulnlab/` — deliberately vulnerable Flask lab (13 classes). `vulnlab/app.py` docstring is the
  authoritative inventory; `secret.txt`, `.env.demo`, `static/app.js` exist to be leaked.
- `packaging/hexhound_cli.py`, `packaging/hexhound_desktop.py` — PyInstaller entry shims (absolute
  imports; the package-relative import breaks frozen builds).
- `HexHound.spec`, `HexHound-desktop.spec`, `build_desktop.bat`, `hexhound.exe` (47.5 MB, prebuilt CLI).

---

## 3. Run it

```powershell
# one-time
pip install -e ".[lab,dev]"          # flask for the lab/GUI, pytest+ruff+pyinstaller

# configure (nothing is pre-filled by design)
hexhound setup                        # wizard, writes .env
hexhound providers                    # list the 12 presets + which keys are configured
hexhound providers --test             # one minimal request per configured provider

# the lab, inside WSL (the sandbox backend lives there)
wsl -d Ubuntu-24.04 -u root -- bash /mnt/c/Users/LeXSon/Documents/ChatGPT/HexHound\ 2/tools/start_lab_in_wsl.sh
hexhound sandbox status               # runtime + installed tools (sqlmap/nmap/nuclei/ffuf/…)

# a real engagement (measured: ¥0.20–0.60, 2–6 min)
hexhound audit --target http://127.0.0.1:5000 --mode blackbox `
  --max-tasks 4 --task-steps 12 --parallel 3 --max-cost 1.2 --output reports/lab.md

# tests
python -m pytest                      # must print "254 passed"
python examples/tool_selftest.py      # 31 detection checks, no API key needed
python examples/swarm_demo.py         # full orchestration with a scripted LLM (SWARM_MOCK=1)

# rebuild the CLI exe after code changes
python -m PyInstaller --noconfirm --clean HexHound.spec
Copy-Item dist\hexhound.exe .\hexhound.exe -Force
```

`audit` flags that matter: `--mode source|blackbox`, `--single` (v0.1 single agent),
`--sandbox/--no-sandbox`, `--sandbox-map-loopback` (**only** when the target runs on the host and
the sandbox is elsewhere — not needed when the lab is in WSL), `--coverage-sweep/--no-coverage-sweep`
(disabling it skips sweep waves but *not* the special-class tasks), `--role-model role=model`,
`--fail-on LEVEL` (exit code 2 for CI).

Artifacts land in `~/.hexhound/`:
`runs/<host>-<timestamp>/{surface.json,tasks.json,run.json,poc/}` and `memory/<host>.json`.
`HEXHOUND_HOME` overrides the root (the test suite uses this).

---

## 4. Architecture in one screen

```
plan (LLM, no tools)
  └─ deterministic bias: parameters but no injection task → append one naming sqlmap_scan
wave 1  plan tasks            recon / injection / auth, parallel, each with its own step budget
wave 2  follow-up tasks       new endpoints handed to injection/auth
wave 2b special-class tasks   S1 race (state-changing endpoints) + K1 credential forging
                              (protected endpoint + leak source) — dispatched deterministically
wave 3  endpoint sweep        endpoints nobody touched
wave 4  parameter sweep       (endpoint,param) never attacked — up to 2 rounds, only if progress
wave 5  verification          replay each candidate's evidence; promote or kill
aggregate → dedupe → coverage gate → report → memory record
```

Core concepts you must keep straight:

- **Attack surface** (`surface.py`) is the shared truth: endpoints, params, forms, tech, `attempts`
  (dedup key = endpoint+param+category+payload), candidates, verified findings, coverage records
  (`reported` / `no_issue_found` / `ruled_out` / `not_tested` / `blocked`).
- **Evidence namespaces**: `R` = HTTP exchange, `C` = code excerpt, `T` = real-tool/script execution,
  `S` = screenshot. Findings reference these ids; ids that do not exist are **rejected**
  (`tools._pick_tool_evidence`). Tool evidence is `W<worker>-T<n>`; the report appendix renders
  exactly those ids (not the sandbox-internal `X<n>` log) so a reviewer can look up any reference.
- **Verification gate**: `record_finding` without a valid `evidence_ref` lands in the *candidate*
  pool, never in the conclusions. Wave 5 replays and promotes.
- **Dedupe** = `(vuln class, normalized path, param)` with a coarse fallback — used both for merging
  and for the cross-run diff.
- **Special-class dispatch** (`orchestrator.special_class_tasks`) exists because prompt guidance
  alone failed: recon *found* the leads and wrote them in notes, and nothing acted on them. It fires
  only when the script channel is usable (`_sandbox_script_ready`), and it keys off the surface, so
  **endpoint discovery directly controls whether race/forging tests happen at all** (see §7 item 3).

---

## 5. The script channel (`sandbox_script`) — how to extend it safely

Purpose: race conditions, multi-step business logic and crypto/auth forging cannot be expressed as a
single tool call. `injection`, `auth` and `verify` roles get a Python channel (≤20 KB) that runs in
the sandbox.

Enforcement is **two layers** — keep both:

1. **Static** (`Sandbox.check_script`): extracts URLs, bare IPv4/IPv6 and quoted domains from the
   script text and validates them against `ALLOWED_HOSTS`; rejects destructive patterns
   (`rm -rf`, `shutil.rmtree`, `os.remove`, `mkfs`, `dd if=`, reverse shells, `subprocess`,
   `os.system`, `os.popen`, `pty.spawn`, `crontab`, `authorized_keys`). Oversize scripts (>20 000
   chars) are refused.
2. **Runtime guard** (`sandbox._SCRIPT_GUARD`, prepended to the payload): hijacks
   `socket.getaddrinfo` and `socket.socket.connect` inside the process, so a host built by string
   concatenation / base64 / f-string is refused *before* any packet leaves. Verified live:

   ```
   socket.create_connection(("ev" + "il.com", 80))
   → RuntimeError [hexhound-scope] refused to connect non-allowlisted host: evil.com
   ```

The guard's allowlist is built **after** loopback mapping, so scripts may keep writing
`http://127.0.0.1:5000` while running in a different network namespace. This is a Python-level guard
plus a container — it is scope discipline, not a security boundary; say so if you document it.

Probe it yourself after any change here: `python tools/probe_script_channel.py` (runs a normal
script and the concatenation bypass attempt).

---

## 6. Invariants you must not break (each has a test)

| Invariant | Where | Locked by |
| --- | --- | --- |
| Every target host is validated against `ALLOWED_HOSTS` before execution, in code | `sandbox.check_scope`, `check_script`, `tools._validate_url` | `tests/test_sandbox.py`, `tests/test_sandbox_script.py` |
| Loopback mapping happens **after** scope validation | `sandbox._execute` | `test_loopback_mapping_*` |
| `python3` commands are not scanned for bare domains (dotted identifiers are not hosts) | `sandbox.check_scope` | `test_python3_dotted_identifiers_are_not_hosts` |
| Target HTTP ignores ambient/registry proxies; opt-in only via `HEXHOUND_HTTP_PROXY` | `tools._proxy_kwargs` | `test_send_disables_env_proxy_by_default` |
| The script launcher contains no newline | `sandbox.run_script` | `test_launcher_is_single_line` |
| A finding without valid evidence stays a candidate | `tools._record_finding` | `tests/test_tools_gates.py` |
| Dedup merges same root cause; merge count recorded | `dedupe.py` | `tests/test_surface.py` |
| **Not tested ≠ fixed**; a previous finding is `fixed` only when the endpoint was retested *and* nothing is reported there now; `reported` coverage counts as "still affected"; `not_tested`/`blocked` never count as coverage | `diff.diff_findings`, `surface.touched_endpoints`, `surface.reported_endpoints`, `report.build_diff` | `tests/test_diff.py` |
| Coverage is two-layer; blind spots are printed, never omitted | `orchestrator.coverage_gate`, `report.to_markdown` | `tests/test_orchestrator.py` |
| Race tasks use two different inputs for baseline vs burst | `orchestrator.special_class_tasks` | `test_race_objective_forbids_reusing_the_one_shot_input` |
| The report appendix renders the same ids findings cite (as ```python for scripts) | `report._tool_command_block`, `orchestrator._aggregate` | `tests/test_report_new.py` |

---

## 7. Traps, with symptoms and fixes (all reproduced this session)

| Symptom | Cause | Fix / status |
| --- | --- | --- |
| Every endpoint recorded `status=502`, findings collapse, agents fall back to `curl` | httpx `trust_env=True` + **Windows registry** system proxy (`127.0.0.1:7892`); env vars are empty so it looks impossible. Proof: `trust_env=True → 502`, `False → 200` | Fixed in `tools._proxy_kwargs`; LLM calls intentionally unaffected |
| `sandbox_script` always `SyntaxError: unexpected character after line continuation character` | multi-line launcher + `json.dumps` + bash → literal `\n` | Fixed: one-line launcher, base64 payload to a temp file, self-check + test |
| Race test concludes "no race" | task said "serial first, then concurrent"; the serial call **consumed** the single-use coupon | Fixed: objective requires two different inputs; test asserts the wording |
| Race task never dispatched at all | `/coupon` was never in the surface — the generic wordlist had no state-changing vocabulary and reading `app.js` did not register what it contained | Fixed: `business` path tier (77 paths, on by default) + `read_urls` harvests paths from JS/HTML (`_harvest_endpoints`) |
| Lab appears to run old code after editing it | old instance started as `python3 app.py` (relative), so `pkill -f /opt/hexhound-lab/app.py` missed it and it kept the port | `start_lab_in_wsl.sh` now kills by port (`fuser -k 5000/tcp`) and warns if the port is still busy |
| Intermittent 502 from the target although the app logs nothing | WSL2 localhost relay, typically stale right after restarting the lab | Use `hexhound sandbox lab`, the WSL IP, or restart the lab; documented in README |
| `web_fingerprint` (`whatweb`) returns mojibake in WSL; sqlmap output contains raw ANSI escapes (`[?1049h`) | no UTF-8/ANSI normalisation of sandbox stdout | **Open bug — good first task.** Strip ANSI in `sandbox._clip`/`ExecResult.output`, and force UTF-8 decoding |
| Sub-agents keep hitting step caps (`未收尾`) | broad targets + 12-step budgets; S1/K1 tasks often produce their finding but never reach `finish_task` | Partly expected (unfinished ≠ no output, and it is reported as such). Raising `TASK_STEPS` for special tasks is a cheap improvement |
| Console `UnicodeEncodeError` on `✓` | GBK console | `console.py` + ASCII markers `[OK]/[!!]/[XX]/[--]`; keep using them |
| Frozen build crashes with `attempted relative import` | PyInstaller + package-relative import | `packaging/hexhound_cli.py` shim; keep entry points absolute |
| Tests overwrite the developer's real `.env` | `config` calls `load_dotenv()` at import | `tests/conftest.py` stubs `dotenv.load_dotenv` and chdirs to a temp dir; root `conftest.py` anchors collection. Do not "simplify" either file |

Environment facts: Docker Desktop is installed but **broken** on this machine and the user is not
admin, so the working backend is **WSL Ubuntu-24.04** (root, tools installed). WSL does not read the
Windows hosts file, and `web_fetch` refuses non-public IPs — that is why some early research went
through mirrors.

---

## 8. Verification protocol — do this for every non-trivial change

```powershell
python -m pytest                                   # 254 passed, ~7 s
python examples/tool_selftest.py                   # 31 detection checks, no key needed
python tools/probe_script_channel.py               # script channel + runtime guard
wsl -d Ubuntu-24.04 -u root -- bash /mnt/c/.../tools/verify_lab_new_vulns.sh   # lab vulns 5/5
```

For a change that affects detection, orchestration, coverage or reporting, **run the agent against
the lab and read the artifacts**, do not trust the summary line:

```powershell
hexhound audit --target http://127.0.0.1:5000 --mode blackbox `
  --max-tasks 4 --task-steps 12 --parallel 3 --max-cost 1.2 --output reports/check.md
```

Then check, using the tools in `tools/` (they exist because reading a 200 KB report by eye hides
exactly the failures that matter):

| Script | What it answers |
| --- | --- |
| `tools/list_report_evidence.py` | Which `T`-id evidence the appendix contains, and with which tool label |
| `tools/check_evidence_ids.py reports/x.md W5-T8` | Does an id cited by a finding actually exist in the appendix, with its script and output? |
| `tools/inspect_task_steps.py reports/x.md S1` | Step-by-step trace of one sub-task — the fastest way to see *why* a role failed |
| `tools/inspect_finding_evidence.py` | Evidence chain of one finding |
| `tools/diff_ab_check.py <run-dir>` | A/B the old vs new diff verdicts on real data (this is how the false "possibly fixed" entries were proven: 8 → 0) |
| `tools/probe_script_channel.py` | Script channel + scope guard, including the concatenation bypass |

Expected anatomy of a good run against the lab: 7–11 verified findings, `reports/*.md` with an
endpoint-coverage line, a parameter-coverage line, a diff section, and an appendix whose ids match
the findings. A run that reports "0 findings, 100% coverage" is almost always a broken HTTP path —
check the proxy first.

---

## 9. Measured state (2026-09-20, this machine)

- Tests: **254 passed**.
- Lab: 13 vulnerability classes; `tools/verify_lab_new_vulns.sh` reproduces the three advanced ones
  **5/5** without HexHound in the loop (coupon race 6/6 concurrent successes; one reset token → 6
  sessions; no token 401 / `role=user` 403 / leaked-secret HS256 admin token 200 / `alg=none` 200).
- Best live run against the lab: **11 verified findings** including
  `/coupon` TOCTOU (serial `#1 +100`, `#2 409`; `Barrier(N=10)` → 10/10 succeed, balance 0 → 1000,
  `409` afterwards; evidence `W5-T8`/`W5-T9`) and the leaked-JWT admin forgery (`alg=none` too).
- Cost/time: ¥0.20–0.60 and 2–6 min per run at `--max-tasks 4 --task-steps 12 --parallel 3`; a run
  with the full two-round sweeps took 20 min / ¥0.60.
- Sandbox: WSL Ubuntu-24.04 with sqlmap/nmap/nuclei/ffuf/gobuster/nikto/whatweb/curl/python3.
  nuclei default category set ≈ 930 templates / ~66 s and gets **0 hits on the lab** (documented;
  full set 4488 templates / 146 s). `requests` *is* available to sandbox scripts.
- Production target `lingdayun.cn`: 0 verified findings, 0 false positives on the runs performed —
  i.e. the tool currently proves nothing on that target; treat it as "unknown", not "clean".
- Hindsight memory tools are **401 in this environment** (no API token). Do not rely on them; the
  durable knowledge lives in `docs/`.

---

## 10. Known gaps and tech debt (ranked)

1. **No version control.** Fix first.
2. **ANSI/encoding garbage** in sandbox output (`whatweb` mojibake, sqlmap escape codes). Cheap,
   self-contained, immediately improves report quality and model comprehension.
3. **Special tasks frequently hit their step cap** and thus never call `finish_task` (findings still
   land). Give S1/K1 a slightly larger budget or an explicit "record then finish" micro-protocol.
4. **Run length is unbounded** when sweeps keep making progress: two rounds × (endpoint + parameter
   sweep) can reach 20 minutes. Add a wall-clock guard for sweeps (there is already `MAX_SECONDS`).
5. **Memory noise**: `memory/<host>.json` grows monotonically, and stale entries reappear as
   `unknown` in every diff. `hexhound memory --before/--forget/--reset` exists, but nothing prunes
   automatically or marks entries as resolved.
6. **Business logic has no lab target.** The lab covers races and crypto/auth, not pure state-machine
   abuse (price tampering, step skipping, negative quantities). Adding `/shop`-style endpoints would
   make that playbook testable.
7. **GUI is unverified** in this session (`gui.py`, 1226 lines, plus `desktop.py`); no automated
   coverage. Assume it may be broken and do not claim otherwise.
8. **No CI**: no workflow runs the tests; PyInstaller builds are manual.
9. **XSS stops at string reflection** — a real browser in the sandbox is the only way to change that.
10. **`reports/` is gitignored** but contains the evidence used in this handover; copy anything you
    need into `docs/` if it must survive.

---

## 11. Suggested next tasks (each with an acceptance test)

1. **`git init` + baseline commit** (after confirming `.env` is ignored). Acceptance:
   `git log --oneline` shows one commit; `git status` clean; `.env` untracked.
2. **Sanitise sandbox output**: strip ANSI, decode UTF-8 with replacement in
   `sandbox._clip` / `ExecResult`. Acceptance: a new unit test feeds an ANSI-laden byte string and
   asserts no `\x1b[` survives; a live lab run shows readable `whatweb`/sqlmap output in the report.
3. **Make special tasks converge**: raise their step budget and/or require a closing `finish_task`.
   Acceptance: in a lab run, `S1`/`K1` end with outcome `done` (not `max_steps`) in the ledger while
   still producing their findings.
4. **Bound sweep runtime** with a wall-clock check between rounds. Acceptance: a test drives the
   gate with a stub clock and asserts no third round starts past the cap; a live run with
   `--max-seconds 300` finishes within ~1.2×.
5. **Lab business-logic endpoints** (`/cart`, `/order/confirm` with client-supplied price and a
   skippable step). Acceptance: extend `tools/verify_lab_new_vulns.sh` to reproduce each one by hand
   (no HexHound in the loop), then a live run finds at least one of them.
6. **Auto-prune/annotate memory** so stale entries stop polluting the diff. Acceptance:
   `tests/test_diff.py` gains a case where a resolved entry no longer appears; `hexhound memory`
   reports what was pruned.

When you finish any of these: update `README.md` **and** `README_ZH.md` in the same change, keep the
"measured, not claimed" tone, and re-run §8.

---

## 12. Do-not-do list

- Do not widen `ALLOWED_HOSTS`, remove scope checks, or bypass `ScopeViolation` "to make a test pass".
- Do not let target traffic use ambient proxies again (see §0.3).
- Do not weaken the read-only contract: no data modification on targets, no webshells, no reverse
  shells, no exploitation beyond proof. `FORBIDDEN_ARGS` and `FORBIDDEN_SCRIPT_PATTERNS` exist for
  this; adding an exception requires the user's explicit approval.
- Do not remove `if "\n" in launcher` self-checks or the "two different inputs" wording in the race
  objective — both encode bugs that cost whole implementation rounds.
- Do not report "fixed" for anything that was merely not retested; that is the invariant the whole
  diff feature exists to protect.
- Do not print or commit `.env`, and do not send target traffic to hosts outside the allowlist, even
  "just to check connectivity".

---

## 13. Round 4 (2026-10-02) — external review P1–P7, current state

Full detail: `docs/WORK-REPORT-ROUND4.md`. Commits `a255248` (fixes) + `6d23f08` (regressions).

- Tests: **952 passed, 10 skipped**; `ruff check src tests tools` clean.
  Skips are "no playwright browser in this environment" and DPAPI-only cases.
- Fixed, each reproduced first:
  - **P1 desktop never wired the scan environment** — CLI and desktop each had their own
    sandbox-preparation copy and the recorded reason was a constant string, so "installed but
    unused" was undiagnosable. Now one `sandbox.prepare_sandbox()` for both, and the concrete
    reason/hint reaches `run.json`, the report, and the UI.
  - **P2 role prompts advertised tools the role did not have** — static role text ("prefer
    sqlmap_scan", "you must use sandbox_script") vs a dynamically pruned registry. Now
    `prompts.adapt_prompt_to_tools()` drops those bullets and names what is missing. Invariant
    test: a prompt body may not mention a tool the run does not have.
  - **P3 identity was not part of the dedup fingerprint** — `attempt_key` now carries
    method/identity(header hash)/location, and `blocked` (401/403) never counts as "tried".
  - **P4 JSON bodies / PUT / PATCH** — injected into the JSON body; methods preserved.
  - **P5 sqlmap negative verdicts** ("does not seem to be injectable") no longer read as
    "injectable".
  - **P7** `LLM_REASONING_EFFORT` (low/high/max, blank = server default, DeepSeek only), the
    effective request config recorded as a trace `llm_config` event, and per-run tool-failure
    statistics split into `unknown` / `crashed` / `returned` / `budget`.
- Two real isolation bugs found by the new tests and fixed:
  - the browser followed redirects **without** re-entering the route guard, so out-of-scope
    targets (and other ports on the same host — cookies ignore ports) really received requests.
    The `Location` header is now stripped for any redirect we refuse, and the refusal is recorded
    in the observation.
  - a malformed `NO_PROXY` entry (e.g. `[::1]`) made httpx throw while **constructing** a client,
    which broke both `hexhound doctor` and every LLM client. Proxy resolution is now ours
    (loopback and `NO_PROXY` matches go direct).
- Built artifacts (verified this round): `hexhound.exe` (desktop, 21/21 startup checks via
  `tools/verify_desktop_exe.py`) and `dist\hexhound.exe` (CLI).

