"""HexHound 图形化界面（Flask）：可视化配置 + 运行 + 结果展示，并记住上次设置。

运行：hexhound gui  （需要 flask，pip install -e ".[lab]"）
设置持久化在 ~/.hexhound/settings.json，下次打开自动回填。
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import sys
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template_string, request, send_file

from . import history, secretstore
from .agent import ReActAgent
from .budget import Budget, limits_from_config
from .config import (
    ROLES,
    _normalize_host,
    normalize_base_url,
    resolve_provider,
    scope_allows,
    scope_unrestricted,
    write_env_file,
)
from .diff import diff_findings
from .llm import LLMClient
from .login import capture_login_state
from .memory import HostMemory, RunArtifacts
from .orchestrator import (
    Orchestrator,
    SwarmCallbacks,
)
from .providers import (
    ROLE_LABEL,
    describe_presets,
    env_key_name,
    get_preset,
    mask_key,
    pricing_for,
    pricing_known,
)
from .report import write_report
from .runparams import (
    BY_KEY,
    config_from_settings,
    field_specs,
    numeric_defaults,
    parse_fields,
)
from .sandbox import prepare_sandbox, sandbox_report
from .screenshot import capture_url
from .submission import write_butian_package
from .surface import AttackSurface
from .tools import ToolRegistry
from .vision import VisionClient


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "HexHound"
    return Path(__file__).resolve().parents[2]


PROJECT_ROOT = _project_root()
#: 设置文件路径。可用 `HEXHOUND_SETTINGS_PATH` 覆盖——测试/CI 与"打包后验收"
#: 都靠它用临时文件跑，不碰用户真实配置（与 `memory.data_home` 的
#: `HEXHOUND_HOME` 约定一致）。
SETTINGS_PATH = Path(
    os.getenv("HEXHOUND_SETTINGS_PATH", "").strip()
    or (Path.home() / ".hexhound" / "settings.json")
)

#: 本机控制面只接受这些主机名（见 `create_app` 的请求守卫）。
#:
#: 为什么必须校验 Host：攻击者可以把自己的域名解析到 127.0.0.1（DNS rebinding），
#: 让受害者浏览器"带着攻击者的域名"访问本机端口。此时浏览器认为这是
#: 同源（攻击者域），页面里的脚本就能读走 `/api/providers` 之类的响应。
#: 校验 Host 之后，`Host: evil.com:5001` 的请求会被直接拒绝。
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: 有副作用的本机接口必须携带的会话令牌头（见 `create_app`）。
#:
#: 跨站请求**无法**携带自定义头：浏览器会先发 OPTIONS 预检，而本服务不返回任何
#: CORS 响应头，预检必然失败。所以它同时挡掉 CSRF——否则一个恶意网页就能让本机
#: 去跑一次审计（消耗真实模型额度）、改白名单、写 .env、甚至弹出登录窗口。
TOKEN_HEADER = "X-HexHound-Token"

DEFAULTS = {
    # 刻意留空：不预设提供商/模型/密钥，避免"没注意就按某家付费模型跑起来"。
    # 首次打开时面板会引导选择（或从 .env 读取）。
    "api_key": "",
    "base_url": "",
    "model": "",
    "provider": "",
    "provider_keys": "{}",
    "temperature": "0.2",
    "reasoning_effort": "",
    "role_models": "{}",
    "max_steps": "30",
    "request_timeout": "10",
    "allowed_hosts": "127.0.0.1,localhost",
    "target": "http://127.0.0.1:5000",
    "mode": "blackbox",
    "path": "vulnlab",
    "output": "reports/report.md",
    "zoom": "1.0",
    "auth_a": "",
    "auth_b": "",
    # 多代理编排与预算。
    # 数值字段（含预算上限）的默认值由 `runparams.FIELDS` 统一提供，
    # 避免"界面一处默认值、CLI 另一处默认值"的漂移。
    "max_tasks": "6",
    "task_steps": "10",
    "parallel": "3",
    "max_cost": "0",
    "rate_limit": "0",
    "swarm": "1",
}
#: 合并 `runparams` 的数值字段默认值（键冲突时以 runparams 为准）。
DEFAULTS.update(numeric_defaults())

HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HexHound 控制台</title>
<style>

  :root { color-scheme:dark; --bg:#0d1014; --panel:#14181e; --line:#292e36; --fg:#ecedf0;
    --muted:#949ca9; --accent:#b9ed80; --ok:#b9ed80; --err:#ff8989; --warn:#e9bd77; }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  body { margin:0; color:var(--fg); background:var(--bg); font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif; }
  button,input,select { font:inherit; }
  button,a,input,select,summary { -webkit-tap-highlight-color:transparent; }
  button { cursor:pointer; border:1px solid var(--line); border-radius:8px; padding:10px 15px; background:#20252d; color:var(--fg); font-weight:600; transition:background .15s,border-color .15s; }
  button:hover:not(:disabled) { background:#2c333d; border-color:#596373; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  :focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
  a { color:var(--accent); text-underline-offset:4px; }
  .sidebar { position:fixed; inset:0 auto 0 0; width:218px; padding:30px 18px 20px; border-right:1px solid var(--line); background:#111419; display:flex; flex-direction:column; z-index:5; }
  .brand { display:flex; align-items:center; gap:11px; padding:0 10px; font-size:22px; font-weight:700; letter-spacing:-.8px; }
  .brand-mark { display:grid; place-items:center; width:33px; height:37px; background:var(--accent); color:#172213; clip-path:polygon(50% 0,96% 24%,96% 76%,50% 100%,4% 76%,4% 24%); font-size:23px; font-weight:800; }
  .eyebrow { color:var(--muted); font:10px/1.5 Consolas,monospace; letter-spacing:2px; text-transform:uppercase; }
  .brand-sub { margin:10px 10px 46px; }
  .nav-label { padding:0 13px; margin-bottom:10px; }
  nav { display:grid; gap:7px; }
  .nav-item { width:100%; display:flex; align-items:center; gap:12px; text-align:left; background:transparent; border-color:transparent; color:var(--muted); padding:12px 14px; font-size:13px; }
  .nav-item[aria-current="page"] { background:#232d20; border-color:#36462c; color:var(--accent); }
  .nav-icon { font:18px/1 monospace; width:20px; text-align:center; }
  .side-footer { margin-top:auto; padding:20px 12px 0; border-top:1px solid var(--line); color:var(--muted); font-size:11px; }
  .side-footer strong { display:block; color:#cdd3da; font-size:12px; margin-bottom:5px; font-weight:500; }
  .dot { display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--accent); margin-right:7px; }
  .app { margin-left:218px; }
  .topbar { height:70px; padding:0 36px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--line); color:var(--muted); font-size:12px; }
  .breadcrumb { display:flex; gap:13px; align-items:center; }
  .breadcrumb strong { color:var(--fg); font-weight:500; }
  .local-badge { border:1px solid var(--line); padding:4px 10px; border-radius:6px; font:10px Consolas,monospace; letter-spacing:1px; }
  main { max-width:1600px; margin:auto; padding:32px 36px 42px; }
  .page-heading { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:27px; }
  h1 { font-size:29px; letter-spacing:-1px; line-height:1.4; margin:5px 0 8px; font-weight:600; }
  .page-heading p { color:var(--muted); margin:0; font-size:13px; }
  .heading-index { color:#48523f; font:52px/1 Consolas,monospace; letter-spacing:-4px; white-space:nowrap; flex-shrink:0; }
  .metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); border:1px solid var(--line); border-radius:12px; background:var(--panel); margin-bottom:24px; overflow:hidden; }
  .metric { padding:18px 22px; border-right:1px solid var(--line); }
  .metric:last-child { border:0; }
  .metric-label { display:flex; justify-content:space-between; color:var(--muted); font-size:12px; }
  .metric-label span { color:#717c6a; font:12px Consolas,monospace; }
  .metric-value { display:block; font:30px/1.5 Consolas,monospace; letter-spacing:-1px; margin-top:6px; }
  .metric small { color:var(--muted); font-size:11px; }
  #metricFindings { color:var(--accent); }
  .workspace { display:grid; grid-template-columns:330px minmax(0,1fr); gap:22px; align-items:start; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; min-width:0; overflow:hidden; }
  .panel-head { display:flex; align-items:center; justify-content:space-between; padding:17px 20px; border-bottom:1px solid var(--line); gap:10px; }
  h2 { font-size:14px; font-weight:600; margin:0; }
  .section-number { color:#606d59; font:11px Consolas,monospace; margin-right:9px; }
  .panel-body { padding:18px 20px; }
  label { display:block; margin:14px 0 6px; font-size:12px; color:#b6bdc8; }
  label:first-child { margin-top:0; }
  input,select { width:100%; min-width:0; padding:10px 11px; background:#101318; color:var(--fg); border:1px solid #333943; border-radius:7px; font-size:12px; }
  input::placeholder { color:#707986; }
  input:focus,select:focus { border-color:var(--accent); }
  input[type="file"] { padding:24px; border:1px dashed #47533e; background:#171e16; }
  input::file-selector-button { padding:8px 12px; border:1px solid #47533e; border-radius:6px; background:#293623; color:var(--accent); margin-right:12px; cursor:pointer; }
  .row { display:flex; gap:10px; align-items:end; }
  .row > div { flex:1; min-width:0; }
  details { border-top:1px solid var(--line); padding-top:14px; margin-top:18px; }
  summary { cursor:pointer; font-size:12px; color:#c9cfda; }
  .form-actions { border-top:1px solid var(--line); margin-top:20px; padding-top:17px; display:grid; gap:8px; }
  #runBtn { background:var(--accent); border-color:var(--accent); color:#1c2815; }
  #runBtn:hover:not(:disabled) { background:#cef5a5; }
  #stopBtn { color:var(--err); background:transparent; }
  #saveBtn { font-size:12px; }
  .hint,.muted { color:var(--muted); }
  .hint { font-size:11px; margin-top:10px; }
  #status { display:inline-flex; align-items:center; gap:7px; font-size:11px; color:var(--muted); border:1px solid var(--line); padding:3px 9px; border-radius:5px; max-width:70%; overflow-wrap:anywhere; }
  #status::before { content:""; width:5px; height:5px; border-radius:50%; background:currentColor; flex-shrink:0; }
  #status.running,#status.done { color:var(--ok); }
  #status.error { color:var(--err); }
  .log-toolbar { padding:11px 20px; display:flex; align-items:center; justify-content:space-between; background:#11151a; border-bottom:1px solid var(--line); color:var(--muted); font:10px Consolas,monospace; letter-spacing:1px; }
  .log-toolbar label { display:flex; align-items:center; gap:6px; margin:0; font:11px "Segoe UI",sans-serif; }
  .log-toolbar input { width:auto; accent-color:var(--accent); }
  #log { height:440px; overflow:auto; padding:18px 20px; font:12px/1.7 Consolas,"Microsoft YaHei",monospace; overflow-wrap:anywhere; scrollbar-color:#3a424d transparent; }
  .empty-state { min-height:330px; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; padding:28px; }
  .empty-symbol { display:grid; place-items:center; width:72px; height:72px; border:1px solid #35432c; border-radius:20px; background:radial-gradient(circle,#23301c,#151b13); color:var(--accent); font:30px Consolas,monospace; margin-bottom:20px; }
  .empty-state h3 { font:500 16px "Segoe UI","Microsoft YaHei",sans-serif; margin:0 0 9px; color:#dce1e8; }
  .empty-state p { color:var(--muted); font:12px/1.9 "Segoe UI","Microsoft YaHei",sans-serif; margin:0; max-width:330px; }
  .step { padding:12px 13px; border-left:2px solid #576c45; margin-bottom:12px; background:#1a2027; border-radius:0 6px 6px 0; }
  .step .a { color:var(--accent); margin-bottom:4px; }
  .step .t { color:var(--muted); white-space:pre-wrap; }
  .token-footer { padding:13px 20px; border-top:1px solid var(--line); font:10px/1.7 Consolas,"Microsoft YaHei",monospace; color:var(--muted); overflow-wrap:anywhere; }
  .workflow { display:flex; align-items:center; justify-content:space-between; padding:18px 5px; gap:10px; color:var(--muted); font-size:11px; }
  .workflow span { display:flex; gap:7px; align-items:center; }
  .workflow i { color:#718362; font:10px Consolas,monospace; font-style:normal; }
  .workflow b { color:#46503e; font-weight:400; }
  .finding { border:1px solid var(--line); border-left:3px solid var(--warn); padding:16px; margin:12px 0; background:#191d24; border-radius:8px; overflow-wrap:anywhere; }
  .finding b { color:var(--fg); }
  .tag { display:inline-block; padding:2px 7px; margin:2px; border-radius:4px; font-size:10px; background:#2c333d; color:var(--fg); }
  #results h2 { margin:20px 0 10px; }
  pre.raw { background:#0e1216; border:1px solid var(--line); padding:20px; border-radius:8px; overflow:auto; max-height:600px; font:12px/1.8 Consolas,monospace; }
  .shot-preview img { display:block; max-width:100%; border:1px solid var(--line); border-radius:8px; margin-top:18px; }
  .vision-grid { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:24px; }
  .vision-output { min-height:300px; padding:24px; background:#101419; border:1px solid var(--line); border-radius:8px; }
  #visionResult { white-space:pre-wrap; overflow-wrap:anywhere; }
  .modal-overlay { padding:0; background:var(--panel); color:var(--fg); border:1px solid #434b57; border-radius:14px; width:min(620px,92vw); max-height:88vh; }
  .modal-overlay::backdrop { background:#000a; backdrop-filter:blur(5px); }
  .modal { padding:26px; }
  .modal h2 { font-size:21px; margin-bottom:20px; }
  .modal .actions { display:flex; justify-content:flex-end; gap:10px; margin-top:24px; }
  #settingsSave { background:var(--accent) !important; color:#172213 !important; }
  #notice { position:fixed; bottom:24px; right:28px; max-width:min(460px,90vw); padding:13px 20px; border:1px solid #566b43; border-radius:9px; background:#212c1d; color:#e6f3da; box-shadow:0 12px 40px #0005; z-index:30; }
  @media(min-width:1450px) { .workspace { grid-template-columns:360px minmax(0,1fr); } #log { height:470px; } }
  @media(max-width:1100px) { .sidebar { width:180px; padding-inline:12px; } .app { margin-left:180px; } main { padding:24px; } .topbar { padding:0 24px; } .workspace { grid-template-columns:290px minmax(0,1fr); gap:16px; } .metric { padding:15px; } }
  @media(max-width:850px) { .sidebar { position:static; width:auto; padding:16px 20px; border-right:0; border-bottom:1px solid var(--line); } .brand { padding:0; } .brand-sub,.nav-label,.side-footer { display:none; } nav { display:flex; margin-top:16px; gap:6px; } .nav-item { width:auto; padding:8px 12px; } .app { margin:0; } .topbar { height:48px; } .workspace { grid-template-columns:1fr; } .metrics { grid-template-columns:repeat(2,minmax(0,1fr)); } .metric:nth-child(2) { border-right:0; } .metric:nth-child(-n+2) { border-bottom:1px solid var(--line); } .vision-grid { grid-template-columns:1fr; } }
  @media(max-width:480px) { main { padding:22px 16px; } .topbar { padding:0 16px; } .nav-item { padding:8px 10px; font-size:12px; gap:7px; } .nav-icon { display:none; } h1 { font-size:25px; } .heading-index { font-size:38px; } .row { flex-wrap:wrap; } .row > div { flex-basis:40%; } .modal { padding:20px; } .workflow { flex-wrap:wrap; } }
  @media(prefers-reduced-motion:reduce) { * { transition:none !important; } }
</style>
</head>
<body>

<aside class="sidebar">
  <div class="brand"><span class="brand-mark" aria-hidden="true">H</span>HexHound</div>
  <div class="brand-sub eyebrow">Security workspace</div>
  <div class="nav-label eyebrow">Workspace / 工作空间</div>
  <nav aria-label="主导航">
    <button class="nav-item" data-view="workspace" aria-current="page"><span class="nav-icon" aria-hidden="true">⊞</span>审计工作台</button>
    <button class="nav-item" data-view="reports"><span class="nav-icon" aria-hidden="true">▤</span>审计报告</button>
    <button class="nav-item" data-view="vision"><span class="nav-icon" aria-hidden="true">◎</span>视觉分析</button>
    <button class="nav-item" id="settingsBtn"><span class="nav-icon" aria-hidden="true">⚙</span>模型与设置</button>
  </nav>
  <div class="side-footer"><strong><span class="dot"></span>本地工作空间</strong>配置 · 执行 · 验证 · 留存<br>HexHound / v0.1</div>
</aside>
<div class="app">
<header class="topbar"><div class="breadcrumb">工作空间 <span>/</span> <strong id="currentPage">审计工作台</strong></div><span class="local-badge">LOCAL CONSOLE</span></header>
<main>
  <div class="page-heading"><div><div class="eyebrow">HEXHOUND / SECURITY OPERATIONS</div><h1 id="pageTitle">让每一次发现，都有据可循。</h1><p id="pageDescription">配置评估范围，跟踪代理执行，留存可复核的安全证据。</p></div><div class="heading-index" aria-hidden="true">/ 01</div></div>
  <section id="workspacePane">
    <div class="metrics" aria-label="本次审计指标">
      <div class="metric"><div class="metric-label">执行步骤 <span>01</span></div><strong class="metric-value" id="metricSteps">0</strong><small>本次运行累计步骤</small></div>
      <div class="metric"><div class="metric-label">已复核发现 <span>02</span></div><strong class="metric-value" id="metricFindings">0</strong><small>候选项单独列于报告</small></div>
      <div class="metric"><div class="metric-label">Token 用量 <span>03</span></div><strong class="metric-value" id="metricTokens">0</strong><small>输入与输出合计</small></div>
      <div class="metric"><div class="metric-label">预估费用 <span>04</span></div><strong class="metric-value" id="metricCost">¥0.0000</strong><small>按当前模型计价</small></div>
    </div>
    <div class="workspace">
      <section class="panel"><div class="panel-head"><h2><span class="section-number">01</span>任务配置</h2><span class="eyebrow">CONFIGURE</span></div><div class="panel-body">    <form id="cfg">
      <label>模式</label>
      <select name="mode">
        <option value="blackbox" {% if settings.mode == 'blackbox' %}selected{% endif %}>黑盒评估 · URL</option>
        <option value="source" {% if settings.mode == 'source' %}selected{% endif %}>源码审计 · Source</option>
      </select>
      <label>编排方式</label>
      <select name="swarm">
        <option value="1" {% if settings.swarm != '0' %}selected{% endif %}>多代理协作</option>
        <option value="0" {% if settings.swarm == '0' %}selected{% endif %}>单代理 ReAct</option>
      </select>
      <label>目标 URL</label>
      <input name="target" value="{{ settings.target }}" placeholder="https://授权目标">
<div id="sourceFields"><label>源码目录</label><input name="path" value="{{ settings.path }}"></div>
      <details><summary>执行参数与预算上限</summary>
      <p class="muted">标签、单位与取值范围来自同一份字段定义（与 CLI 一致）。预算类字段填 <b>0</b> 或留空 = 不限制；界面与后端都会校验。</p>
      {% for group in field_groups %}
      <div class="row">
        {% for field in group %}
        <div>
          <label for="f-{{ field.key }}">{{ field.label }}{% if field.unit %} / {{ field.unit }}{% endif %}</label>
          <input id="f-{{ field.key }}" name="{{ field.key }}" value="{{ settings[field.key] }}" inputmode="decimal">
          <small class="muted" id="hint-{{ field.key }}">范围：{{ field.range }}{% if field.hint %}。{{ field.hint }}{% endif %}</small>
        </div>
        {% endfor %}
      </div>
      {% endfor %}
      </details>
      <label>授权主机 · 逗号分隔</label>
      <input name="allowed_hosts" value="{{ settings.allowed_hosts }}">
      <div class="form-actions"><button type="button" id="runBtn">开始审计 <span aria-hidden="true">↗</span></button>
      <button type="button" id="stopBtn" disabled>中断当前任务</button>
      <button type="button" id="saveBtn">保存此配置</button>
</div>
<div class="hint">仅在已授权的目标范围内执行审计。配置会保存在本机，供下次使用。</div>
    </form></div></section>
      <div><section class="panel"><div class="panel-head"><h2><span class="section-number">02</span>执行记录</h2><div id="status" role="status">等待开始</div></div>
        <div class="log-toolbar"><span>AGENT ACTIVITY</span><label><input id="followLog" type="checkbox" checked>自动跟随</label></div>
        <div id="log" role="region" aria-label="代理执行日志" tabindex="0"><div class="empty-state"><div class="empty-symbol" aria-hidden="true">⌘</div><h3>准备好，开始下一次审计</h3><p>在左侧配置目标与授权范围。<br>代理的执行步骤、工具观察和编排进度将在这里实时呈现。</p></div></div>
        <div id="tokenStats" class="token-footer">Token：输入 0 / 输出 0 / 缓存命中 0 / 未命中 0</div>
      </section><div class="workflow" aria-label="审计流程"><span><i>01</i> 范围配置</span><b>→</b><span><i>02</i> 协同评估</span><b>→</b><span><i>03</i> 证据复核</span><b>→</b><span><i>04</i> 报告归档</span></div></div>
    </div>
  </section>
  <section id="reportsPane" class="panel" hidden><div class="panel-head"><h2>发现与报告</h2><button type="button" id="reportBtn">查看完整报告</button></div><div class="panel-body">
    <div id="findingToolbar" class="row">
      <div><label for="filterStatus">状态</label><select id="filterStatus">
        <option value="">全部</option><option value="verified">仅已复核</option><option value="candidate">仅待复核候选</option>
      </select></div>
      <div><label for="filterSeverity">等级</label><select id="filterSeverity"><option value="">全部</option></select></div>
      <div><label for="filterText">关键词</label><input id="filterText" placeholder="标题 / URL / 类型"></div>
      <div><label for="compareSelect">与历史运行对比</label><select id="compareSelect"><option value="">— 选择一次历史运行 —</option></select></div>
      <div><button type="button" id="compareBtn">对比</button></div>
    </div>
    <div class="row"><div id="findingCount" class="muted">共 0 条</div>
      <div><a id="exportJson" href="#" download>导出 JSON</a> · <a id="exportMarkdown" href="#" download>导出 Markdown</a></div>
    </div>
    <div id="compareResult" hidden></div>
    <div id="detailPane" hidden></div>
    <div id="results"><div class="empty-state"><div class="empty-symbol" aria-hidden="true">▤</div><h3>尚无审计结果</h3><p>完成一次审计后，在这里查看发现、复核状态和完整报告。</p></div></div><div id="reportSection"><pre class="raw" id="reportView" style="display:none;"></pre></div>
    <details id="historySection" open><summary>历史运行（重启后仍可查看，只读本机产物）</summary>
      <div class="row"><div><button type="button" id="historyRefresh">刷新历史</button></div><div id="historyNote" class="muted">只读取本机运行产物：不调用模型，也不会访问目标。</div></div>
      <div id="historyList" class="muted">正在加载…</div>
      <div id="historyDetail"></div>
    </details>
  </div></section>
  <section id="visionPane" class="panel" hidden><div class="panel-head"><h2>页面与图像分析</h2><span class="eyebrow">VISION</span></div><div class="panel-body vision-grid"><div>    <input type="file" id="imgInput" accept="image/*">
    <label>直接截图目标 URL</label>
    <div class="row">
      <input id="shotUrl" value="{{ settings.target }}" placeholder="http://127.0.0.1:5000">
      <button type="button" id="shotBtn" style="background:var(--line);color:var(--fg);white-space:nowrap;">截图并分析</button>
    </div>
    <label>提问（可选）</label>
    <input id="imgQuestion" placeholder="例如：这张页面有什么可疑点 / 有没有报错信息？">
    <button type="button" id="visionBtn" style="background:var(--line);color:var(--fg);margin-top:8px;">分析图片</button>
</div><div class="vision-output"><div class="eyebrow">ANALYSIS OUTPUT</div><div id="shotPreview" class="shot-preview"></div>
    <div id="visionResult" class="muted" style="margin-top:16px;">上传图片或输入目标 URL，分析结果将显示在这里。</div></div>
</div></section>
</main></div>
<div id="notice" role="status" hidden></div>
<dialog class="modal-overlay" id="settingsModal" aria-labelledby="settingsTitle">
  <div class="modal">
    <h2 id="settingsTitle">模型与设置</h2><p class="hint">密钥只在本机使用：不经浏览器回传，Windows 上以 DPAPI 加密保存（换机器/换用户需重填）。共用设备上仍建议跑完即清除。</p>
    <form id="settingsForm">
      <h3 style="margin:14px 0 6px;font-size:14px;">模型提供商</h3>
      <label>提供商预设</label>
      <select name="provider" id="providerSelect"></select>
      <div class="hint" id="providerNote"></div>
      <label>模型（可直接输入，或从下拉选）</label>
      <input name="model" id="modelInput" list="modelOptions" value="{{ settings.model }}" placeholder="模型名">
      <datalist id="modelOptions"></datalist>
      <label>API 密钥 <span class="muted" id="keyState"></span></label>
      <input name="api_key" id="apiKeyInput" type="password" value="{{ settings.api_key }}" autocomplete="off" placeholder="sk-...">
      <label>模型 URL（base_url）</label>
      <input name="base_url" id="baseUrlInput" value="{{ settings.base_url }}" placeholder="https://api.example.com/v1">
      <label for="reasoningEffort">推理强度</label>
      <select name="reasoning_effort" id="reasoningEffort">
        {% for value, label in [('', '服务端默认'), ('low', 'low'), ('high', 'high'), ('max', 'max')] %}
        <option value="{{ value }}"{% if settings.reasoning_effort == value %} selected{% endif %}>{{ label }}</option>
        {% endfor %}
      </select>
      <div class="hint">仅 DeepSeek 生效；其他提供商使用自身默认设置。DeepSeek 思考模式会忽略采样温度。</div>
      <div class="row" style="margin-top:8px;">
        <button type="button" id="testBtn" style="background:var(--line);color:var(--fg);flex:1;">测试连接</button>
        <button type="button" id="fillKeyBtn" style="background:var(--line);color:var(--fg);flex:1;">填入该提供商密钥</button>
        <button type="button" id="envBtn" style="background:var(--line);color:var(--fg);flex:1;">写入 .env</button>
      </div>
      <div id="testResult" class="hint"></div>
      <div id="keystoreNote" class="hint" hidden></div>
      <details style="margin-top:10px;">
        <summary class="muted" style="cursor:pointer;">按角色指定模型（可选：编排/复核用强模型，批量侦察用便宜模型）</summary>
        <div id="roleModelBox" style="margin-top:8px;"></div>
      </details>
      <div id="envResult" class="hint"></div>
      <h3 style="margin:16px 0 6px;font-size:14px;">其他</h3>
      <label>报告输出路径</label>
      <input name="output" value="{{ settings.output }}">
      <label>账号 A 认证信息（JSON，如 {"Cookie":"session=..."}）</label>
      <input name="auth_a" value="{{ settings.auth_a }}" placeholder='{"Cookie":"session=xxx"}'>
      <label>账号 B 认证信息（JSON）</label>
      <input name="auth_b" value="{{ settings.auth_b }}" placeholder='{"Cookie":"session=yyy"}'>
      <div class="row" style="margin-top:10px;">
        <button type="button" id="captureLoginA" style="background:var(--line);color:var(--fg);flex:1;">获取账号A登录态</button>
        <button type="button" id="captureLoginB" style="background:var(--line);color:var(--fg);flex:1;">获取账号B登录态</button>
      </div>
      <div id="loginStatus" class="hint"></div>
      <label>界面缩放</label>
      <select name="zoom">
        <option value="0.8" {% if settings.zoom == '0.8' %}selected{% endif %}>80%</option>
        <option value="0.9" {% if settings.zoom == '0.9' %}selected{% endif %}>90%</option>
        <option value="1.0" {% if settings.zoom == '1.0' %}selected{% endif %}>100%</option>
        <option value="1.1" {% if settings.zoom == '1.1' %}selected{% endif %}>110%</option>
        <option value="1.25" {% if settings.zoom == '1.25' %}selected{% endif %}>125%</option>
        <option value="1.5" {% if settings.zoom == '1.5' %}selected{% endif %}>150%</option>
      </select>
    </form>
    <div class="actions">
      <button type="button" id="settingsCancel" style="background:var(--line);color:var(--fg);">取消</button>
      <button type="button" id="settingsSave" style="background:var(--accent);color:#fff;">保存设置</button>
    </div>
  </div>
</dialog>
<script>
const $ = (s) => document.querySelector(s);
let zoomLevel = parseFloat({{ settings.zoom|tojson }}) || 1;
let zoomSaveTimer = null;
function applyZoom(value) {
  zoomLevel = Math.min(2.0, Math.max(0.5, parseFloat(value) || 1));
  zoomLevel = Math.round(zoomLevel * 100) / 100;
  document.documentElement.style.zoom = zoomLevel;
  const select = $('#settingsForm [name="zoom"]');
  let option = Array.from(select.options).find((item) => item.value === String(zoomLevel));
  if (!option) {
    option = document.createElement('option');
    option.value = String(zoomLevel);
    option.textContent = Math.round(zoomLevel * 100) + '%';
    select.appendChild(option);
  }
  select.value = option.value;
  clearTimeout(zoomSaveTimer);
  zoomSaveTimer = setTimeout(async () => {
    await post('/api/save', collect());
  }, 600);
}
window.addEventListener('wheel', (event) => {
  if (!event.ctrlKey) return;
  event.preventDefault();
  const step = event.deltaY < 0 ? 0.05 : -0.05;
  applyZoom(zoomLevel + step);
}, { passive: false });
function collect() {
  const o = {};
  for (const selector of ['#cfg', '#settingsForm']) {
    const f = new FormData($(selector));
    for (const [k, v] of f.entries()) o[k] = v.trim();
  }
  return o;
}
/* 本机控制面的会话令牌：由服务端渲染进本页面，有副作用的请求都带上它。
   跨站页面拿不到这个令牌（读不到本页面的 HTML），因此无法借本机发起审计或改配置。 */
const LOCAL_TOKEN = {{ local_token|tojson }};
function apiFetch(url, options) {
  const opts = Object.assign({}, options || {});
  opts.headers = Object.assign({}, opts.headers || {}, {'X-HexHound-Token': LOCAL_TOKEN});
  return fetch(url, opts);
}
async function post(url, data) {
  const r = await apiFetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  const result = await r.json();
  if (!r.ok || result.error) throw new Error(result.error || '请求失败，请稍后重试');
  return result;
}
function renderStep(s) {
  const d = document.createElement('div');
  d.className = 'step';
  const act = s.action || '?';
  const who = s.worker ? `<span class="tag">${escapeHtml(s.worker)}</span> ` : '';
  const role = s.role ? `<span class="tag">${escapeHtml(s.role)}</span> ` : '';
  const thought = s.thought ? `<div class="t">思考：${escapeHtml(s.thought)}</div>` : '';
  const obs = s.observation ? `<div>观察：${escapeHtml(String(s.observation).slice(0, 600))}</div>` : '';
  d.innerHTML = `<div class="a">${who}${role}Step ${escapeHtml(s.step)} · ${escapeHtml(act)}</div>${thought}${obs}`;
  return d;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function renderFindings(list) {
  ALL_FINDINGS = list || [];
  renderSeverityOptions();
  renderFilteredFindings();
}
/* ---------- 报表工作区：筛选 / 详情 / 导出 / 跨运行对比 ---------- */
function currentFilter() {
  return {
    status: $('#filterStatus').value,
    severity: $('#filterSeverity').value,
    text: $('#filterText').value.trim().toLowerCase()
  };
}
function visibleFindings() {
  const f = currentFilter();
  return ALL_FINDINGS.filter(item => {
    const status = item.status === 'candidate' ? 'candidate' : 'verified';
    if (f.status && status !== f.status) return false;
    if (f.severity && String(item.severity || '') !== f.severity) return false;
    if (f.text) {
      const haystack = [item.id, item.title, item.url, item.vuln_type, item.param, item.evidence]
        .map(v => String(v || '').toLowerCase()).join(' ');
      if (!haystack.includes(f.text)) return false;
    }
    return true;
  });
}
function renderSeverityOptions() {
  const select = $('#filterSeverity');
  const levels = [...new Set(ALL_FINDINGS.map(item => String(item.severity || '')).filter(Boolean))].sort();
  const keep = select.value;
  select.innerHTML = '<option value="">全部</option>' + levels.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
  select.value = levels.includes(keep) ? keep : '';
}
function findingDetail(item) {
  const rows = [['编号', item.id], ['标题', item.title], ['等级', item.severity],
    ['状态', item.status === 'candidate' ? '待复核候选（不是已确认漏洞）' : '已复核'],
    ['类型', item.vuln_type], ['URL', item.url], ['参数', item.param],
    ['复核方式', item.verification], ['PoC', item.poc_path], ['来源角色', item.worker || item.role],
    ['证据', item.evidence || item.description], ['反证', item.counterevidence]]
    .filter(([, value]) => value !== undefined && value !== null && String(value) !== '');
  return '<div class="finding"><b>' + escapeHtml(item.id || '') + ' ' + escapeHtml(item.title || '') + '</b>'
    + '<button type="button" id="detailClose" style="float:right">关闭</button>'
    + rows.map(([label, value]) => `<div class="muted"><b>${escapeHtml(label)}</b>：<span>${escapeHtml(String(value).slice(0, 1200))}</span></div>`).join('')
    + '</div>';
}
function renderFilteredFindings() {
  const box = $('#results');
  const list = visibleFindings();
  $('#findingCount').textContent = `显示 ${list.length} / 共 ${ALL_FINDINGS.length} 条`;
  if (!ALL_FINDINGS.length) {
    box.innerHTML = '<div class="empty-state"><div class="empty-symbol" aria-hidden="true">▤</div><h3>暂无已记录的发现</h3><p>运行完成后的发现与复核状态会列在这里。<br>未发现问题不代表目标安全。</p></div>';
    return;
  }
  if (!list.length) {
    box.innerHTML = '<div class="muted">当前筛选条件下没有发现（清空条件可看全部）。</div>';
    return;
  }
  const verified = list.filter(f => f.status !== 'candidate');
  const candidates = list.filter(f => f.status === 'candidate');
  const card = (f) => `
    <div class="finding" data-finding="${escapeHtml(f.id || '')}" style="${f.status === 'candidate' ? 'border-left-color:var(--warn);opacity:.9' : ''}">
      <b>${escapeHtml(f.id || '')} ${escapeHtml(f.title || '')}</b>
      <span class="tag">${escapeHtml(f.severity || '')}</span>
      ${f.status === 'candidate' ? '<span class="tag" style="background:var(--warn);color:#000">待复核</span>' : '<span class="tag" style="background:var(--ok);color:#000">已复核</span>'}
      ${f.vuln_type ? `<span class="tag">${escapeHtml(f.vuln_type)}</span>` : ''}
      ${f.url ? `<div class="muted">${escapeHtml(f.url)}</div>` : ''}
      <div class="muted">${escapeHtml((f.evidence || f.description || '').slice(0, 300))}</div>
      ${f.counterevidence ? `<div class="muted">反证：${escapeHtml(String(f.counterevidence).slice(0, 160))}</div>` : ''}
      ${f.poc_path ? `<div class="hint">PoC：${escapeHtml(f.poc_path)}</div>` : ''}
    </div>`;
  box.innerHTML = `<h2>已复核漏洞（${verified.length}）</h2>` + (verified.map(card).join('') || '<div class="muted">无</div>')
    + (candidates.length ? `<h2>待复核候选（${candidates.length}）</h2>` + candidates.map(card).join('') : '');
  box.querySelectorAll('[data-finding]').forEach(node => {
    node.style.cursor = 'pointer';
    node.onclick = () => {
      const item = ALL_FINDINGS.find(f => String(f.id || '') === node.dataset.finding);
      if (!item) return;
      const pane = $('#detailPane');
      pane.innerHTML = findingDetail(item);
      pane.hidden = false;
      const close = pane.querySelector('#detailClose');
      if (close) close.onclick = () => { pane.hidden = true; pane.innerHTML = ''; };
    };
  });
}
['#filterStatus', '#filterSeverity'].forEach(selector => {
  $(selector).onchange = () => renderFilteredFindings();
});
let filterTimer;
$('#filterText').oninput = () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => renderFilteredFindings(), 150);
};
function updateExportLinks() {
  const run = $('#compareSelect').value || 'current';
  $('#exportJson').href = '/api/export?format=json&run=' + encodeURIComponent(run);
  $('#exportMarkdown').href = '/api/export?format=markdown&run=' + encodeURIComponent(run);
}
$('#compareBtn').onclick = async () => {
  const against = $('#compareSelect').value;
  const box = $('#compareResult');
  if (!against) { notify('先选择一次历史运行'); return; }
  box.hidden = false;
  box.textContent = '正在对比…';
  try {
    const r = await apiFetch('/api/compare?with=' + encodeURIComponent(against));
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || '对比失败');
    const block = (title, items, hint) => `<h3>${escapeHtml(title)}（${items.length}）</h3>`
      + (hint ? `<div class="muted">${escapeHtml(hint)}</div>` : '')
      + (items.length
        ? items.map(i => `<div class="muted">· ${escapeHtml(i.id || '')} ${escapeHtml(i.title || '')} <span class="tag">${escapeHtml(i.severity || '')}</span> ${escapeHtml(i.url || '')}</div>`).join('')
        : '<div class="muted">无</div>');
    box.innerHTML = `<div class="finding"><b>与 ${escapeHtml(against)} 对比</b>`
      + `<div class="muted">本次 ${j.current_count} 条 / 历史 ${j.previous_count} 条（历史来源：${escapeHtml(j.against_source || '')}）</div>`
      + block('本次新增', j.new || [])
      + block('历史已有、本次仍存在', j.persisting || [])
      + block('疑似已修复', j.fixed || [], '只有在本次确实覆盖过该端点且无问题时才算"疑似已修复"；没测到的一律进"无法判定"。')
      + block('无法判定', j.unknown || [], '历史上报过、但本次没有覆盖到该位置——**不能说成已修复**。')
      + '</div>';
  } catch (error) {
    box.textContent = '对比失败：' + error.message;
  }
};
async function loadReport() {
  const view = $('#reportView');
  const r = await apiFetch('/api/report');
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || '报告加载失败');
  view.textContent = j.markdown || '暂无报告';
  view.style.display = 'block';
}
let timer = null;
let lastLog = '';
let lastResult = '';
/* 报表工作区状态：当前展示的发现（本次运行或选中的历史运行）与筛选条件。 */
let ALL_FINDINGS = [];
let CURRENT_RUN = 'current';
const idleLog = $('#log').innerHTML;

/* ---------- 历史运行（只读本机产物） ---------- */
function formatHistoryRun(run) {
  const label = run.status_label || run.status || '';
  const cost = Number(run.cost || 0).toFixed(4);
  const when = (run.finished_at || '').replace('T', ' ').slice(0, 19);
  return `<div class="finding" style="border-left-color:${run.status === 'done' ? 'var(--ok)' : 'var(--warn)'}">
    <b>${escapeHtml(run.target || run.id)}</b>
    <span class="tag">${escapeHtml(label)}</span>
    ${run.mode ? `<span class="tag">${escapeHtml(run.mode)}</span>` : ''}
    <div class="muted">${escapeHtml(when)} · 发现 ${run.findings || 0} · 端点 ${run.endpoints || 0} · ${Number(run.tokens || 0).toLocaleString()} token · ¥${cost}</div>
    <div class="muted">产物目录：${escapeHtml(run.dir || run.id)}</div>
    ${run.report_path ? `<div class="hint">报告文件：${escapeHtml(run.report_path)}</div>` : '<div class="muted">这次运行没有留下报告文件</div>'}
    <button type="button" data-run="${escapeHtml(run.id)}">查看这次报告</button>
  </div>`;
}
async function loadHistory() {
  const list = $('#historyList');
  try {
    const r = await apiFetch('/api/history?limit=30');
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || '历史加载失败');
    const runs = j.runs || [];
    const labels = j.status_labels || {};
    // 对比下拉与导出目标都跟着历史清单走
    const select = $('#compareSelect');
    const keep = select.value;
    select.innerHTML = '<option value="">— 选择一次历史运行 —</option>' + runs.map(run =>
      `<option value="${escapeHtml(run.id)}">${escapeHtml(run.id)}（${escapeHtml(labels[run.status] || run.status)}）</option>`).join('');
    select.value = runs.some(run => run.id === keep) ? keep : '';
    updateExportLinks();
    if (!runs.length) {
      list.innerHTML = '<div class="muted">本机还没有运行产物（跑一次审计后这里会出现记录）。</div>';
      return;
    }
    list.innerHTML = runs.map(run => formatHistoryRun({...run, status_label: labels[run.status] || run.status})).join('');
    list.querySelectorAll('button[data-run]').forEach(button => {
      button.onclick = () => loadHistoryDetail(button.dataset.run);
    });
  } catch (error) {
    list.textContent = '历史加载失败：' + error.message;
  }
}
async function loadHistoryDetail(runId) {
  const detail = $('#historyDetail');
  detail.textContent = '正在读取 ' + runId + ' …';
  try {
    const r = await apiFetch('/api/history/' + encodeURIComponent(runId));
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || '读取失败');
    const source = j.markdown_source === 'report' ? '当时写下的报告原文'
      : j.markdown_source === 'snapshot' ? '由运行快照离线重渲染（原文已不存在）' : '产物里没有报告';
    detail.innerHTML = `<h3>${escapeHtml(j.id)}</h3><div class="muted">来源：${escapeHtml(source)}</div>`;
    // 把这次历史运行的发现读进工作区（与本次运行同一套筛选/详情/导出）
    const findingsResponse = await apiFetch('/api/findings?run=' + encodeURIComponent(runId));
    const findingsPayload = await findingsResponse.json();
    if (findingsResponse.ok && !findingsPayload.error) {
      CURRENT_RUN = runId;
      ALL_FINDINGS = findingsPayload.findings || [];
      renderSeverityOptions();
      renderFilteredFindings();
      detail.insertAdjacentHTML('beforeend',
        `<div class="muted">已载入该次运行的 ${ALL_FINDINGS.length} 条发现（来源：${escapeHtml(findingsPayload.source)}）；筛选与导出都跟着它走。</div>`);
    }
    const pre = document.createElement('pre');
    pre.className = 'raw';
    pre.style.display = 'block';
    pre.textContent = j.markdown || '（这次运行没有留下报告文本）';
    detail.appendChild(pre);
  } catch (error) {
    detail.textContent = '读取失败：' + error.message;
  }
}
$('#historyRefresh').onclick = () => loadHistory();
async function poll() {
  try {
    const response = await apiFetch('/api/status');
    if (!response.ok) throw new Error('无法读取运行状态');
    const s = await response.json();
    const st = $('#status');
    st.className = s.status;
    // 状态文案以后端为准（单一来源），避免前后端各写一份映射而漂移。
    st.textContent = s.status_label || '等待开始';
    if (s.error) st.textContent = '执行失败：' + s.error;
    // running 包含"正在停止"的收尾期：那期间服务端仍占用运行名额（会拒绝新任务），
    // 界面必须一致地禁用"开始审计"，否则用户点了只会收到一句 409 错误。
    const busy = Boolean(s.running) || s.status === 'running';
    $('#stopBtn').disabled = s.status !== 'running';
    $('#runBtn').disabled = busy;
    $('#runBtn').textContent = busy ? '审计进行中…' : '开始审计 ↗';
    const tok = s.tokens || {};
    $('#metricSteps').textContent = (s.steps || []).length;
    $('#metricFindings').textContent = (s.findings || []).filter(f => f.status !== 'candidate').length;
    $('#metricTokens').textContent = Number(tok.total_tokens || (tok.prompt_tokens || 0) + (tok.completion_tokens || 0)).toLocaleString();
    $('#metricCost').textContent = '¥' + Number(tok.estimated_cost || 0).toFixed(4);
    $('#tokenStats').textContent = `Token：输入 ${tok.prompt_tokens ?? 0} / 输出 ${tok.completion_tokens ?? 0} / 缓存命中 ${tok.cache_hit_tokens ?? 0} / 未命中 ${tok.cache_miss_tokens ?? 0}`;
    const log = $('#log');
    const signature = JSON.stringify([s.phases, s.steps, s.status]);
    if (signature !== lastLog) {
      const top = log.scrollTop;
      log.replaceChildren();
      const phases = s.phases || [];
      if (phases.length) {
        const box = document.createElement('div');
        box.className = 'step';
        box.innerHTML = `<div class="a">编排进度</div><div class="t">${escapeHtml(phases.join('\n'))}</div>`;
        log.appendChild(box);
      }
      for (const step of s.steps || []) log.appendChild(renderStep(step));
      if (!log.children.length) {
        log.innerHTML = s.status === 'running'
          ? '<div class="empty-state"><div class="empty-symbol">…</div><h3>正在准备评估</h3><p>等待代理返回首个执行步骤。</p></div>' : idleLog;
      }
      log.scrollTop = $('#followLog').checked ? log.scrollHeight : top;
      lastLog = signature;
    }
    const resultKey = JSON.stringify([s.status, s.findings, s.summary, s.output_path]);
    if (resultKey !== lastResult) {
      renderFindings(s.findings || []);
      if (s.status === 'done' || s.status === 'cancelled') {
        // 中断也要展示成果：**部分结果不是没有结果**，但必须写明不完整。
        const banner = s.status === 'cancelled'
          ? '<div class="muted" style="border-left:3px solid var(--warn);padding-left:10px">'
            + '<b>本次运行被中断，报告不完整。</b>已完成的步骤与发现如实列出；'
            + '尚未测试的端点与参数没有被测过——它们既不表示安全，也不表示已修复。</div>'
          : '';
        $('#results').innerHTML += banner + `<h2>审计总结</h2><div class="muted">${escapeHtml(s.summary || '暂无总结')}</div>`;
        if (s.output_path) $('#results').innerHTML += `<div class="hint">报告已保存：${escapeHtml(s.output_path)}</div>`;
        if (s.submission_path) $('#results').innerHTML += '<p><a href="/api/submission">下载补天提交包</a></p>';
      }
      if (s.status === 'running') {
        $('#reportView').textContent = '';
        $('#reportView').style.display = 'none';
      }
      lastResult = resultKey;
    }
  } catch (error) {
    $('#status').className = 'error';
    $('#status').textContent = '连接中断，正在重试';
  } finally {
    clearTimeout(timer);
    timer = setTimeout(poll, 1200);
  }
}
$('#saveBtn').onclick = async () => {
  await post('/api/save', collect());
  notify('配置已保存');
  await loadProviders();
};
$('#settingsBtn').onclick = async () => {
  $('#settingsModal').showModal();
  await loadProviders();
};

/* ---------- 模型提供商面板 ---------- */
let PROVIDERS = [];
/* 只保存掩码与"是否已保存"：明文密钥不再经过浏览器（服务端按 provider 取用）。 */
let PROVIDER_STATE = {active: '', keys_masked: {}, keys_saved: {}};

function currentProvider() {
  return $('#providerSelect').value || 'custom';
}
function presetOf(key) {
  return PROVIDERS.find(p => p.key === key) || null;
}
function renderProviderOptions() {
  const select = $('#providerSelect');
  const placeholder = '<option value="">— 请选择提供商 —</option>';
  select.innerHTML = placeholder + PROVIDERS.map(p =>
    `<option value="${p.key}">${escapeHtml(p.label)}</option>`).join('');
  select.value = PROVIDER_STATE.active || '';
  if (!select.value) {
    // 没有已保存/已配置的提供商：不要替用户预选一个付费服务
    $('#providerNote').innerHTML = '<b>还没有选择提供商。</b>选一个预设，或选「自定义」手动填 base_url 与模型名；填好后点「测试连接」。';
    $('#modelOptions').innerHTML = '';
  }
}
function applyPreset({fillModel = true, fillUrl = true} = {}) {
  if (!$('#providerSelect').value) return;
  const preset = presetOf(currentProvider());
  if (!preset) return;
  if (fillUrl && preset.base_url) $('#baseUrlInput').value = preset.base_url;
  if (fillModel && preset.default_model) $('#modelInput').value = preset.default_model;
  $('#modelOptions').innerHTML = (preset.models || []).map(m => `<option value="${escapeHtml(m)}"></option>`).join('');
  const keyHint = preset.key_required
    ? `需要 key（${escapeHtml(preset.key_style)}…）${preset.api_key_url ? ` · <a href="${preset.api_key_url}" target="_blank" rel="noreferrer">获取密钥</a>` : ''}`
    : '该提供商无需密钥';
  $('#providerNote').innerHTML = keyHint + (preset.note ? `<br>${escapeHtml(preset.note)}` : '');
  const masked = PROVIDER_STATE.keys_masked[preset.key];
  const saved = PROVIDER_STATE.keys_saved[preset.key];
  $('#keyState').textContent = saved ? `（已保存 ${masked || ''}）` : '';
  // 刻意**不**把已保存的密钥回填进输入框：接口只回传掩码，回填等于把掩码
  // 当成真密钥再用一次。留空时服务端会自动使用已保存的密钥。
  if (saved) $('#apiKeyInput').placeholder = '留空 = 使用已保存的密钥（要更换请粘贴新密钥）';
  else $('#apiKeyInput').placeholder = preset.key_style || '粘贴密钥';
}
function renderRoleModels() {
  const spec = {{ role_labels|tojson }};
  const box = $('#roleModelBox');
  box.innerHTML = Object.entries(spec).map(([role, label]) => `
    <label for="role-${role}" style="margin-top:8px;">${escapeHtml(label)}</label>
    <input id="role-${role}" name="role_model_${role}" data-role="${role}" placeholder="留空 = 跟随上面的默认模型">`).join('');
  const saved = {{ settings.role_models|tojson }};
  for (const [role, model] of Object.entries(saved || {})) {
    const input = box.querySelector(`input[data-role="${role}"]`);
    if (input) input.value = model;
  }
}
async function loadProviders() {
  try {
    const r = await apiFetch('/api/providers');
    const j = await r.json();
    PROVIDERS = j.presets || [];
    PROVIDER_STATE = {active: j.active || '', keys_masked: j.keys_masked || {}, keys_saved: j.keys_saved || {}};
    // 磁盘加密状态与解密失败原因都要能看见："密钥突然没了"必须查得出原因
    const notes = [];
    if (j.keystore_error) notes.push('读取已保存密钥失败：' + j.keystore_error);
    if (j.keys_encrypted_at_rest === false && j.protection_note) notes.push(j.protection_note);
    $('#keystoreNote').textContent = notes.join(' ');
    $('#keystoreNote').hidden = !notes.length;
  } catch (error) {
    PROVIDER_STATE = {active: '', keys_masked: {}, keys_saved: {}};
  }
  renderProviderOptions();
  applyPreset({fillModel: false, fillUrl: false});
  renderRoleModels();
}
$('#providerSelect').onchange = () => { applyPreset(); };
$('#fillKeyBtn').onclick = () => {
  // 明文密钥不再回传到页面，所以这里不能"填入"——只能告诉用户留空即用已保存的密钥。
  const saved = PROVIDER_STATE.keys_saved[currentProvider()];
  if (!saved) { $('#testResult').textContent = '该提供商还没有保存过密钥，请直接粘贴。'; return; }
  $('#apiKeyInput').value = '';
  $('#apiKeyInput').placeholder = '留空 = 使用已保存的密钥（要更换请粘贴新密钥）';
  $('#testResult').textContent = '将使用已保存的密钥（' + (PROVIDER_STATE.keys_masked[currentProvider()] || '') + '）；密钥只在服务端使用，不会回显到页面。';
};
$('#testBtn').onclick = async () => {
  const out = $('#testResult');
  out.textContent = '正在测试连接…';
  $('#testBtn').disabled = true;
  const r = await apiFetch('/api/provider_test', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      provider: currentProvider(),
      model: $('#modelInput').value.trim(),
      base_url: $('#baseUrlInput').value.trim(),
      api_key: $('#apiKeyInput').value.trim(),
      reasoning_effort: $('#reasoningEffort').value
    })
  });
  const j = await r.json();
  $('#testBtn').disabled = false;
  if (j.error) { out.textContent = '测试失败：' + j.error; return; }
  out.innerHTML = (j.ok ? '✅ ' : '❌ ') + escapeHtml(j.message || '').replace(/\n/g, '<br>')
    + (j.usage ? `<br><span class="muted">用量 ${j.usage.total_tokens} token · 延迟 ${j.latency_ms} ms</span>` : '');
  if (j.ok) {
    // 测通即记住该提供商的密钥，省得下次重填（页面只记"已保存"，不记明文）
    const typed = $('#apiKeyInput').value.trim();
    if (typed) await post('/api/provider_key', {provider: currentProvider(), api_key: typed});
    PROVIDER_STATE.keys_saved[currentProvider()] = true;
    PROVIDER_STATE.keys_masked[currentProvider()] = j.masked || PROVIDER_STATE.keys_masked[currentProvider()] || '';
    $('#keyState').textContent = '（已保存）';
    $('#apiKeyInput').value = '';
    $('#apiKeyInput').placeholder = '留空 = 使用已保存的密钥（要更换请粘贴新密钥）';
  }
};
$('#envBtn').onclick = async () => {
  const out = $('#envResult');
  out.textContent = '正在写入 .env…';
  const j = await post('/api/write_env', collect());
  out.textContent = j.error ? ('写入失败：' + j.error) : (j.message || '已写入 .env');
};
$('#settingsCancel').onclick = () => { $('#settingsModal').close(); };
$('#settingsModal').onclick = (e) => {
  if (e.target === $('#settingsModal')) $('#settingsModal').close();
};
$('#settingsForm [name="zoom"]').onchange = (e) => { applyZoom(e.target.value); };
$('#settingsSave').onclick = async () => {
  applyZoom($('#settingsForm [name="zoom"]').value);
  await post('/api/save', collect());
  $('#settingsModal').close();
  notify('配置已保存');
};
async function captureLogin(account) {
  const url = $('#cfg [name="target"]').value.trim();
  const cfg = collect();
  const statusBox = $('#loginStatus');
  if (!url) { statusBox.textContent = '请先填写目标 URL'; return; }
  const btn = account === 'A' ? $('#captureLoginA') : $('#captureLoginB');
  btn.disabled = true;
  statusBox.textContent = '正在打开登录窗口，登录完成后点击页面右上角按钮';
  try {
    const r = await apiFetch('/api/capture_login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: url, allowed_hosts: cfg.allowed_hosts, timeout: 300})
    });
    const j = await r.json();
    if (j.error) { statusBox.textContent = '登录失败：' + j.error; return; }
    const field = account === 'A' ? 'auth_a' : 'auth_b';
    $('#settingsForm [name="' + field + '"]').value = JSON.stringify(j.auth_json || {});
    await post('/api/save', collect());
    statusBox.textContent = '账号' + account + '登录态已保存';
  } catch (error) {
    statusBox.textContent = '登录失败：' + error.message;
  } finally {
    btn.disabled = false;
  }
}
$('#captureLoginA').onclick = () => captureLogin('A');
$('#captureLoginB').onclick = () => captureLogin('B');
$('#runBtn').onclick = async () => {
  if (!$('#cfg').reportValidity()) return;
  $('#runBtn').disabled = true;
  try {
    await post('/api/run', collect());
    await poll();
  } catch (error) {
    notify(error.message);
    $('#runBtn').disabled = false;
  }
};
$('#stopBtn').onclick = async () => {
  $('#stopBtn').disabled = true;
  try { await post('/api/stop', {}); await poll(); }
  catch (error) { notify(error.message); $('#stopBtn').disabled = false; }
};
$('#visionBtn').onclick = () => {
  const f = $('#imgInput').files[0];
  const out = $('#visionResult');
  if (!f) { out.textContent = '请先选择一张图片。'; return; }
  out.textContent = '分析中…';
  const reader = new FileReader();
  reader.onload = async () => {
    const dataUrl = String(reader.result);
    const [meta, b64] = dataUrl.split(',');
    const mime = (meta.match(/data:(.*?);/) || ['', 'image/png'])[1];
    const r = await apiFetch('/api/vision', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({image_base64: b64, mime_type: mime, question: $('#imgQuestion').value})
    });
    const j = await r.json();
    out.textContent = j.answer || j.error || '（无结果）';
  };
  reader.readAsDataURL(f);
};
$('#reportBtn').onclick = () => {
  const view = $('#reportView');
  if (view.style.display === 'none') {
    loadReport();
  } else {
    view.style.display = 'none';
  }
};
$('#shotBtn').onclick = async () => {
  const url = $('#shotUrl').value.trim();
  const out = $('#visionResult');
  const preview = $('#shotPreview');
  if (!url) { out.textContent = '请先填写目标 URL'; return; }
  out.textContent = '正在截图并分析…';
  preview.innerHTML = '';
  const cfg = collect();
  const r = await apiFetch('/api/screenshot', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      url: url,
      question: $('#imgQuestion').value,
      allowed_hosts: cfg.allowed_hosts,
      request_timeout: cfg.request_timeout
    })
  });
  const j = await r.json();
  if (j.image_base64) {
    preview.innerHTML = `<img src="data:${j.mime_type || 'image/png'};base64,${j.image_base64}" alt="页面截图">`;
  }
  out.textContent = j.answer || j.error || '（无结果）';
};

const pages = {
  workspace: ['审计工作台', '让每一次发现，都有据可循。', '配置评估范围，跟踪代理执行，留存可复核的安全证据。', '01'],
  reports: ['审计报告', '从发现，到可复核的证据。', '查看本次运行的发现、候选项与完整审计报告。', '02'],
  vision: ['视觉分析', '换个视角，理解目标页面。', '上传页面截图，或对授权目标截图并进行多模态分析。', '03']
};
document.querySelectorAll('[data-view]').forEach(button => {
  button.onclick = () => {
    const key = button.dataset.view;
    for (const name of Object.keys(pages)) $('#' + name + 'Pane').hidden = name !== key;
    document.querySelectorAll('[data-view]').forEach(item => {
      if (item === button) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    const [label, title, description, number] = pages[key];
    $('#currentPage').textContent = label;
    $('#pageTitle').textContent = title;
    $('#pageDescription').textContent = description;
    $('.heading-index').textContent = '/ ' + number;
  };
});
let noticeTimer;
function notify(message) {
  $('#notice').textContent = message;
  $('#notice').hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { $('#notice').hidden = true; }, 4500);
}
window.addEventListener('unhandledrejection', event => {
  notify(event.reason?.message || '操作失败，请重试');
});
document.querySelectorAll('label').forEach((label, index) => {
  const field = label.nextElementSibling;
  if (field?.matches('input,select')) {
    field.id ||= 'field-' + index;
    label.htmlFor = field.id;
  }
});
$('#imgInput').setAttribute('aria-label', '上传待分析图片');
$('#cfg [name="target"]').type = 'url';
$('#cfg [name="allowed_hosts"]').required = true;
const mode = $('#cfg [name="mode"]');
mode.onchange = () => {
  $('#sourceFields').hidden = mode.value !== 'source';
  $('#cfg [name="target"]').required = mode.value === 'blackbox';
  $('#cfg [name="path"]').required = mode.value === 'source';
};
mode.onchange();
// Restore action buttons after a failed request, so the user can retry.
for (const id of ['saveBtn', 'settingsSave', 'testBtn', 'envBtn', 'shotBtn']) {
  const button = $('#' + id);
  const action = button.onclick;
  button.onclick = async event => {
    button.disabled = true;
    try { await action(event); }
    catch (error) { notify(error.message); }
    finally { button.disabled = false; }
  };
}
document.documentElement.style.zoom = Math.min(2, Math.max(.5, zoomLevel));
updateExportLinks();
loadProviders();
loadHistory();
poll();

</script>
</body>
</html>
"""


def _load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    settings = {k: v for k, v in data.items() if isinstance(v, str)}
    # 旧配置缺少此字段时继承环境值；显式空值仍表示服务端默认。
    settings.setdefault("reasoning_effort", os.getenv("LLM_REASONING_EFFORT", "").strip())
    return settings


#: 并发保存的互斥锁：多个请求（/api/save 与 /api/provider_key）同时写
#: settings.json 时，没有它就会出现"后写覆盖先写"。
_SETTINGS_LOCK = threading.RLock()


def _save_settings(data: dict) -> None:
    """保存设置：白名单字段 + 按角色模型字段（`role_model_<角色>`）。

    三条硬化（都是实测问题驱动的）：

    1. **未提交的字段不被清空**：先读磁盘现值作为基底，只覆盖 payload 里
       真的出现的键（`None` 表示显式清空）。早先直接用 `DEFAULTS` 重建整个
       字典，于是**任何一次普通保存都会把已保存的密钥清空**——设置面板的普通
       表单里根本没有 `provider_keys` 输入框，而密钥正是存在这个键里的。
    2. **原子写**：同目录临时文件 + `os.replace`。进程被杀/断电不会留下半份
       JSON；配置文件写坏等于密钥与白名单一起丢。
    3. **加锁**：并发保存（多个标签页、`/api/save` 与 `/api/provider_key` 同时
       到达）串行化，避免后写覆盖先写。
    """
    with _SETTINGS_LOCK:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # 基底 = 磁盘现值；首次保存时磁盘为空，退化为"全部默认值"
        cleaned: dict[str, str] = dict(DEFAULTS)
        cleaned.update(
            {k: v for k, v in _load_settings().items() if isinstance(v, str)}
        )
        for key in DEFAULTS:
            if key not in data:
                continue  # 未提交 → 保留基底（磁盘值或默认值）
            value = data.get(key)
            # 显式 None = 清空回默认值；显式空串 = 就存空串
            cleaned[key] = DEFAULTS.get(key, "") if value is None else str(value).strip()
        for role in ROLES:
            field = f"role_model_{role}"
            if field in data:
                cleaned[field] = str(data.get(field, "") or "").strip()
        # 密钥字段落盘前加密（Windows DPAPI）。旧文件里的明文 JSON 在这里被
        # 自动迁移成密文——读的时候两种格式都认，因此**不会丢密钥**。
        cleaned["provider_keys"] = _protect_provider_keys(cleaned.get("provider_keys", ""))
        _atomic_write_text(
            SETTINGS_PATH, json.dumps(cleaned, ensure_ascii=False, indent=2)
        )


def _atomic_write_text(path: Path, text: str) -> None:
    """原子写文本：同目录临时文件 + `os.replace`（POSIX/Windows 都是原子替换）。

    同目录很重要：跨文件系统 `os.replace` 可能退化成"复制+删除"，
    就不再原子了。
    """
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        # 替换成功后 tmp 已不存在；失败时清掉，避免留下垃圾文件
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _provider_keys() -> dict[str, str]:
    """读取已保存的各提供商密钥（存在 settings.json 的 provider_keys 里）。

    落盘时用 DPAPI 加密（Windows），因此这里要先解密。解不开**不能**静默当成
    "没配过"——原因记进 `_KEYSTORE_NOTE`，由 `/api/providers` 带给界面。
    """
    raw = _load_settings().get("provider_keys") or "{}"
    global _KEYSTORE_NOTE
    _KEYSTORE_NOTE = ""
    if secretstore.is_protected(raw):
        decrypted, error = secretstore.unprotect(raw)
        if error:
            _KEYSTORE_NOTE = error
            return {}
        raw = decrypted
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if str(v).strip()}


#: 最近一次读取密钥时的说明（解密失败等），供界面显示。
_KEYSTORE_NOTE = ""


def _protect_provider_keys(raw: str) -> str:
    """把 provider_keys 字段加密后再落盘；已经是密文就原样保留（不重复加密）。"""
    text = str(raw or "")
    if not text or secretstore.is_protected(text):
        return text
    return secretstore.protect(text)


def _active_provider(settings: dict) -> str:
    """当前生效的提供商：settings.provider 优先，其次 .env 的 LLM_PROVIDER。"""
    return resolve_provider(settings.get("provider") or os.getenv("LLM_PROVIDER", ""))


def _role_models(settings: dict) -> dict[str, str]:
    """解析界面里的按角色模型设置（表单字段 role_model_<角色> → dict）。"""
    result: dict[str, str] = {}
    for role in ROLES:
        value = str(settings.get(f"role_model_{role}", "") or "").strip()
        if value:
            result[role] = value
    return result


def _resolve_llm_settings(settings: dict) -> dict[str, str]:
    """把界面设置解析成实际请求参数（provider/模型/URL/密钥），含预设回填。

    优先级：界面显式值 > 该提供商的已保存密钥 > .env 里的专用/共享密钥。
    """
    provider = _active_provider(settings)
    preset = get_preset(provider)
    base_url = normalize_base_url(
        settings.get("base_url") or (preset.base_url if preset else "")
    )
    model = (
        str(settings.get("model") or "").strip()
        or (preset.default_model if preset else "")
        or os.getenv("LLM_MODEL", "").strip()
    )
    saved_keys = _provider_keys()
    api_key = (
        str(settings.get("api_key") or "").strip()
        or saved_keys.get(provider, "")
        or os.getenv(env_key_name(provider), "").strip()
        or os.getenv("LLM_API_KEY", "").strip()
    )
    return {
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "api_key": api_key,
    }


def _update_env_file(path: Path, updates: dict[str, str]) -> list[str]:
    """把若干键写进 .env：已存在的键就地替换，缺失的追加；先备份原文件。

    保留注释与未知键——用户的 .env 里常有他们自己加的东西，不能被工具覆盖掉。
    返回实际更新的键名列表。
    """
    path = Path(path)
    lines: list[str] = []
    if path.exists():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        try:
            path.with_suffix(path.suffix + ".bak").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
        except OSError:
            pass  # 备份失败不阻塞写入
    remaining = dict(updates)
    changed: list[str] = []
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        key, _, _value = stripped.partition("=")
        key = key.strip()
        if key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
            changed.append(key)
        else:
            out.append(line)
    if remaining:
        if out and out[-1].strip():
            out.append("")
        out.append("# ---- 由 HexHound 设置面板写入 ----")
        for key, value in remaining.items():
            out.append(f"{key}={value}")
            changed.append(key)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return changed


def _looks_like_mask(value: str) -> bool:
    """判断送进来的"密钥"其实是界面回显的**掩码**。

    掩码（`sk-123…abcd`）只用于展示。一旦被当成真实密钥保存回去，
    之后每次请求都拿着一个必然失败的假密钥——而界面还显示"已保存"，
    用户只能看到"鉴权失败"，很难想到是掩码被存了。
    """
    text = str(value or "").strip()
    if not text:
        return False
    if "…" in text or "***" in text:
        return True
    try:
        saved = _provider_keys().values()
    except Exception:  # noqa: BLE001 读配置失败不应阻断保存
        return False
    return any(secret and text == mask_key(secret) for secret in saved)


def _secret_candidates(extra: str = "") -> list[str]:
    """收集本机已知的密钥值（用于错误文本打码）。"""
    values: list[str] = [extra, os.getenv("LLM_API_KEY", "")]
    values.append(os.getenv("VISION_API_KEY", ""))
    try:
        values.extend(_provider_keys().values())
    except Exception:  # noqa: BLE001 配置不可读时退化为只打码环境变量
        pass
    for preset in describe_presets():
        values.append(os.getenv(str(preset.get("env_key") or ""), ""))
    return [value.strip() for value in values if isinstance(value, str) and len(value.strip()) >= 8]


def _scrub_secrets(text: str, extra: str = "") -> str:
    """把错误文本里夹带的密钥替换成掩码后才允许展示。

    为什么需要：提供商的报错经常**原样回显凭据**
    （典型如 `Incorrect API key provided: sk-xxxx`）。这条文本会进界面、
    日志和运行记录——密钥就顺着"报错"泄漏出去了。
    """
    out = str(text or "")
    for secret in _secret_candidates(extra):
        if secret in out:
            out = out.replace(secret, mask_key(secret))
    # 兜底：密钥不在本机配置里（例如用户刚粘贴、还没保存）也要打码。
    out = re.sub(r"sk-[A-Za-z0-9_\-]{8,}", lambda m: mask_key(m.group(0)), out)
    # `Bearer <token>` 是空格分隔的，单独一条规则（`key=value` 那条抓不到）。
    out = re.sub(r"(?i)\b(bearer)\s+([A-Za-z0-9_\-\.=]{8,})", r"\1 ***", out)
    out = re.sub(
        r"(?i)\b(api[-_]?key|authorization|access[-_]?token|token)\b(\s*[:=]\s*)([A-Za-z0-9_\-\.=]{8,})",
        r"\1\2***",
        out,
    )
    return out


def _request_hostname() -> str:
    """取请求的 Host（去掉端口，IPv6 去掉方括号），小写。"""
    host = str(getattr(request, "host", "") or "").strip()
    if host.startswith("["):  # [::1]:5001
        end = host.find("]")
        return host[1:end].lower() if end > 0 else host.lower()
    return (host.rsplit(":", 1)[0] if ":" in host else host).lower()


def _settings_payload() -> dict:
    """给模板的完整设置（含 provider 相关字段、角色模型与数值字段定义）。"""
    stored = _load_settings()
    merged = {**DEFAULTS, **stored}
    specs = field_specs()
    # 每行两个字段：与既有版式一致，且不依赖模板里的循环算术。
    groups = [specs[index : index + 2] for index in range(0, len(specs), 2)]
    return {
        "settings": {**merged, "role_models": _role_models(stored)},
        "role_labels": ROLE_LABEL,
        "field_groups": groups,
        "run_history": history.list_runs(limit=10),
    }


#: 运行状态取值。刻意把"正在停止"与"已取消"单独成态：
#: 早先停止后直接变回 `idle`，于是**界面看不出这次是被中断的**，
#: 而且最终报告那条路径被 `if is_stopped: return` 直接跳过——
#: 已经跑出来的步骤、发现与用量全都没落盘。
STATUS_IDLE = "idle"
STATUS_RUNNING = "running"
STATUS_STOPPING = "stopping"
STATUS_CANCELLED = "cancelled"
STATUS_FAILED = "failed"
STATUS_DONE = "done"

#: 真实结束态（可以开始新任务的状态）
TERMINAL_STATUSES = frozenset(
    {STATUS_IDLE, STATUS_CANCELLED, STATUS_FAILED, STATUS_DONE}
)

#: 状态的用户可读文案（界面直接显示）
STATUS_LABEL = {
    STATUS_IDLE: "等待开始",
    STATUS_RUNNING: "正在执行",
    STATUS_STOPPING: "正在停止",
    STATUS_CANCELLED: "已中断（部分结果已保存）",
    STATUS_FAILED: "执行失败",
    STATUS_DONE: "审计完成",
}


class RunState:
    """后台审计运行的状态（线程安全）。

    生命周期：`idle → running → (stopping → cancelled) | failed | done`。
    `stopping` 是**过渡态**：停止请求已发出，审计线程还在收尾（写部分报告）。
    这样界面能区分"已经停了"和"正在停"，也能防止在收尾期间重复启动。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token = 0
        self._cancel_event = threading.Event()
        self._running = False
        self.status = STATUS_IDLE
        self.steps: list[dict] = []
        self.events: list[dict] = []
        self.findings: list[dict] = []
        self.summary = ""
        self.error = ""
        self.output_path = ""
        self.submission_path = ""
        self.partial = False
        self.tokens = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cache_hit_tokens": 0,
            "cache_miss_tokens": 0,
            "estimated_cost": 0.0,
            "total_tokens": 0,
        }

    # ---------- 启动 / 停止（互斥，防重叠执行）----------

    def try_begin(self) -> bool:
        """尝试占用"正在运行"名额。已占用返回 False。

        为什么必须防重叠（P1-5 要求）：两个审计线程会同时写同一个攻面、
        同一个 `runs/<host>-<ts>` 产物目录与同一个 `STATE`，
        用量与结论互相污染，而且界面上看不出跑了两份。
        """
        with self._lock:
            if self._running or self.status not in TERMINAL_STATUSES:
                return False
            self._running = True
            return True

    def abort_begin(self) -> None:
        """释放占位（`try_begin` 成功但后续步骤失败时调用）。"""
        with self._lock:
            self._running = False

    def start(self) -> int:
        with self._lock:
            self._token += 1
            self._cancel_event.clear()
            self._running = True
            self.status = STATUS_RUNNING
            self.steps = []
            self.events = []
            self.findings = []
            self.summary = ""
            self.error = ""
            self.output_path = ""
            self.submission_path = ""
            self.partial = False
            self.tokens = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cache_hit_tokens": 0,
                "cache_miss_tokens": 0,
                "estimated_cost": 0.0,
                "total_tokens": 0,
            }
            return self._token

    def add_step(self, step: dict, token: int) -> None:
        with self._lock:
            # 注意：**停止后仍然接收步骤**。收尾阶段（写部分报告、清点发现）
            # 产生的记录属于"本次运行已完成的成果"，不能因为已经按下停止就丢掉。
            if token == self._token:
                self.steps.append(step)

    def add_event(self, event: dict, token: int) -> None:
        """记录一次编排事件（计划/波次/子任务起止/预警），供界面展示进度。"""
        with self._lock:
            if token == self._token:
                self.events.append(event)
                del self.events[:-200]

    def phases(self) -> list[str]:
        """把编排事件压成人类可读的进度行。"""
        lines: list[str] = []
        for event in self.events:
            kind = event.get("kind")
            if kind == "plan":
                lines.append(f"计划：{len(event.get('tasks') or [])} 个子任务")
                for task in event.get("tasks") or []:
                    lines.append(f"  [{task['id']}] {task['role']} — {str(task['objective'])[:70]}")
            elif kind == "wave":
                lines.append(f"—— 第 {event.get('wave')} 波（{event.get('count')} 个子任务）——")
            elif kind == "task_start":
                task = event.get("task") or {}
                lines.append(f">> [{task.get('id')}] {task.get('role')} 开始：{str(task.get('objective'))[:60]}")
            elif kind == "task_end":
                task = event.get("task") or {}
                flag = "[OK]" if task.get("outcome") == "done" else "[!!]"
                label = task.get("outcome_label") or task.get("outcome") or ""
                lines.append(
                    f"{flag} [{task.get('id')}] {label} "
                    f"{str(task.get('summary') or task.get('error') or '')[:80]}"
                )
            elif kind == "notice":
                lines.append(f"! [{event.get('task')}] {event.get('level')}: {event.get('message')}")
            elif kind == "dedupe":
                lines.append(f"去重：合并 {event.get('merged')} 条重复上报")
            elif kind == "plan_error":
                lines.append(f"! 规划回退：{event.get('message')}")
        return lines

    def update_tokens(self, usage: dict, token: int) -> None:
        with self._lock:
            if token == self._token:
                self.tokens = {
                    "prompt_tokens": int(usage.get("prompt_tokens", 0)),
                    "completion_tokens": int(usage.get("completion_tokens", 0)),
                    "cache_hit_tokens": int(usage.get("cache_hit_tokens", 0)),
                    "cache_miss_tokens": int(usage.get("cache_miss_tokens", 0)),
                    "estimated_cost": float(usage.get("estimated_cost", 0.0)),
                    "total_tokens": int(usage.get("total_tokens", 0)),
                }

    def finish(
        self,
        result,
        output_path: str,
        token: int,
        submission_path: str = "",
        *,
        partial: bool = False,
    ) -> None:
        """收尾。`partial=True` 表示这次是中断/异常下的部分结果。

        完成与中断都写同一份成果（发现、用量、报告路径），只有 `status`
        与 `partial` 不同——**中断不等于没有成果**，但报告必须写明不完整。
        """
        with self._lock:
            if token != self._token:
                return
            cancelled = self._cancel_event.is_set()
            self.status = STATUS_CANCELLED if (partial or cancelled) else STATUS_DONE
            self.partial = bool(partial or cancelled)
            self.findings = list(getattr(result, "findings", []) or [])
            self.summary = str(getattr(result, "final_summary", "") or "")
            self.output_path = output_path
            self.submission_path = submission_path
            self.tokens = {
                "prompt_tokens": int(getattr(result, "prompt_tokens", 0)),
                "completion_tokens": int(getattr(result, "completion_tokens", 0)),
                "cache_hit_tokens": int(getattr(result, "cache_hit_tokens", 0)),
                "cache_miss_tokens": int(getattr(result, "cache_miss_tokens", 0)),
                "estimated_cost": float(getattr(result, "estimated_cost", 0.0)),
                "total_tokens": int(getattr(result, "total_tokens", 0)),
            }
            self._running = False

    def fail(self, message: str, token: int) -> None:
        with self._lock:
            if token == self._token:
                self.status = STATUS_FAILED
                self.error = message
                self._running = False

    def stop_current(self) -> None:
        """请求停止：进入 `stopping`，由审计线程收尾后转 `cancelled`。

        **不清空已完成的成果**（早先把 summary/error 清成空串，
        于是"跑到一半停下"看起来像"什么都没发生"）。
        """
        with self._lock:
            self._cancel_event.set()
            if self.status == STATUS_RUNNING:
                self.status = STATUS_STOPPING

    def is_stopped(self, token: int) -> bool:
        with self._lock:
            return token != self._token or self._cancel_event.is_set()

    def status_label(self) -> str:
        return STATUS_LABEL.get(self.status, self.status)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self.status,
                "status_label": self.status_label(),
                "partial": self.partial,
                "running": self._running,
                "steps": list(self.steps),
                "findings": list(self.findings),
                "summary": self.summary,
                "error": self.error,
                "output_path": self.output_path,
                "submission_path": self.submission_path,
                "tokens": dict(self.tokens),
                "phases": self.phases(),
            }


STATE = RunState()


def _goal_for(mode: str, path: str, target: str) -> str:
    """审计目标（供编排者/单代理使用）。"""
    if mode == "source":
        return (
            f"审计源码目录 {path}，并对靶场 {target} 做黑盒验证，"
            "只记录有真实请求证据的漏洞。"
        )
    return (
        f"对目标 {target} 做黑盒安全评估（仅限授权 scope，主机白名单见配置），"
        "按 OWASP Top 10 覆盖，只记录有真实请求证据的漏洞。"
    )


def _parse_auth_profile(raw: str, *, label: str = "认证信息") -> dict[str, str]:
    """解析账号 Cookie/Token JSON，例如 `{"Cookie":"session=..."}`。

    校验必须是**严格**的，因为"配置写错了"和"故意匿名测试"在报告里含义完全不同：
    早先非法 JSON 直接返回 `{}`，于是一次配置错误会**静默变成匿名评估**——
    报告里看起来"这些接口匿名也能读"，而真实原因只是 Cookie 没解析成功。
    那是最危险的一类错误方向（把配置错误写成访问控制缺陷）。

    现在：非法 JSON / 顶层不是对象 / 值不是字符串 → 抛 `ValueError`，
    并在**启动审计之前**校验（见 `_validate_run_settings`）。

    **错误信息只包含字段名与类型，绝不回显值**——值里就是 Cookie 与 Token。
    """
    text = str(raw or "").strip()
    if not text:
        return {}  # 空 = 明确的匿名身份，不是错误
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{label} 不是合法 JSON（第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}）。"
            '正确格式形如 {"Cookie":"name=value"}。'
            "如需匿名测试请把该栏留空。"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"{label} 必须是 JSON 对象（形如 {{\"Cookie\":\"name=value\"}}），"
            f"当前是 {type(data).__name__}。"
        )
    profile: dict[str, str] = {}
    for key, value in data.items():
        name = str(key).strip()
        if not name:
            raise ValueError(f"{label} 里有空的请求头名。")
        if not isinstance(value, str):
            # 只报类型，不报值
            raise ValueError(
                f"{label} 的字段 {name!r} 必须是字符串，当前是 {type(value).__name__}。"
            )
        if not value.strip():
            raise ValueError(f"{label} 的字段 {name!r} 是空字符串，请填写或删除该字段。")
        profile[name] = value
    return profile


def _parse_auth_profiles(settings: dict) -> dict[str, dict[str, str]]:
    """解析 A/B 两个身份；任一非法就抛错（由调用方转成用户可见的错误）。"""
    return {
        "A": _parse_auth_profile(settings.get("auth_a", ""), label="身份 A 的 Cookie/Token"),
        "B": _parse_auth_profile(settings.get("auth_b", ""), label="身份 B 的 Cookie/Token"),
    }


def _validate_run_settings(settings: dict) -> dict[str, dict[str, str]]:
    """启动审计**之前**的校验（把配置错误挡在跑之前，而不是让它在报告里变形）。

    两类都校验，**一次报出全部问题**：

    1. 认证身份解析——唯一"错了以后会静默改变结论含义"的配置；
    2. 数值字段（步数/并发/预算上限…）——与 CLI 同一份定义。
       预算护栏填错（例如把 0 不限制写成 -1）必须在启动前拦住。

    返回解析好的身份字典，供 `_run_audit` 复用（避免解析两次）。
    """
    problems: list[str] = []
    try:
        parse_fields(settings)
    except ValueError as exc:
        problems.append(str(exc))
    if str(settings.get("reasoning_effort") or "").strip().lower() not in ("", "low", "high", "max"):
        problems.append("推理强度只能留空（服务端默认）或填写 low / high / max。")
    profiles: dict[str, dict[str, str]] = {}
    try:
        profiles = _parse_auth_profiles(settings)
    except ValueError as exc:
        problems.append(str(exc))
    if problems:
        raise ValueError("配置有误，已阻止启动：" + "；".join(problems))
    return profiles


def _findings_markdown(findings: list[dict], *, title: str) -> str:
    """把发现渲染成可交付的 Markdown（导出用，字段与报告口径一致）。"""
    lines = [f"# {title}", ""]
    verified = [item for item in findings if str(item.get("status")) != "candidate"]
    candidates = [item for item in findings if str(item.get("status")) == "candidate"]
    lines.append(f"- 已复核：{len(verified)} 条")
    lines.append(f"- 待复核候选：{len(candidates)} 条")
    lines.append("")
    lines.append("> 候选项**不是**已确认漏洞；未列出的位置也不代表安全（可能没测到）。")
    lines.append("")
    for label, group in (("已复核发现", verified), ("待复核候选", candidates)):
        if not group:
            continue
        lines.append(f"## {label}")
        lines.append("")
        for item in group:
            lines.append(
                f"### {item.get('id', '')} {item.get('title', '')}"
                f"（{item.get('severity', '')} · {item.get('vuln_type', '')}）"
            )
            lines.append("")
            if item.get("url"):
                lines.append(f"- URL：{item['url']}")
            if item.get("param"):
                lines.append(f"- 参数：{item['param']}")
            if item.get("verification"):
                lines.append(f"- 复核方式：{item['verification']}")
            if item.get("poc_path"):
                lines.append(f"- PoC：{item['poc_path']}")
            evidence = str(item.get("evidence") or item.get("description") or "")
            if evidence:
                lines.append("")
                lines.append("```")
                lines.append(evidence)
                lines.append("```")
            if item.get("counterevidence"):
                lines.append(f"- 反证：{item['counterevidence']}")
            lines.append("")
    return "\n".join(lines)


def _archive_report(artifacts: RunArtifacts, report_path: Path) -> None:
    """把最终报告复制进本次运行的产物目录（历史复盘用）。

    路径刻意是**运行目录根**下的 `report.md`，不是 `write_artifact()` 的
    `artifacts/` 子目录——`history.render_run_report()` 读的就是运行目录根，
    两边不一致时"优先用当时写下的报告原文"会静默失效（实测踩到：
    副本落在 artifacts/ 下，历史面板于是显示成"由快照重渲染"）。

    失败**不影响**审计收尾：报告已经写在输出路径上了，副本只是"历史里也有一份"。
    """
    try:
        text = Path(report_path).read_text(encoding="utf-8")
    except OSError:
        return
    if not getattr(artifacts, "enabled", False):
        return
    try:
        target = Path(artifacts.dir) / "report.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError:
        return


def _mark_partial(result, settings: dict):
    """给"被中断"的结果打上不完整标记（**不得让未测区域看起来像安全**）。

    做法很克制、也很重要：

    1. 在总结最前面加一段醒目的中断说明；
    2. 让报告渲染出"本次运行未完成"；
    3. **绝不**把未完成的端点/参数写成 `no_issue_found`——那会把"没测"
       说成"测过没问题"。这里不新增、也不修改任何 coverage/finding。

    与项目最重要的那条不变量一致：没测到 ≠ 已修复 / 已安全。
    """
    from .agent import AgentResult

    previous_summary = str(getattr(result, "final_summary", "") or "")
    note = (
        "【本次运行被中断，报告不完整】\n"
        "用户在该审计结束前停止了运行。已经完成的步骤、发现、覆盖记录与用量"
        "都**如实保存在本报告中**；但**尚未测试的端点与参数没有被测过**，"
        "它们既不代表安全，也不代表已修复。请把它当作一次未完成的评估，"
        "需要完整结论时请重新运行。\n"
    )
    if isinstance(result, AgentResult):
        result.final_summary = note + ("\n" + previous_summary if previous_summary else "")
        result.finish_reason = "cancelled"
        return result

    # 兜底：极少数情况下 result 不是 AgentResult（例如单代理分支返回别的类型），
    # 就地补两个属性，report 渲染器读的就是它们。
    try:
        result.final_summary = note + ("\n" + previous_summary if previous_summary else "")
        result.finish_reason = "cancelled"
    except Exception:  # noqa: BLE001 标注失败也不能让收尾崩掉
        pass
    return result


def _run_audit(settings: dict, token: int) -> None:
    runtime_sandbox = None
    try:
        allowed = frozenset(
            host
            for host in (_normalize_host(x) for x in settings["allowed_hosts"].split(","))
            if host
        )
        resolved = _resolve_llm_settings(settings)
        if not resolved["api_key"] and resolved["provider"] not in ("ollama", "vllm", "custom"):
            raise ValueError(
                f"请为提供商 {resolved['provider']} 填写 API 密钥"
                "（设置 → 模型提供商，或写入 .env）。"
            )
        if not resolved["model"]:
            raise ValueError("请填写模型名（设置 → 模型提供商）。")
        provider = resolved["provider"]
        preset = get_preset(provider)
        # 参数解析、范围校验与 Config/Budget 构造都走 `runparams`——
        # 与 CLI 同一份字段定义。早先这里手抄了一遍 Config，于是 CLI 支持的
        # token / 模型调用数 / 总时长三个上限在桌面上被静默丢弃（用户以为设了护栏）。
        config = config_from_settings(
            settings,
            api_key=resolved["api_key"],
            base_url=resolved["base_url"] or (preset.base_url if preset else ""),
            model=resolved["model"],
            provider=provider,
            role_models=_role_models(settings),
            allowed_hosts=allowed,
        )
        config.validate()
        target = settings.get("target", "")
        target_host = (urlparse(target).hostname or "").lower()
        if not scope_allows(allowed, target_host):
            raise ValueError(
                f"目标主机 {target_host!r} 不在 ALLOWED_HOSTS 白名单内，请先把它加进去。"
            )
        mode = settings.get("mode", "blackbox")
        swarm = str(settings.get("swarm", "1")) not in ("0", "false", "no", "")
        base_dir = Path(settings.get("path") or "vulnlab") if mode == "source" else Path.cwd()
        # 必须用**同一个**客户端池构造函数：CLI 走 `cli._build_llm_pool`
        # （内含按角色解析 key/base_url 的逻辑），这里是同一个入口。
        # 回归：此处曾调用一个**从未导入**的 `_build_llm_pool`，
        # 于是"从 GUI 启动审计"必定 NameError——GUI 长期没有自动化测试才没被发现。
        from .cli import _build_llm_pool

        llm, llm_pool = _build_llm_pool(config)
        # 身份解析已在 `/api/run` 里预先校验过（错误会以 400 返回给界面）；
        # 这里再解析一次拿到结果——线程里不做"静默降级成匿名"。
        auth_profiles = _parse_auth_profiles(settings)
        if not auth_profiles:
            STATE.add_event(
                {
                    "kind": "notice", "task": "身份", "level": "info",
                    "message": "未配置账号 A/B，当前仅使用匿名身份；需要登录的接口应配置认证信息。",
                },
                token,
            )
        # 预算上限与 CLI 同源（`budget.limits_from_config`），五个上限全部生效。
        budget = Budget(limits_from_config(config))
        budget.on_change(lambda snapshot: STATE.update_tokens(snapshot, token))
        # 把生效中的护栏写进运行记录：用户要能一眼确认"我设的上限真的生效了"，
        # 而不是只能等跑完看用量。0 = 不限制的项不列（列出来反而像设了限制）。
        active_limits = [
            text
            for field, text in (
                (BY_KEY["max_cost"], f"费用 ≤ ¥{config.max_cost:.2f}"),
                (BY_KEY["max_tokens"], f"Token ≤ {config.max_tokens}"),
                (BY_KEY["max_llm_calls"], f"模型调用 ≤ {config.max_llm_calls} 次"),
                (BY_KEY["max_tool_calls"], f"工具调用 ≤ {config.max_tool_calls} 次"),
                (BY_KEY["max_seconds"], f"总时长 ≤ {config.max_seconds:.0f} 秒"),
                (BY_KEY["soft_seconds"], f"软上限 {config.soft_seconds:.0f} 秒（只拦新波次）"),
            )
            if getattr(config, field.key)
        ]
        if scope_unrestricted(allowed):
            STATE.add_event(
                {
                    "kind": "notice",
                    "task": "范围",
                    "level": "warn",
                    "message": (
                        "未限制主机（ALLOWED_HOSTS=*）：任何主机都可能被访问，"
                        "请确认为已授权目标。范围会写进报告。"
                    ),
                },
                token,
            )
        STATE.add_event(
            {
                "kind": "notice",
                "task": "护栏",
                "level": "info",
                "message": "；".join(active_limits) if active_limits else "未设置预算上限（0 = 不限制）",
            },
            token,
        )
        STATE.add_event(
            {
                "kind": "notice", "task": "步数", "level": "info",
                "message": (
                    f"每个子任务最多 {config.task_steps} 个探测步骤，各波次累计；"
                    "单代理最大步数不用于多代理。总量可用模型调用/工具调用/时长上限限制。"
                    if swarm and mode == "blackbox" else
                    f"单代理最多 {config.max_steps} 个探测步骤。"
                ) + "步数用尽后另有至多两轮仅用于保存结论的收尾回合。",
            },
            token,
        )
        STATE.add_event(
            {"kind": "notice", "task": "沙箱", "level": "info", "message": "正在探测已安装的工具环境…"},
            token,
        )
        sandbox = None
        sandbox_setup = None
        try:
            # 与 CLI 共用同一份探测/降级逻辑（桌面端只使用已有镜像，不自动下载）。
            sandbox_setup = prepare_sandbox(
                allowed,
                exec_timeout=max(120, config.request_timeout * 30),
                local_image_only=True,
            )
            sandbox = sandbox_setup.sandbox
            runtime_sandbox = sandbox
            message = sandbox_setup.message()
            if not sandbox_setup.ok and sandbox_setup.hint:
                message = f"{message}｜{sandbox_setup.hint}"
        except Exception as exc:  # noqa: BLE001 环境故障不丢弃内置探测能力
            message = f"真工具沙箱不可用，降级为内置 HTTP 探测：{type(exc).__name__}: {exc}"
        STATE.add_event(
            {"kind": "notice", "task": "沙箱", "level": "info" if sandbox else "warn", "message": _scrub_secrets(message)},
            token,
        )
        artifacts = RunArtifacts(target)
        surface = AttackSurface(
            target=target, mode=mode, path=artifacts.surface_path, allowed_hosts=allowed
        )
        goal = _goal_for(mode, settings.get("path", ""), target)

        def on_step(step: dict) -> None:
            STATE.add_step(step, token)

        def on_event(event: dict) -> None:
            STATE.add_event(event, token)

        callbacks = SwarmCallbacks(on_step=on_step, on_event=on_event,
                                   should_stop=lambda: STATE.is_stopped(token))
        if swarm and mode == "blackbox":
            orchestrator = Orchestrator(
                llm,
                target=target,
                goal=goal,
                mode=mode,
                base_dir=base_dir,
                allowed_hosts=allowed,
                timeout=config.request_timeout,
                max_tasks=config.max_tasks,
                task_steps=config.task_steps,
                parallel=config.parallel,
                budget=budget,
                artifacts=artifacts,
                surface=surface,
                auth_profiles=auth_profiles,
                rate_limit=config.rate_limit,
                callbacks=callbacks,
                memory=HostMemory(target),
                llm_pool=llm_pool,
                sandbox=sandbox,
                sandbox_note=sandbox_setup,
                soft_seconds=getattr(config, "soft_seconds", 0.0),
            )
            result = orchestrator.run()
        else:
            registry = ToolRegistry(
                base_dir=base_dir,
                allowed_hosts=allowed,
                timeout=config.request_timeout,
                mode=mode,
                auth_profiles=auth_profiles,
                surface=surface,
                budget=budget,
                worker_id="W1",
                role="source" if mode == "source" else "blackbox",
                artifacts=artifacts,
                rate_limit=config.rate_limit,
                sandbox=sandbox,
            )
            agent = ReActAgent(
                llm,
                registry,
                max_steps=config.max_steps,
                verbose=False,
                budget=budget,
                target=target,
                role="source" if mode == "source" else "blackbox",
            )
            result = agent.run(
                goal,
                on_step=on_step,
                should_stop=lambda: STATE.is_stopped(token),
            )
            artifacts.save_surface(surface)
            # 单代理路径同样要记录执行环境状态（报告里必须能看出有没有用上真工具）。
            result.sandbox = sandbox_report(
                sandbox,
                reason=sandbox_setup.reason if sandbox_setup else "",
                hint=sandbox_setup.hint if sandbox_setup else "",
                tools=sandbox_setup.tools if sandbox_setup else (),
            )
        # ---- 收尾：**无论正常结束、用户中断还是异常，都要落盘成果** ----
        #
        # 早先这里是 `if STATE.is_stopped(token): return`——按下停止之后
        # 连报告都不写，已经跑出来的发现、用量与覆盖率全部丢掉。
        # 那正是 P1-5 要修的第一件事：中断时成果必须保存，且报告要**写明不完整**。
        interrupted = STATE.is_stopped(token)
        output_value = settings.get("output") or DEFAULTS["output"]
        output_path = Path(output_value)
        if not output_path.is_absolute():
            output_path = PROJECT_ROOT / output_path
        if interrupted:
            result = _mark_partial(result, settings)
        output = write_report(result, goal, output_path)
        package = write_butian_package(result, output)
        # 把这一份报告存进**本次运行的产物目录**：默认输出路径是固定的
        # `reports/report.md`，下一次运行就覆盖了——所以"历史里还能看到当时的报告"
        # 必须有一份随运行目录走的副本。
        _archive_report(artifacts, output)
        STATE.finish(
            result,
            str(output),
            token,
            submission_path=str(package) if package else "",
            partial=interrupted,
        )
    except Exception as exc:  # noqa: BLE001  # 后台线程兜底，任何异常转成界面错误
        STATE.fail(_scrub_secrets(f"{type(exc).__name__}: {exc}"), token)
    finally:
        if runtime_sandbox is not None:
            try:
                # stop 只回收本次创建的容器；WSL 后端不停止或删除发行版。
                runtime_sandbox.stop()
            except Exception:  # noqa: BLE001 清理失败不能覆盖审计成果
                pass

def create_app() -> Flask:
    app = Flask(__name__)
    #: 每次启动换一次；只有真正渲染出来的那个页面知道它（见 `index`）。
    local_token = secrets.token_urlsafe(32)
    app.config["HEXHOUND_LOCAL_TOKEN"] = local_token

    def _deny(reason: str):
        return jsonify({"error": reason}), 403

    @app.before_request
    def _guard_local_control_plane():
        """本机控制面的准入检查：Host 只能是本机 + 有副作用请求必须带会话令牌。

        这两条都不是"洁癖"，对应两个真实可利用的场景（见模块顶部常量注释）：
        DNS rebinding 读走配置；恶意页面借本机发起审计/改配置/弹登录窗。
        """
        if _request_hostname() not in _LOCAL_HOSTS:
            return _deny("拒绝访问：本机控制面只接受 127.0.0.1 / localhost。")
        origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
        if origin and (urlparse(origin).hostname or "").lower() not in _LOCAL_HOSTS:
            return _deny("拒绝访问：请求来源不是本机页面。")
        if request.method != "GET" and request.headers.get(TOKEN_HEADER) != local_token:
            return _deny("拒绝执行：缺少本机会话令牌，请在本程序窗口内操作。")
        return None

    @app.route("/")
    def index() -> str:
        return render_template_string(HTML, local_token=local_token, **_settings_payload())

    @app.route("/api/providers")
    def providers_api() -> str:
        """预设清单 + 当前生效提供商 + 已保存密钥的**掩码**。

        这里**绝不回传明文密钥**。早先为了"一键填入密钥框"而回传了明文 `keys`，
        等于把 `settings.json` 里的凭据通过 HTTP 暴露给任何能访问本机端口的
        东西（含 DNS rebinding 页面）。现在改成：只回显掩码与"是否已保存"，
        真正要用密钥时由**服务端**按 provider 取（`/api/provider_test`、
        `_resolve_llm_settings`），密钥不再经过浏览器。
        """
        stored = _load_settings()
        saved = _provider_keys()
        masked = {key: mask_key(value) for key, value in saved.items()}
        active = _active_provider(stored)
        protected_ok, protection_reason = secretstore.protection_available()
        return jsonify(
            {
                "presets": describe_presets(),
                "active": active,
                "keys_masked": masked,
                "keys_saved": {key: True for key in saved},
                # 密钥在磁盘上是否加密保存，以及有没有解密失败——
                # "密钥突然没了"必须能查出原因，而不是让用户以为从没配过。
                "keys_encrypted_at_rest": protected_ok,
                "protection_note": protection_reason,
                "keystore_error": _KEYSTORE_NOTE,
                "env_keys": {
                    preset["key"]: bool(os.getenv(preset["env_key"], "").strip())
                    for preset in describe_presets()
                },
                "shared_key": bool(os.getenv("LLM_API_KEY", "").strip()),
                "pricing_known": pricing_known(active),
                "pricing": pricing_for(active),
            }
        )

    @app.route("/api/provider_key", methods=["POST"])
    def provider_key_api() -> str:
        """记住某个提供商的密钥（存进 settings.json 的 provider_keys）。"""
        data = request.get_json(force=True) or {}
        provider = resolve_provider(data.get("provider", ""))
        api_key = str(data.get("api_key") or "").strip()
        if not api_key:
            return jsonify({"error": "密钥为空。"}), 400
        if _looks_like_mask(api_key):
            return (
                jsonify(
                    {
                        "error": "这看起来是界面回显的掩码（含 …），不是真实密钥。"
                        "密钥已在服务端保存，留空即可继续使用；要换密钥请粘贴完整密钥。"
                    }
                ),
                400,
            )
        stored = _load_settings()
        try:
            keys = json.loads(stored.get("provider_keys") or "{}")
        except json.JSONDecodeError:
            keys = {}
        if not isinstance(keys, dict):
            keys = {}
        keys[provider] = api_key
        stored["provider_keys"] = json.dumps(keys, ensure_ascii=False)
        _save_settings(stored)
        return jsonify({"ok": True, "provider": provider, "masked": mask_key(api_key)})

    @app.route("/api/provider_test", methods=["POST"])
    def provider_test_api() -> str:
        """对指定提供商发一次最小请求，验证 key/URL/模型名是否可用。"""
        data = request.get_json(force=True) or {}
        provider = resolve_provider(data.get("provider", ""))
        preset = get_preset(provider)
        model = str(data.get("model") or "").strip() or (preset.default_model if preset else "")
        base_url = normalize_base_url(
            data.get("base_url") or (preset.base_url if preset else "")
        )
        api_key = (
            str(data.get("api_key") or "").strip()
            or _provider_keys().get(provider, "")
            or os.getenv(env_key_name(provider), "").strip()
            or os.getenv("LLM_API_KEY", "").strip()
        )
        if not model:
            return jsonify({"error": "请先填写模型名。"}), 400
        if not base_url:
            return jsonify({"error": "请先填写 base_url（自定义提供商必填）。"}), 400
        if not api_key and provider not in ("ollama", "vllm", "custom"):
            return jsonify({"error": f"请先填写 {provider} 的 API 密钥。"}), 400
        try:
            client = LLMClient(
                api_key, base_url, model, provider=provider, timeout=25,
                reasoning_effort=data.get("reasoning_effort", _load_settings().get("reasoning_effort", "")),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            check = client.test_connection()
        except Exception as exc:  # noqa: BLE001 兜底：任何异常都转成可读结论
            # 打码后再返回：提供商的鉴权报错经常原样回显 key。
            return jsonify({"error": _scrub_secrets(f"{type(exc).__name__}: {exc}", api_key)}), 500
        payload = check.to_dict()
        # 只回掩码：界面据此显示"已保存 sk-123…abcd"，明文不出服务端。
        payload["masked"] = mask_key(api_key)
        return jsonify(payload)

    @app.route("/api/write_env", methods=["POST"])
    def write_env_api() -> str:
        """把当前提供商设置写进 .env（保留其它键；先备份原文件）。"""
        data = request.get_json(force=True) or {}
        effort = str(data.get("reasoning_effort", _load_settings().get("reasoning_effort", "")) or "").strip().lower()
        if effort not in ("", "low", "high", "max"):
            return jsonify({"error": "推理强度只能留空（服务端默认）或填写 low / high / max。"}), 400
        resolved = _resolve_llm_settings(data)
        updates = {
            "LLM_PROVIDER": resolved["provider"],
            "LLM_MODEL": resolved["model"],
            "LLM_BASE_URL": resolved["base_url"],
            "LLM_API_KEY": resolved["api_key"],
            "LLM_REASONING_EFFORT": effort,
        }
        if resolved["provider"] not in ("ollama", "vllm", "custom") and resolved["api_key"]:
            updates[env_key_name(resolved["provider"])] = resolved["api_key"]
        for role, model in _role_models(data).items():
            updates[f"LLM_{role.upper()}_MODEL"] = model
        try:
            # 写到「当前工作目录」的 .env（打包运行时即 exe 所在目录），
            # 与 config.env_file_candidates() 的第一优先级保持一致。
            target, changed = write_env_file(updates, Path.cwd() / ".env")
        except OSError as exc:
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
        return jsonify(
            {
                "ok": True,
                "path": str(target),
                "message": f"已写入 {target}（更新 {len(changed)} 项：{', '.join(changed)}）",
            }
        )

    @app.route("/api/save", methods=["POST"])
    def save() -> str:
        data = request.get_json(force=True) or {}
        _save_settings(data)
        return jsonify({"ok": True})

    @app.route("/api/run", methods=["POST"])
    def run() -> str:
        data = request.get_json(force=True) or {}
        # 先校验再落盘：配置错误必须以 **400 + 明确原因** 返回给界面，
        # 而不是保存下来、然后在后台线程里静默降级成匿名评估。
        try:
            _validate_run_settings(data)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        # 同一个运行未停止前不允许重复启动（否则两个审计线程会同时改同一份
        # 攻面与产物目录，用量与结论互相污染）。
        if not STATE.try_begin():
            return (
                jsonify({"error": "已有审计任务在运行或正在停止，请先等待其结束或点击停止。"}),
                409,
            )
        try:
            _save_settings(data)
            token = STATE.start()
        except Exception as exc:  # noqa: BLE001 落盘失败要把占位释放掉
            STATE.abort_begin()
            return jsonify({"error": f"保存配置失败：{exc}"}), 500
        threading.Thread(target=_run_audit, args=(data, token), daemon=True).start()
        return jsonify({"ok": True, "token": token})

    @app.route("/api/stop", methods=["POST"])
    def stop() -> str:
        STATE.stop_current()
        return jsonify({"ok": True})

    @app.route("/api/capture_login", methods=["POST"])
    def capture_login():
        data = request.get_json(force=True) or {}
        url = str(data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "缺少登录 URL。"}), 400
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        allowed_raw = str(data.get("allowed_hosts") or DEFAULTS["allowed_hosts"])
        allowed = frozenset(
            _normalize_host(item) for item in allowed_raw.split(",") if item.strip()
        )
        if parsed.scheme not in ("http", "https") or not host or not scope_allows(allowed, host):
            return jsonify({"error": "登录 URL 不在 ALLOWED_HOSTS 白名单内。"}), 400
        timeout = int(str(data.get("timeout") or "300"))
        timeout = max(60, min(timeout, 600))
        try:
            result = capture_login_state(url, timeout_sec=timeout)
        except Exception as exc:  # noqa: BLE001  # 登录窗口异常兜底
            detail = f"{type(exc).__name__}: {exc}"
            return jsonify({"error": _scrub_secrets(detail)}), 500
        return jsonify(result)

    @app.route("/api/status")
    def status() -> str:
        return jsonify(STATE.snapshot())

    @app.route("/api/history")
    def history_api() -> str:
        """历史运行清单（只读磁盘：不调模型、不访问目标）。

        这就是"关掉程序再打开还能看到上次跑了什么"的入口。
        """
        limit = request.args.get("limit", "30")
        try:
            count = max(1, min(int(limit), 200))
        except (TypeError, ValueError):
            count = 30
        return jsonify(
            {
                "runs": history.list_runs(limit=count, target=request.args.get("target", "")),
                "status_labels": history.STATUS_LABEL,
            }
        )

    @app.route("/api/history/<run_id>")
    def history_detail_api(run_id: str) -> str:
        """某次历史运行的报告（原文优先，缺失时离线重渲染）。"""
        detail = history.run_detail(run_id)
        if detail is None:
            return jsonify({"error": "找不到这次运行的产物目录。"}), 404
        return jsonify(detail)

    def _findings_for(run: str) -> tuple[list[dict], str, str]:
        """取某次运行的发现：`current`（内存）或历史运行目录。

        返回 `(findings, 来源说明, 错误)`；错误非空时应回 404。
        历史来源**只读磁盘**——复盘不该产生新的流量或费用。
        """
        if run in ("", "current"):
            return list(STATE.findings or []), "current", ""
        findings, source = history.run_findings_with_source(run)
        if source == "none":
            detail = history.run_detail(run)
            if detail is None:
                return [], "", "找不到这次运行的产物目录。"
        return findings, source, ""

    @app.route("/api/findings")
    def findings_api() -> str:
        """某次运行的发现清单（`?run=current|<历史目录名>`）。

        界面据此做筛选与详情展示；历史运行走同一条路径，
        因此"看上次的发现"与"看本次的发现"用同一套字段。
        """
        run = request.args.get("run", "current").strip()
        findings, source, error = _findings_for(run)
        if error:
            return jsonify({"error": error}), 404
        return jsonify({"run": run or "current", "source": source, "findings": findings})

    @app.route("/api/compare")
    def compare_api() -> str:
        """把**本次**发现与某次历史运行对比（新增 / 仍存在 / 疑似已修复 / 无法判定）。

        复用 `diff.diff_findings`：判定顺序（指纹 → 类别+路径 → 端点是否仍报问题）
        本身就是要守住的东西，界面上另写一套判断只会漂移。
        """
        against = request.args.get("with", "").strip()
        if not against:
            return jsonify({"error": "缺少 with 参数（要对比的历史运行目录名）。"}), 400
        previous, previous_source = history.run_findings_with_source(against)
        if previous_source == "none" and history.run_detail(against) is None:
            return jsonify({"error": "找不到这次运行的产物目录。"}), 404
        current = list(STATE.findings or [])
        summary = history.run_summary(against)
        result = diff_findings(
            previous,
            current,
            target=str(summary.get("target") or ""),
        )
        payload = result.to_dict()
        payload["against"] = against
        payload["against_source"] = previous_source
        payload["current_count"] = len(current)
        payload["previous_count"] = len(previous)
        return jsonify(payload)

    @app.route("/api/export")
    def export_api() -> str:
        """导出某次运行的**发现清单**（`format=json|markdown`）。只读，不触网。

        刻意只导出发现清单，不管目标是本次还是历史运行——格式与字段可预测，
        界面上的筛选/详情看的就是同一份数据。
        **完整报告**是另一个入口（`查看完整报告` / `/api/history/<run>`），
        它可能包含报告正文与附录，与本接口的用途不同。
        """
        run = request.args.get("run", "current").strip() or "current"
        fmt = request.args.get("format", "json").strip().lower()
        findings, source, error = _findings_for(run)
        if error:
            return jsonify({"error": error}), 404
        if fmt not in ("json", "markdown", "md"):
            return jsonify({"error": "format 只能是 json 或 markdown。"}), 400
        if fmt == "json":
            body = json.dumps(
                {
                    "run": run,
                    "source": source,
                    "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "findings": findings,
                },
                ensure_ascii=False,
                indent=2,
            )
            mimetype, suffix = "application/json", "json"
        else:
            where = "本次运行" if run == "current" else f"历史运行 {run}"
            body = _findings_markdown(findings, title=f"{where}的发现（来源：{source}）")
            mimetype, suffix = "text/markdown", "md"
        safe_name = re.sub(r"[^A-Za-z0-9_.\-]", "_", run) or "current"
        response = app.response_class(body, mimetype=mimetype)
        response.headers["Content-Disposition"] = (
            f"attachment; filename=hexhound_findings_{safe_name}.{suffix}"
        )
        return response

    @app.route("/api/report")
    def report() -> str:
        output = STATE.output_path
        if output and Path(output).exists():
            return jsonify({"markdown": Path(output).read_text(encoding="utf-8")})
        return jsonify({"markdown": ""})

    @app.route("/api/submission")
    def submission():
        package = STATE.submission_path
        if package and Path(package).exists():
            try:
                response = send_file(
                    package,
                    mimetype="application/zip",
                    as_attachment=True,
                )
                response.headers["Content-Disposition"] = (
                    f"attachment; filename={Path(package).name}"
                )
                return response
            except Exception as exc:  # noqa: BLE001  # 下载接口兜底
                return jsonify({"error": f"下载提交包失败：{exc}"}), 500
        return jsonify({"error": "暂无补天提交包。"}), 404

    @app.route("/api/screenshot", methods=["POST"])
    def screenshot() -> str:
        data = request.get_json(force=True) or {}
        url = str(data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "缺少目标 URL。"}), 400
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        allowed_raw = str(data.get("allowed_hosts") or DEFAULTS["allowed_hosts"])
        allowed = frozenset(
            _normalize_host(item) for item in allowed_raw.split(",") if item.strip()
        )
        if parsed.scheme not in ("http", "https") or not host or not scope_allows(allowed, host):
            return jsonify({"error": "目标 URL 不在 ALLOWED_HOSTS 白名单内。"}), 400
        try:
            timeout = int(str(data.get("request_timeout") or "30"))
            timeout = max(5, min(timeout, 120))
            image_bytes = capture_url(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001  # 截图接口兜底
            detail = f"{type(exc).__name__}: {exc}"
            return jsonify({"error": _scrub_secrets(detail)}), 500

        question = str(data.get("question") or "请描述这个页面，并指出可能存在漏洞的可疑点。")
        answer = "截图成功。"
        api_key = os.getenv("VISION_API_KEY", "")
        if api_key:
            try:
                client = VisionClient(
                    api_key,
                    os.getenv(
                        "VISION_BASE_URL",
                        "https://dashscope.aliyuncs.com/compatible-mode/v1",
                    ),
                    os.getenv("VISION_MODEL", "qwen3-vl-235b-a22b-thinking"),
                )
                answer = client.analyze(image_bytes, "image/png", question)
            except Exception as exc:  # noqa: BLE001  # 视觉接口兜底
                detail = _scrub_secrets(f"{type(exc).__name__}: {exc}")
                answer = f"截图成功，但视觉分析失败：{detail}"
        else:
            answer = "截图成功；未配置 VISION_API_KEY，无法自动分析。"

        return jsonify(
            {
                "image_base64": base64.b64encode(image_bytes).decode("ascii"),
                "mime_type": "image/png",
                "answer": answer,
            }
        )

    @app.route("/api/vision", methods=["POST"])
    def vision() -> str:
        data = request.get_json(force=True) or {}
        api_key = os.getenv("VISION_API_KEY", "")
        if not api_key:
            return jsonify({"error": "未配置 VISION_API_KEY，请在 .env 中填写。"}), 400
        image_b64 = data.get("image_base64", "")
        if not image_b64:
            return jsonify({"error": "缺少图片。"}), 400
        base_url = os.getenv(
            "VISION_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"
        )
        model = os.getenv("VISION_MODEL", "qwen3-vl-235b-a22b-thinking")
        question = str(data.get("question") or "请描述这张图片。")
        mime = str(data.get("mime_type") or "image/png")
        try:
            image_bytes = base64.b64decode(image_b64)
            client = VisionClient(api_key, base_url, model)
            answer = client.analyze(image_bytes, mime, question)
            return jsonify({"answer": answer})
        except Exception as exc:  # noqa: BLE001  # 视觉接口兜底
            detail = f"{type(exc).__name__}: {exc}"
            return jsonify({"error": _scrub_secrets(detail, api_key)}), 500

    return app


def run_server(host: str = "127.0.0.1", port: int = 5001) -> None:
    app = create_app()
    print(f"HexHound GUI 已启动：http://{host}:{port}")
    print("按 Ctrl+C 退出。")
    app.run(host=host, port=port, threaded=True, debug=False)
