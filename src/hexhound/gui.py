"""HexHound 图形化界面（Flask）：可视化配置 + 运行 + 结果展示，并记住上次设置。

运行：hexhound gui  （需要 flask，pip install -e ".[lab]"）
设置持久化在 ~/.hexhound/settings.json，下次打开自动回填。
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template_string, request, send_file

from .agent import ReActAgent
from .budget import Budget, BudgetLimits
from .config import (
    ROLES,
    Config,
    _normalize_host,
    normalize_base_url,
    resolve_provider,
    write_env_file,
)
from .llm import LLMClient, build_llm_pool
from .login import capture_login_state
from .memory import HostMemory, RunArtifacts
from .orchestrator import (
    DEFAULT_TASK_STEPS,
    MAX_PARALLEL,
    MAX_TASKS,
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
SETTINGS_PATH = Path.home() / ".hexhound" / "settings.json"

DEFAULTS = {
    # 刻意留空：不预设提供商/模型/密钥，避免"没注意就按某家付费模型跑起来"。
    # 首次打开时面板会引导选择（或从 .env 读取）。
    "api_key": "",
    "base_url": "",
    "model": "",
    "provider": "",
    "provider_keys": "{}",
    "temperature": "0.2",
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
    # 多代理编排与预算
    "max_tasks": "6",
    "task_steps": "10",
    "parallel": "3",
    "max_cost": "0",
    "rate_limit": "0",
    "swarm": "1",
}

HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HexHound 控制台</title>
<style>
  :root { --bg:#0f1420; --panel:#1a2130; --line:#2b3547; --fg:#e6ebf2; --muted:#8b98ad;
          --accent:#4f8cff; --ok:#3fb950; --err:#f85149; --warn:#d29922; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.6 "Segoe UI",system-ui,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--line); display:flex; align-items:baseline; gap:12px; }
  header h1 { margin:0; font-size:20px; }
  header span { color:var(--muted); }
  main { display:grid; grid-template-columns:360px 1fr; gap:20px; padding:20px 24px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px; }
  .panel h2 { margin:0 0 14px; font-size:15px; color:var(--fg); }
  label { display:block; margin:10px 0 4px; color:var(--muted); font-size:12px; }
  input, select { width:100%; padding:8px 10px; background:#0c111b; color:var(--fg);
    border:1px solid var(--line); border-radius:6px; font-size:13px; }
  input:focus, select:focus { outline:none; border-color:var(--accent); }
  .row { display:flex; gap:10px; }
  .row > div { flex:1; }
  button { cursor:pointer; border:0; border-radius:6px; padding:10px 16px; font-size:14px; font-weight:600; }
  #runBtn { background:var(--accent); color:#fff; width:100%; margin-top:16px; }
  #saveBtn { background:var(--line); color:var(--fg); width:100%; margin-top:8px; }
  button:disabled { opacity:.55; cursor:not-allowed; }
  #status { margin:12px 0; font-size:13px; }
  #status.running { color:var(--accent); }
  #status.done { color:var(--ok); }
  #status.error { color:var(--err); }
  #log { background:#0c111b; border:1px solid var(--line); border-radius:8px; padding:12px;
    height:320px; overflow:auto; font:12px/1.5 Consolas,monospace; white-space:pre-wrap; word-break:break-all; }
  .step { margin:0 0 12px; padding:10px; border-left:3px solid var(--accent); background:#121826; border-radius:6px; }
  .step .a { color:var(--accent); font-weight:600; }
  .step .t { color:var(--muted); }
  .finding { border-left:3px solid var(--err); padding:12px; margin:10px 0; background:#1a1215; border-radius:6px; }
  .finding b { color:var(--warn); }
  .tag { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; background:var(--line); color:var(--fg); }
  .muted { color:var(--muted); }
  pre.raw { background:#0c111b; padding:12px; border-radius:8px; overflow:auto; max-height:400px; font:12px/1.5 Consolas,monospace; }
  .shot-preview { margin-top:10px; }
  .shot-preview img { display:block; max-width:100%; border:1px solid var(--line); border-radius:8px; background:#0c111b; }
  .hint { color:var(--muted); font-size:12px; margin-top:8px; }
  .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; align-items:center; justify-content:center; z-index:20; }
  .modal { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:20px; width:min(480px,92vw); max-height:90vh; overflow:auto; }
  .modal h2 { margin:0 0 14px; font-size:16px; }
  .modal .actions { display:flex; gap:10px; justify-content:flex-end; margin-top:16px; }
  @media (max-width: 900px) { main { grid-template-columns:1fr; } }
</style>
</head>
<body>
<header><h1>🐕‍🦺 HexHound</h1><span>AI 驱动的漏洞挖掘 · 图形控制台</span><span id="tokenStats" class="muted" style="margin-left:16px;font-size:12px;">Token：输入 0 / 输出 0 / 缓存命中 0 / 未命中 0 · 预估 ¥0.000000</span></header>
<main>
  <div class="panel">
    <h2>配置</h2>
    <form id="cfg">
      <label>模式</label>
      <select name="mode">
        <option value="blackbox" {% if settings.mode == 'blackbox' %}selected{% endif %}>blackbox（纯 URL 黑盒）</option>
        <option value="source" {% if settings.mode == 'source' %}selected{% endif %}>source（源码审计）</option>
      </select>
      <label>编排方式</label>
      <select name="swarm">
        <option value="1" {% if settings.swarm != '0' %}selected{% endif %}>多代理编排（规划 + 并发子代理 + 复核）</option>
        <option value="0" {% if settings.swarm == '0' %}selected{% endif %}>单代理 ReAct（v0.1 行为）</option>
      </select>
      <label>目标 URL</label>
      <input name="target" value="{{ settings.target }}" placeholder="https://授权目标">
      <label>源码目录（source 模式用）</label>
      <input name="path" value="{{ settings.path }}">
      <div class="row">
        <div><label>MAX_STEPS（单代理）</label><input name="max_steps" value="{{ settings.max_steps }}"></div>
        <div><label>REQUEST_TIMEOUT</label><input name="request_timeout" value="{{ settings.request_timeout }}"></div>
      </div>
      <div class="row">
        <div><label>MAX_TASKS</label><input name="max_tasks" value="{{ settings.max_tasks }}"></div>
        <div><label>TASK_STEPS</label><input name="task_steps" value="{{ settings.task_steps }}"></div>
        <div><label>PARALLEL</label><input name="parallel" value="{{ settings.parallel }}"></div>
      </div>
      <div class="row">
        <div><label>MAX_COST（¥，0=不限）</label><input name="max_cost" value="{{ settings.max_cost }}"></div>
        <div><label>RATE_LIMIT（秒）</label><input name="rate_limit" value="{{ settings.rate_limit }}"></div>
      </div>
      <label>ALLOWED_HOSTS（逗号分隔，只填主机名）</label>
      <input name="allowed_hosts" value="{{ settings.allowed_hosts }}">
      <button type="button" id="runBtn">开始审计</button>
      <button type="button" id="stopBtn" disabled style="background:var(--err);color:#fff;width:100%;margin-top:8px;">中断当前任务</button>
      <button type="button" id="saveBtn">仅保存设置</button>
      <button type="button" id="settingsBtn" style="background:var(--line);color:var(--fg);width:100%;margin-top:8px;">设置</button>
      <div class="hint">设置保存在 ~/.hexhound/settings.json，下次打开自动回填。密钥以明文存储，请勿在公用机器上使用。</div>
    </form>
  </div>
  <div class="panel">
    <h2>运行</h2>
    <div id="status">空闲</div>
    <div id="log"></div>
    <div id="results"></div>
    <div id="reportSection" style="margin-top:14px;">
      <button type="button" id="reportBtn" style="background:var(--line);color:var(--fg);">查看完整报告</button>
      <pre class="raw" id="reportView" style="display:none;margin-top:10px;"></pre>
    </div>
    <hr style="border:0;border-top:1px solid var(--line);margin:18px 0;">
    <h2>识图（多模态分析）</h2>
    <input type="file" id="imgInput" accept="image/*">
    <label>直接截图目标 URL</label>
    <div class="row">
      <input id="shotUrl" value="{{ settings.target }}" placeholder="http://127.0.0.1:5000">
      <button type="button" id="shotBtn" style="background:var(--line);color:var(--fg);white-space:nowrap;">截图并分析</button>
    </div>
    <label>提问（可选）</label>
    <input id="imgQuestion" placeholder="例如：这张页面有什么可疑点 / 有没有报错信息？">
    <button type="button" id="visionBtn" style="background:var(--line);color:var(--fg);margin-top:8px;">分析图片</button>
    <div id="shotPreview" class="shot-preview"></div>
    <div id="visionResult" class="muted" style="margin-top:10px;white-space:pre-wrap;"></div>
  </div>
</main>
<div class="modal-overlay" id="settingsModal">
  <div class="modal">
    <h2>设置</h2>
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
      <div class="row" style="margin-top:8px;">
        <button type="button" id="testBtn" style="background:var(--line);color:var(--fg);flex:1;">测试连接</button>
        <button type="button" id="fillKeyBtn" style="background:var(--line);color:var(--fg);flex:1;">填入该提供商密钥</button>
        <button type="button" id="envBtn" style="background:var(--line);color:var(--fg);flex:1;">写入 .env</button>
      </div>
      <div id="testResult" class="hint"></div>
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
</div>
<script>
window.addEventListener("load", () => {
  fetch("/api/stop", {method: "POST", keepalive: true}).catch(() => {});
});
window.addEventListener("beforeunload", () => {
  if (navigator.sendBeacon) {
    navigator.sendBeacon("/api/stop", new Blob(["{}"], {type: "application/json"}));
  }
});
const $ = (s) => document.querySelector(s);
let zoomLevel = parseFloat("{{ settings.zoom }}") || 1;
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
async function post(url, data) {
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  return r.json();
}
function renderStep(s) {
  const d = document.createElement('div');
  d.className = 'step';
  const act = s.action || '?';
  const who = s.worker ? `<span class="tag">${escapeHtml(s.worker)}</span> ` : '';
  const role = s.role ? `<span class="tag">${escapeHtml(s.role)}</span> ` : '';
  const thought = s.thought ? `<div class="t">思考：${escapeHtml(s.thought)}</div>` : '';
  const obs = s.observation ? `<div>观察：${escapeHtml(String(s.observation).slice(0, 600))}</div>` : '';
  d.innerHTML = `<div class="a">${who}${role}Step ${s.step} · ${escapeHtml(act)}</div>${thought}${obs}`;
  return d;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function renderFindings(list) {
  const box = $('#results');
  if (!list.length) { box.innerHTML = ''; return; }
  const verified = list.filter(f => f.status !== 'candidate');
  const candidates = list.filter(f => f.status === 'candidate');
  const card = (f) => `
    <div class="finding" style="${f.status === 'candidate' ? 'border-left-color:var(--warn);opacity:.9' : ''}">
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
}
async function loadReport() {
  const view = $('#reportView');
  const r = await fetch('/api/report');
  const j = await r.json();
  view.textContent = j.markdown || '暂无报告';
  view.style.display = 'block';
}
let timer = null;
function poll() {
  fetch('/api/status').then(r => r.json()).then(s => {
    const st = $('#status');
    if (s.status === 'running') { st.className = 'running'; st.textContent = '运行中…'; }
    else if (s.status === 'done') { st.className = 'done'; st.textContent = '完成 [OK]'; }
    else if (s.status === 'error') { st.className = 'error'; st.textContent = '出错：' + s.error; }
    else { st.className = ''; st.textContent = '空闲'; }
    $('#stopBtn').disabled = s.status !== 'running';
    const tok = s.tokens || {};
    const cost = Number(tok.estimated_cost || 0).toFixed(6);
    $('#tokenStats').textContent = `Token：输入 ${tok.prompt_tokens ?? 0} / 输出 ${tok.completion_tokens ?? 0} / 缓存命中 ${tok.cache_hit_tokens ?? 0} / 未命中 ${tok.cache_miss_tokens ?? 0} · 预估 ¥${cost}`;
    const log = $('#log');
    log.innerHTML = '';
    const phases = s.phases || [];
    if (phases.length) {
      const box = document.createElement('div');
      box.className = 'step';
      box.innerHTML = `<div class="a">编排进度</div><div class="t" style="white-space:pre-wrap">${escapeHtml(phases.join('\n'))}</div>`;
      log.appendChild(box);
    }
    for (const step of s.steps) log.appendChild(renderStep(step));
    log.scrollTop = log.scrollHeight;
    if (s.status === 'done') {
      renderFindings(s.findings);
      $('#results').innerHTML += `<h2>总结</h2><div class="muted">${escapeHtml(s.summary || '')}</div>`;
      $('#results').innerHTML += `<div class="hint">完整报告已写入 ${escapeHtml(s.output_path || '')}</div>`;
      if (s.submission_path) {
        $('#results').innerHTML += `<div class="hint"><a href="/api/submission">下载补天提交包</a></div>`;
      }
      loadReport();
      if (timer) { clearInterval(timer); timer = null; }
    } else if (s.status === 'running') {
      if (!timer) timer = setInterval(poll, 800);
    }
  });
}
$('#saveBtn').onclick = async () => {
  await post('/api/save', collect());
  $('#status').textContent = '设置已保存';
  await loadProviders();
};
$('#settingsBtn').onclick = async () => {
  $('#settingsModal').style.display = 'flex';
  await loadProviders();
};

/* ---------- 模型提供商面板 ---------- */
let PROVIDERS = [];
let PROVIDER_STATE = {active: '', keys: {}};

function currentProvider() {
  return $('#providerSelect').value || 'custom';
}
function presetOf(key) {
  return PROVIDERS.find(p => p.key === key) || null;
}
def renderProviderOptions() {
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
  const preset = presetOf(currentProvider());
  if (!preset) return;
  if (fillUrl && preset.base_url) $('#baseUrlInput').value = preset.base_url;
  if (fillModel && preset.default_model) $('#modelInput').value = preset.default_model;
  $('#modelOptions').innerHTML = (preset.models || []).map(m => `<option value="${escapeHtml(m)}"></option>`).join('');
  const keyHint = preset.key_required
    ? `需要 key（${escapeHtml(preset.key_style)}…）${preset.api_key_url ? ` · <a href="${preset.api_key_url}" target="_blank" rel="noreferrer">获取密钥</a>` : ''}`
    : '该提供商无需密钥';
  $('#providerNote').innerHTML = keyHint + (preset.note ? `<br>${escapeHtml(preset.note)}` : '');
  const saved = PROVIDER_STATE.keys[preset.key];
  $('#keyState').textContent = saved ? `（已保存 ${escapeHtml(saved)}）` : '';
  if (saved && !$('#apiKeyInput').value) $('#apiKeyInput').value = saved;
}
function renderRoleModels() {
  const spec = {{ role_labels|tojson }};
  const box = $('#roleModelBox');
  box.innerHTML = Object.entries(spec).map(([role, label]) => `
    <label style="margin-top:8px;">${escapeHtml(label)}</label>
    <input name="role_model_${role}" data-role="${role}" placeholder="留空 = 跟随上面的默认模型">`).join('');
  const saved = {{ settings.role_models|tojson }};
  for (const [role, model] of Object.entries(saved || {})) {
    const input = box.querySelector(`input[data-role="${role}"]`);
    if (input) input.value = model;
  }
}
async function loadProviders() {
  try {
    const r = await fetch('/api/providers');
    const j = await r.json();
    PROVIDERS = j.presets || [];
    PROVIDER_STATE = {active: j.active || '', keys: j.keys || {}};
  } catch (error) {
    PROVIDER_STATE = {active: '', keys: {}};
  }
  renderProviderOptions();
  applyPreset({fillModel: false, fillUrl: false});
  renderRoleModels();
}
$('#providerSelect').onchange = () => { applyPreset(); };
$('#fillKeyBtn').onclick = () => {
  const saved = PROVIDER_STATE.keys[currentProvider()];
  if (!saved) { $('#testResult').textContent = '该提供商还没有保存过密钥，请直接粘贴。'; return; }
  $('#apiKeyInput').value = saved;
  $('#testResult').textContent = '已填入保存的密钥。';
};
$('#testBtn').onclick = async () => {
  const out = $('#testResult');
  out.textContent = '正在测试连接…';
  $('#testBtn').disabled = true;
  const r = await fetch('/api/provider_test', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      provider: currentProvider(),
      model: $('#modelInput').value.trim(),
      base_url: $('#baseUrlInput').value.trim(),
      api_key: $('#apiKeyInput').value.trim()
    })
  });
  const j = await r.json();
  $('#testBtn').disabled = false;
  if (j.error) { out.textContent = '测试失败：' + j.error; return; }
  out.innerHTML = (j.ok ? '✅ ' : '❌ ') + escapeHtml(j.message || '').replace(/\n/g, '<br>')
    + (j.usage ? `<br><span class="muted">用量 ${j.usage.total_tokens} token · 延迟 ${j.latency_ms} ms</span>` : '');
  if (j.ok) {
    // 测通即记住该提供商的密钥，省得下次重填
    await post('/api/provider_key', {provider: currentProvider(), api_key: $('#apiKeyInput').value.trim()});
    PROVIDER_STATE.keys[currentProvider()] = '(已保存)';
    $('#keyState').textContent = '（已保存）';
  }
};
$('#envBtn').onclick = async () => {
  const out = $('#envResult');
  out.textContent = '正在写入 .env…';
  const j = await post('/api/write_env', collect());
  out.textContent = j.error ? ('写入失败：' + j.error) : (j.message || '已写入 .env');
};
$('#settingsCancel').onclick = () => { $('#settingsModal').style.display = 'none'; };
$('#settingsModal').onclick = (e) => {
  if (e.target === $('#settingsModal')) $('#settingsModal').style.display = 'none';
};
$('#settingsForm [name="zoom"]').onchange = (e) => { applyZoom(e.target.value); };
$('#settingsSave').onclick = async () => {
  applyZoom($('#settingsForm [name="zoom"]').value);
  await post('/api/save', collect());
  $('#settingsModal').style.display = 'none';
  $('#status').textContent = '设置已保存';
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
    const r = await fetch('/api/capture_login', {
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
  $('#results').innerHTML = '';
  $('#runBtn').disabled = true;
  await post('/api/run', collect());
  $('#runBtn').disabled = false;
  $('#stopBtn').disabled = false;
  poll();
};
$('#stopBtn').onclick = async () => {
  $('#stopBtn').disabled = true;
  await post('/api/stop', {});
  poll();
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
    const r = await fetch('/api/vision', {
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
  const r = await fetch('/api/screenshot', {
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
</script>
</body>
</html>
"""


def _load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def _save_settings(data: dict) -> None:
    """保存设置：白名单字段 + 按角色模型字段（`role_model_<角色>`）一起落盘。"""
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    cleaned = {k: str(data.get(k, DEFAULTS.get(k, ""))).strip() for k in DEFAULTS}
    for role in ROLES:
        field = f"role_model_{role}"
        if field in data:
            cleaned[field] = str(data.get(field, "")).strip()
    SETTINGS_PATH.write_text(
        json.dumps(cleaned, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _provider_keys() -> dict[str, str]:
    """读取已保存的各提供商密钥（存在 settings.json 的 provider_keys 里）。"""
    raw = _load_settings().get("provider_keys") or "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if str(v).strip()}


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


def _settings_payload() -> dict:
    """给模板的完整设置（含 provider 相关字段与角色模型）。"""
    stored = _load_settings()
    merged = {**DEFAULTS, **stored}
    return {
        "settings": {**merged, "role_models": _role_models(stored)},
        "role_labels": ROLE_LABEL,
    }


class RunState:
    """后台审计运行的状态（线程安全）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token = 0
        self._cancel_event = threading.Event()
        self.status = "idle"
        self.steps: list[dict] = []
        self.events: list[dict] = []
        self.findings: list[dict] = []
        self.summary = ""
        self.error = ""
        self.output_path = ""
        self.submission_path = ""
        self.tokens = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cache_hit_tokens": 0,
            "cache_miss_tokens": 0,
            "estimated_cost": 0.0,
            "total_tokens": 0,
        }

    def start(self) -> int:
        with self._lock:
            self._token += 1
            self._cancel_event.clear()
            self.status = "running"
            self.steps = []
            self.events = []
            self.findings = []
            self.summary = ""
            self.error = ""
            self.output_path = ""
            self.submission_path = ""
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
            if token == self._token and not self._cancel_event.is_set():
                self.steps.append(step)

    def add_event(self, event: dict, token: int) -> None:
        """记录一次编排事件（计划/波次/子任务起止/预警），供界面展示进度。"""
        with self._lock:
            if token == self._token and not self._cancel_event.is_set():
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
            if token == self._token and not self._cancel_event.is_set():
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
    ) -> None:
        with self._lock:
            if token == self._token and not self._cancel_event.is_set():
                self.status = "done"
                self.findings = list(result.findings)
                self.summary = result.final_summary
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

    def fail(self, message: str, token: int) -> None:
        with self._lock:
            if token == self._token and not self._cancel_event.is_set():
                self.status = "error"
                self.error = message

    def stop_current(self) -> None:
        with self._lock:
            self._cancel_event.set()
            if self.status == "running":
                self.status = "idle"
                self.summary = ""
                self.error = ""

    def is_stopped(self, token: int) -> bool:
        with self._lock:
            return token != self._token or self._cancel_event.is_set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self.status,
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


def _parse_auth_profile(raw: str) -> dict[str, str]:
    """解析账号 Cookie/Token JSON，例如 {"Cookie":"session=..."}。"""
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items() if str(value)}


def _run_audit(settings: dict, token: int) -> None:
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
        config = Config(
            api_key=resolved["api_key"],
            base_url=resolved["base_url"] or (preset.base_url if preset else ""),
            model=resolved["model"],
            provider=provider,
            role_models=_role_models(settings),
            max_steps=int(settings.get("max_steps") or DEFAULTS["max_steps"]),
            request_timeout=int(settings.get("request_timeout") or DEFAULTS["request_timeout"]),
            allowed_hosts=allowed,
            max_tasks=int(settings.get("max_tasks") or DEFAULTS["max_tasks"]),
            task_steps=int(settings.get("task_steps") or DEFAULTS["task_steps"]),
            parallel=int(settings.get("parallel") or DEFAULTS["parallel"]),
            rate_limit=float(settings.get("rate_limit") or DEFAULTS["rate_limit"]),
            max_cost=float(settings.get("max_cost") or DEFAULTS["max_cost"]),
            temperature=float(settings.get("temperature") or DEFAULTS["temperature"]),
        )
        config.validate()
        target = settings.get("target", "")
        target_host = (urlparse(target).hostname or "").lower()
        if target_host not in allowed:
            raise ValueError(
                f"目标主机 {target_host!r} 不在 ALLOWED_HOSTS 白名单内，请先把它加进去。"
            )
        mode = settings.get("mode", "blackbox")
        swarm = str(settings.get("swarm", "1")) not in ("0", "false", "no", "")
        base_dir = Path(settings.get("path") or "vulnlab") if mode == "source" else Path.cwd()
        llm, llm_pool = _build_llm_pool(config)
        auth_profiles = {
            "A": _parse_auth_profile(settings.get("auth_a", "")),
            "B": _parse_auth_profile(settings.get("auth_b", "")),
        }
        budget = Budget(
            BudgetLimits(
                max_cost=config.max_cost,
                max_tool_calls=int(settings.get("max_tool_calls") or 0),
            )
        )
        budget.on_change(lambda snapshot: STATE.update_tokens(snapshot, token))
        artifacts = RunArtifacts(target)
        surface = AttackSurface(target=target, mode=mode, path=artifacts.surface_path)
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
        if STATE.is_stopped(token):
            return
        output_value = settings.get("output") or DEFAULTS["output"]
        output_path = Path(output_value)
        if not output_path.is_absolute():
            output_path = PROJECT_ROOT / output_path
        output = write_report(result, goal, output_path)
        package = write_butian_package(result, output)
        STATE.finish(
            result,
            str(output),
            token,
            submission_path=str(package) if package else "",
        )
    except Exception as exc:  # noqa: BLE001  # 后台线程兜底，任何异常转成界面错误
        STATE.fail(f"{type(exc).__name__}: {exc}", token)


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index() -> str:
        return render_template_string(HTML, **_settings_payload())

    @app.route("/api/providers")
    def providers_api() -> str:
        """预设清单 + 当前生效提供商 + 已保存的密钥（只回显掩码，不回传明文）。"""
        stored = _load_settings()
        saved = _provider_keys()
        masked = {key: mask_key(value) for key, value in saved.items()}
        active = _active_provider(stored)
        # 界面上"填入该提供商密钥"需要明文才能填进密码框，因此只对本机 GUI 回传；
        # 界面本身就是本地单用户工具，能力等价于直接读 settings.json。
        return jsonify(
            {
                "presets": describe_presets(),
                "active": active,
                "keys": saved,
                "keys_masked": masked,
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
        client = LLMClient(api_key, base_url, model, provider=provider, timeout=25)
        try:
            check = client.test_connection()
        except Exception as exc:  # noqa: BLE001 兜底：任何异常都转成可读结论
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
        return jsonify(check.to_dict())

    @app.route("/api/write_env", methods=["POST"])
    def write_env_api() -> str:
        """把当前提供商设置写进 .env（保留其它键；先备份原文件）。"""
        data = request.get_json(force=True) or {}
        resolved = _resolve_llm_settings(data)
        updates = {
            "LLM_PROVIDER": resolved["provider"],
            "LLM_MODEL": resolved["model"],
            "LLM_BASE_URL": resolved["base_url"],
            "LLM_API_KEY": resolved["api_key"],
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
        _save_settings(data)
        token = STATE.start()
        threading.Thread(target=_run_audit, args=(data, token), daemon=True).start()
        return jsonify({"ok": True})

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
        if parsed.scheme not in ("http", "https") or not host or host not in allowed:
            return jsonify({"error": "登录 URL 不在 ALLOWED_HOSTS 白名单内。"}), 400
        timeout = int(str(data.get("timeout") or "300"))
        timeout = max(60, min(timeout, 600))
        try:
            result = capture_login_state(url, timeout_sec=timeout)
        except Exception as exc:  # noqa: BLE001  # 登录窗口异常兜底
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
        return jsonify(result)

    @app.route("/api/status")
    def status() -> str:
        return jsonify(STATE.snapshot())

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
        if parsed.scheme not in ("http", "https") or not host or host not in allowed:
            return jsonify({"error": "目标 URL 不在 ALLOWED_HOSTS 白名单内。"}), 400
        try:
            timeout = int(str(data.get("request_timeout") or "30"))
            timeout = max(5, min(timeout, 120))
            image_bytes = capture_url(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001  # 截图接口兜底
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500

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
                answer = f"截图成功，但视觉分析失败：{type(exc).__name__}: {exc}"
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
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500

    return app


def run_server(host: str = "127.0.0.1", port: int = 5001) -> None:
    app = create_app()
    print(f"HexHound GUI 已启动：http://{host}:{port}")
    print("按 Ctrl+C 退出。")
    app.run(host=host, port=port, threaded=True, debug=False)
