"""Browser smoke check; all requests stay inside Flask's isolated test client."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from hexhound import gui


def _skip_or_fail(reason: str) -> None:
    """缺少 GUI 依赖时：本地跳过，CI（`HEXHOUND_REQUIRE_GUI=1`）**失败**。

    为什么要有这个开关：一个"依赖没装就静默跳过"的 GUI 测试层等于没有测试层——
    正是一个没被导入的函数（`_build_llm_pool`）让"从界面启动审计"长期必定
    报 NameError 却没人发现。CI 里必须让它变成红的。
    """
    if os.environ.get("HEXHOUND_REQUIRE_GUI", "").strip():
        pytest.fail(f"GUI 测试依赖缺失，但本环境要求必须运行：{reason}")
    pytest.skip(reason)


def _browser_candidates() -> list[dict]:
    """按优先级给出可尝试的浏览器启动参数。

    `HEXHOUND_BROWSER` 的取值语义：
    * 空 / `chromium` → Playwright 自带的 chromium（**不传 channel**，
      因为 `channel="chromium"` 不是合法频道名，传了会启动失败）；
    * `msedge` / `chrome` → 系统浏览器频道；
    * 其余值按"频道名"原样尝试。
    """
    requested = os.environ.get("HEXHOUND_BROWSER", "").strip().lower()
    if requested in ("", "chromium"):
        order = [{}, {"channel": "msedge"}, {"channel": "chrome"}]
    else:
        order = [{"channel": requested}, {}, {"channel": "msedge"}, {"channel": "chrome"}]
    if not requested and sys.platform == "win32":
        # Windows 上通常没装 Playwright 自带的 chromium，先用系统 Edge。
        order = [{"channel": "msedge"}, {"channel": "chrome"}, {}]
    return order


def test_console_interactions(monkeypatch, tmp_path):
    # 注意不能用 `pytest.importorskip`：它抛的 `Skipped` 继承自 BaseException，
    # 会把"CI 必须跑"的要求一起吞掉。这里显式导入，缺依赖时交给 _skip_or_fail 决定。
    try:
        from playwright import sync_api as playwright
    except ImportError as exc:
        _skip_or_fail(f"未安装 playwright：{exc}")
        raise
    monkeypatch.setattr(gui, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(gui, "STATE", gui.RunState())
    # 历史面板读的是运行产物目录：隔离到临时目录，别去读用户真实的历史
    monkeypatch.setattr(gui.history, "data_home", lambda home=None: tmp_path / "hh-home")
    app = gui.create_app()
    client = app.test_client()
    token = app.config["HEXHOUND_LOCAL_TOKEN"]
    errors, requests = [], []
    run_token = None
    reject_run = True
    screenshots = os.environ.get("HEXHOUND_GUI_SCREENSHOTS")

    with playwright.sync_playwright() as pw:
        browser = None
        failures: list[str] = []
        for options in _browser_candidates():
            try:
                browser = pw.chromium.launch(**options)
                break
            except playwright.Error as exc:  # noqa: PERF203 逐个候选尝试
                failures.append(f"{options or 'bundled chromium'} → {exc}")
        if browser is None:
            _skip_or_fail("没有可用的浏览器：" + "；".join(failures))
        page = browser.new_page(viewport={"width": 1440, "height": 1050}, device_scale_factor=1)
        page.on("pageerror", lambda error: errors.append(str(error)))

        def route_request(route):
            nonlocal run_token
            req = route.request
            path = urlsplit(req.url).path
            requests.append((req.method, path))
            # 页面发出的每个 /api 请求都必须带本机会话令牌，否则真实服务端会回 403。
            # 这条断言盯住的正是"前端接了令牌、后端查令牌"这个接缝。
            if path.startswith("/api/"):
                assert req.headers.get(gui.TOKEN_HEADER.lower()) == token, (path, dict(req.headers))
            if path == "/api/run":
                if reject_run:
                    route.fulfill(status=400, json={"error": "模拟启动失败"})
                    return
                run_token = gui.STATE.start()
                gui.STATE.add_step({"step": 1, "action": "test_action", "thought": "<script>unsafe</script>", "observation": "模拟执行结果"}, run_token)
                route.fulfill(json={"ok": True})
            elif path in {"/api/vision", "/api/screenshot"}:
                route.fulfill(json={"answer": "模拟视觉分析结果"})
            else:
                assert path in {"/", "/favicon.ico", "/api/providers", "/api/status", "/api/save", "/api/stop", "/api/report", "/api/history"}, path
                # 原样转给 Flask 测试客户端（带令牌），跑的是真实视图函数。
                headers = {gui.TOKEN_HEADER: token}
                response = client.open(path, method=req.method, data=req.post_data, content_type="application/json", headers=headers)
                route.fulfill(status=response.status_code, body=response.data, content_type=response.content_type)

        page.route("**/*", route_request)
        page.goto("http://hexhound.test/")
        expect = playwright.expect
        expect(page.locator("#status")).to_have_text("等待开始")
        expect(page.locator("#providerSelect option")).not_to_have_count(0)
        assert not errors
        assert ("POST", "/api/stop") not in requests
        assert ("POST", "/api/save") not in requests
        # 没有令牌的请求会被服务端拒绝（防 CSRF / DNS rebinding）——这是服务端真实行为，
        # 不是"测试里关掉的校验"。
        assert client.post("/api/stop").status_code == 403
        assert client.post("/api/save", json={"target": "http://127.0.0.1:5000"}).status_code == 403
        assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
        # 密钥不再回传页面：/api/providers 只能看到掩码与"是否已保存"。
        providers = client.get("/api/providers", headers={gui.TOKEN_HEADER: token}).get_json()
        assert "keys" not in providers, providers.keys()
        assert "keys_masked" in providers and "keys_saved" in providers

        def screenshot(name):
            if screenshots:
                folder = Path(screenshots)
                folder.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(folder / name), full_page=True)

        screenshot("console-desktop.png")
        page.locator("#settingsBtn").click()
        expect(page.locator("#settingsModal")).to_be_visible()
        screenshot("console-settings.png")
        page.keyboard.press("Escape")
        expect(page.locator("#settingsModal")).not_to_be_visible()
        expect(page.locator("#settingsBtn")).to_be_focused()
        page.locator('#cfg [name="mode"]').select_option("source")
        expect(page.locator("#sourceFields")).to_be_visible()
        page.locator('#cfg [name="mode"]').select_option("blackbox")
        expect(page.locator("#sourceFields")).not_to_be_visible()
        page.locator("#saveBtn").click()
        expect(page.locator("#notice")).to_have_text("配置已保存")
        assert json.loads(gui.SETTINGS_PATH.read_text(encoding="utf-8"))["target"] == gui.DEFAULTS["target"]

        page.locator("#runBtn").click()
        expect(page.locator("#notice")).to_have_text("模拟启动失败")
        expect(page.locator("#runBtn")).to_be_enabled()
        reject_run = False
        page.locator("#runBtn").click()
        expect(page.locator("#status")).to_have_text("正在执行")
        expect(page.locator("#runBtn")).to_be_disabled()
        expect(page.locator("#metricSteps")).to_have_text("1")
        expect(page.locator("#log")).to_contain_text("<script>unsafe</script>")
        assert page.locator("#log script").count() == 0
        page.reload()
        expect(page.locator("#status")).to_have_text("正在执行")
        assert ("POST", "/api/stop") not in requests
        page.locator("#stopBtn").click()
        # 停止是**过渡态**：请求已发出、审计线程还在收尾写部分报告。
        # 这期间不能再启动新任务（服务端会拒绝，界面也必须禁用它）。
        expect(page.locator("#status")).to_have_text("正在停止", timeout=10000)
        expect(page.locator("#runBtn")).to_be_disabled()
        expect(page.locator("#stopBtn")).to_be_disabled()
        # 模拟审计线程收尾：中断也要留下成果，且报告写明不完整。
        gui.STATE.add_step({"step": 2, "action": "cleanup", "observation": "中断前已完成的步骤"}, run_token)
        gui.STATE.finish(SimpleNamespace(findings=[], final_summary="【本次运行被中断，报告不完整】"), "runs/x/report.md", run_token, partial=True)
        expect(page.locator("#status")).to_have_text("已中断（部分结果已保存）", timeout=10000)
        expect(page.locator("#runBtn")).to_be_enabled()
        expect(page.locator("#results")).to_contain_text("本次运行被中断，报告不完整")
        expect(page.locator("#results")).to_contain_text("runs/x/report.md")
        assert gui.STATE.snapshot()["steps"], "中断后已完成步骤不能丢"
        page.locator("#runBtn").click()
        expect(page.locator("#status")).to_have_text("正在执行")
        gui.STATE.finish(SimpleNamespace(findings=[{"id": "F1", "title": "测试发现", "severity": "low", "status": "candidate", "evidence": "<b>literal evidence</b>"}], final_summary="本地模拟完成"), "", run_token)
        expect(page.locator("#status")).to_have_text("审计完成", timeout=5000)
        page.locator('[data-view="reports"]').click()
        expect(page.locator("#reportsPane")).to_be_visible()
        expect(page.locator("#results")).to_contain_text("测试发现")
        expect(page.locator("#results")).to_contain_text("<b>literal evidence</b>")
        # 历史面板要真的接上后端：隔离的产物目录里没有运行记录，
        # 于是必须显示"还没有运行产物"——而不是一直停在"正在加载…"。
        expect(page.locator("#historyList")).to_contain_text("还没有运行产物", timeout=10000)
        page.locator("#reportBtn").click()
        expect(page.locator("#reportView")).to_have_text("暂无报告")

        page.locator('[data-view="vision"]').click()
        expect(page.locator("#visionPane")).to_be_visible()
        page.locator("#visionBtn").click()
        expect(page.locator("#visionResult")).to_have_text("请先选择一张图片。")
        page.locator("#shotBtn").click()
        expect(page.locator("#visionResult")).to_have_text("模拟视觉分析结果")
        screenshot("console-vision.png")
        for width in (390, 768, 1024):
            page.set_viewport_size({"width": width, "height": 900})
            for view in ("reports", "vision", "workspace"):
                page.locator(f'[data-view="{view}"]').click()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, view)
            if width == 390:
                screenshot("console-mobile.png")
        assert not errors
        browser.close()
