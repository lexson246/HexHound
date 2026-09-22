"""桌面控制台的**无窗口**冒烟测试：起本地 Flask 应用，用 HTTP 走一遍关键路径。

为什么需要：打包出的桌面版在 CI 里没有可交互的桌面会话，开不了窗口；
但"窗口背后的那套控制台"是可以验证的——它就是桌面版真正干活的部分。
这里起真实的应用（临时配置目录），依次检查：

1. `/` 返回控制台页面，且包含本次会话令牌与关键控件；
2. 未带令牌的写操作被拒绝（403），带令牌的成功（防 CSRF 的接缝）；
3. `/api/status` 是干净的 idle 状态；
4. `/api/history` 能列出（空也要能列出，不是 500）；
5. 首页里的参数输入框由字段定义渲染（预算护栏字段都在）。

**不访问任何目标、不调用任何模型、不读写用户真实配置。**
用法：python tools/smoke_gui_server.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hexhound import gui, history  # noqa: E402


def _get(url: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _post(url: str, payload: dict, headers: dict[str, str] | None = None) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main() -> int:
    checks: list[tuple[str, bool, str]] = []
    with tempfile.TemporaryDirectory(prefix="hh-smoke-") as tmp:
        base = Path(tmp)
        # 隔离：临时设置文件 + 临时产物目录（绝不碰用户真实配置与历史）
        gui.SETTINGS_PATH = base / "settings.json"
        gui.STATE = gui.RunState()
        history.data_home = lambda home=None: base / "home"  # type: ignore[assignment]

        app = gui.create_app()
        token = app.config["HEXHOUND_LOCAL_TOKEN"]
        # 关掉 werkzeug 的请求日志与启动横幅：冒烟输出只留结论，CI 日志才好读
        import logging

        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = threading.Thread(
            target=app.run,
            kwargs={"host": "127.0.0.1", "port": port, "debug": False, "threaded": True},
            daemon=True,
        )
        server.start()
        root = f"http://127.0.0.1:{port}"

        for _ in range(100):
            try:
                status, _body = _get(f"{root}/api/status")
                if status == 200:
                    break
            except OSError:
                pass
            import time

            time.sleep(0.1)

        status, html = _get(f"{root}/")
        checks.append(("首页返回 200", status == 200, f"status={status}"))
        checks.append(("页面带会话令牌", token in html, "令牌已渲染进页面"))
        checks.append(
            ("预算护栏字段已渲染", all(f'name="{key}"' in html for key in
                                  ("max_cost", "max_tokens", "max_llm_calls",
                                   "max_tool_calls", "max_seconds")), "五个上限输入框"),
        )
        checks.append(("历史面板存在", 'id="historyList"' in html, "历史面板"))

        # 防 CSRF：没令牌的写操作必须被拒
        status, _ = _post(f"{root}/api/stop", {})
        checks.append(("无令牌写操作被拒（403）", status == 403, f"status={status}"))
        # 带令牌的正常写操作
        status, _ = _post(f"{root}/api/stop", {}, {gui.TOKEN_HEADER: token})
        checks.append(("带令牌写操作成功", status == 200, f"status={status}"))

        status, body = _get(f"{root}/api/status")
        snapshot = json.loads(body) if status == 200 else {}
        checks.append(
            ("状态为 idle 且未在运行",
             snapshot.get("status") == gui.STATUS_IDLE and not snapshot.get("running"),
             f"status={snapshot.get('status')}"),
        )

        status, body = _get(f"{root}/api/history")
        ok = status == 200 and isinstance(json.loads(body).get("runs"), list)
        checks.append(("历史接口可用", ok, f"status={status}"))

        # 保存一次设置：证明磁盘路径可用（写的是临时文件）
        status, _ = _post(f"{root}/api/save", {"target": "http://127.0.0.1:5000"},
                          {gui.TOKEN_HEADER: token})
        saved = json.loads(gui.SETTINGS_PATH.read_text(encoding="utf-8")) if gui.SETTINGS_PATH.exists() else {}
        checks.append(
            ("配置可落盘并保留预算字段",
             status == 200 and saved.get("max_tokens") == gui.DEFAULTS["max_tokens"],
             f"status={status} max_tokens={saved.get('max_tokens')}"),
        )

    failed = [name for name, ok, _detail in checks if not ok]
    for name, ok, detail in checks:
        print(f"{'[ OK ]' if ok else '[FAIL]'} {name} — {detail}")
    print()
    if failed:
        print(f"冒烟失败：{len(failed)} 项未通过 → {', '.join(failed)}")
        return 1
    print(f"冒烟通过：{len(checks)} 项全部通过（本地临时配置，未访问目标、未调用模型）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
