"""故意带漏洞的 Flask 靶场，仅供本地授权测试与自建环境验证。

覆盖的漏洞（HexHound 的检测能力验证集）：
- /login             错误型 SQL 注入（SQL 错误 + 完整查询回显）
- /reflect           反射型 XSS（name 未转义，**真实浏览器里会执行**）
- /reflect-text      对照组：原样回显但 Content-Type 是 text/plain（不执行）
- /reflect-dom       对照组：payload 进了 DOM 的 <textarea>（不执行）
- /reflect-csp       对照组：原样回显但 CSP 禁止内联脚本（不执行）
- /file              目录遍历 / 任意文件读取（可读 secret.txt、.env.demo）
- /fetch             SSRF（url 参数由服务端发起请求）
- /ping              命令注入（ip 参数拼接 shell）
- /ssti              SSTI（模板字符串拼接）
- /api/users         未授权访问 + IDOR（不带 / 带他人 uid 都能读到数据）
- /api/user          登录态越权（alice 的身份读 bob 的资料）
- /admin             受保护路径（403，供枚举验证）
- /static/app.js     前端硬编码密钥（信息泄露）
- /actuator/env      配置泄露（含 app.jwt.secret，是 /api/admin/export 的利用前提）
- /coupon            竞态：先查后写无原子性 → 单次券可并发重复兑换（+ /wallet 看余额）
- /api/reset_token   竞态：一次性重置令牌并发消费 → 拿到多个会话
- /api/jwt_login     签发 HS256 JWT（密钥泄露 + 校验接受 alg=none）
- /api/admin/export  JWT 保护的管理员接口（漏洞 13 的利用目标）

运行：python vulnlab/app.py  （默认监听 0.0.0.0:5000）
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "app.db"

#: 与 /actuator/env 泄露的 app.jwt.secret 保持一致——**故意**让"读配置 → 伪造令牌"
#: 这条链在靶场里走得通（真实世界这正是一次完整的高危漏洞利用）。
JWT_SECRET = "hexhound-demo-jwt-secret-do-not-use"

app = Flask(__name__)

# 演示用账号（仅本地靶场）：密码哈希用常量比较，避免真实凭据误用。
DEMO_USERS = {
    "alice": "alice-demo-pass",
    "bob": "bob-demo-pass",
}

MOCK_PROFILES = {
    1: {"uid": 1, "username": "alice", "name": "爱丽丝", "mobile": "13800000001",
        "email": "alice@example.com", "idcard": "110101199001011234", "role": "user"},
    2: {"uid": 2, "username": "bob", "name": "鲍勃", "mobile": "13800000002",
        "email": "bob@example.com", "idcard": "110101199202022345", "role": "user"},
    3: {"uid": 3, "username": "admin", "name": "管理员", "mobile": "13800000003",
        "email": "admin@example.com", "idcard": "110101198803033456", "role": "admin"},
}


def init_db() -> None:
    """初始化 SQLite 用户表，写入演示账号。"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    cur.execute("DELETE FROM users")
    for name, password in DEMO_USERS.items():
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (name, password))
    conn.commit()
    conn.close()


def _current_user() -> str:
    """从会话 Cookie 里取当前用户名（靶场专用简化实现）。"""
    raw = request.cookies.get("hh_session", "")
    if not raw or ":" not in raw:
        return ""
    name, _, token = raw.partition(":")
    expected = f"tok-{name}-demo"
    return name if hmac.compare_digest(token, expected) else ""


@app.route("/")
def index() -> str:
    return """<!doctype html><html><head><title>HexHound 靶场</title></head><body>
    <h1>HexHound 靶场（仅本地授权测试）</h1>
    <ul>
      <li><a href="/login">/login</a> —— 错误型 SQL 注入</li>
      <li><a href="/reflect?name=hello">/reflect?name=</a> —— 反射型 XSS</li>
      <li><a href="/file?path=secret.txt">/file?path=</a> —— 目录遍历</li>
      <li><a href="/fetch?url=http://127.0.0.1:5000/">/fetch?url=</a> —— SSRF</li>
      <li><a href="/ping?ip=127.0.0.1">/ping?ip=</a> —— 命令注入</li>
      <li><a href="/ssti?name=world">/ssti?name=</a> —— 模板注入</li>
      <li><a href="/api/users">/api/users</a> —— 未授权访问 / IDOR</li>
      <li><a href="/wallet">/wallet</a> —— 余额（配合 /coupon 验证竞态）</li>
      <li><a href="/coupon">/coupon</a> —— 竞态：单次优惠券并发重复兑换（POST code=HH-RACE-100）</li>
      <li><a href="/api/admin/export">/api/admin/export</a> —— JWT 保护的管理员导出</li>
    </ul>
    <form method="POST" action="/login">
      username: <input name="username"><br>
      password: <input name="password"><br>
      <button type="submit">登录</button>
    </form>
    <script src="/static/app.js"></script>
    </body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login() -> tuple[str, int] | str:
    """username/password 直接拼进 SQL（漏洞 1：错误型 SQL 注入）。"""
    if request.method == "GET":
        return """
        <form method="POST" action="/login">
          username: <input name="username"><br>
          password: <input name="password"><br>
          <button type="submit">登录</button>
        </form>
        """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = (
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    )
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except sqlite3.Error as exc:
        conn.close()
        return f"SQL 错误：{exc}<br>查询：{query}", 500
    conn.close()
    if rows:
        response = app.make_response(f"登录成功：{rows[0][1]}")
        response.set_cookie("hh_session", f"{rows[0][1]}:tok-{rows[0][1]}-demo", httponly=False)
        return response
    return "登录失败：用户名或密码错误"


@app.route("/reflect")
def reflect() -> str:
    """name 未转义直接回显（漏洞 2：反射型 XSS）。

    **真的会执行**：payload 落在 HTML 正文上下文里，浏览器会解析它。
    与下面几个"看起来也会 XSS 其实不会"的端点构成对照组——
    这正是需要真实浏览器才能分辨的那一类差异。
    """
    name = request.args.get("name", "")
    return f"<h1>你好，{name}</h1>"


# ---------------------------------------------------------------------------
# XSS 判据对照组（漏洞 2b）：**只有真实浏览器能分辨**
#
# 这三个端点都会把 payload 原样回显，字符串级别完全一样，
# 但浏览器里的结果完全不同：
#   /reflect        HTML 上下文        → 真的执行
#   /reflect-text   Content-Type: text/plain → 不解析，只是纯文本
#   /reflect-dom    进入 <textarea>    → 在 DOM 里但不可执行
#   /reflect-csp    带 CSP 响应头      → 浏览器拒绝执行内联脚本
# 把它们放在一起，是为了让"反射 ≠ 执行"这件事**可复核**：
# 只做字符串匹配的工具会把四个都报成 XSS，而其中三个不是。
# ---------------------------------------------------------------------------


@app.route("/reflect-text")
def reflect_text() -> tuple[str, int]:
    """payload 原样回显，但响应是 text/plain（浏览器不解析 HTML）。"""
    name = request.args.get("name", "")
    return f"你好，{name}", 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/reflect-dom")
def reflect_dom() -> str:
    """payload 进了 DOM，但**被 HTML 转义**后落在 `<textarea>` 里。

    转义是刻意的：这样 payload 会以文本形式出现在渲染后的 DOM 中
    （`innerText`/DOM 文本里查得到），但浏览器不会把它当标签解析、更不会执行。
    这正是"字符串出现在 DOM 里"与"代码被执行"之间那道最容易被误判的界线——
    `render_template_string` 会自动转义，这里用 f-string 所以显式 escape。
    """
    from markupsafe import escape

    name = escape(request.args.get("name", ""))
    return f"<h1>留言</h1><textarea name='msg'>{name}</textarea>"


@app.route("/reflect-csp")
def reflect_csp() -> tuple[str, int, dict[str, str]]:
    """payload 进了 HTML 正文，但 CSP 禁止内联脚本执行。"""
    name = request.args.get("name", "")
    return (
        f"<h1>你好，{name}</h1>",
        200,
        {
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; "
                "object-src 'none'; base-uri 'none'"
            )
        },
    )


@app.route("/file")
def read_file() -> tuple[str, int] | str:
    """path 直接拼接 open()（漏洞 3：目录遍历 / 任意文件读取）。"""
    path = request.args.get("path", "")
    try:
        content = (BASE_DIR / path).read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        return f"读取失败：{exc}", 500
    return f"<pre>{content}</pre>"


@app.route("/fetch")
def fetch() -> str:
    """url 参数由服务端发起请求（漏洞 4：SSRF）。"""
    url = request.args.get("url", "")
    if not url:
        return "用法：/fetch?url=http://127.0.0.1:5000/"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 靶场故意
            body = response.read(2000).decode("utf-8", errors="replace")
        return f"<pre>已抓取 {url}（HTTP {response.status}）：\n{body}</pre>"
    except Exception as exc:  # noqa: BLE001 靶场故意回显错误，便于 SSRF 判定
        return f"抓取失败：{type(exc).__name__}: {exc}", 500


@app.route("/ping")
def ping() -> tuple[str, int] | str:
    """ip 参数拼接进 shell（漏洞 5：命令注入）。"""
    ip = request.args.get("ip", "127.0.0.1")
    command = f"ping -n 1 {ip}" if sys.platform.startswith("win") else f"ping -c 1 {ip}"
    try:
        completed = subprocess.run(  # noqa: S602 靶场故意
            command, shell=True, capture_output=True, text=True, timeout=6
        )
    except subprocess.TimeoutExpired:
        return "执行超时", 500
    output = (completed.stdout or "") + (completed.stderr or "")
    return f"<pre>$ {command}\n{output[:3000]}</pre>"


@app.route("/ssti")
def ssti() -> str:
    """name 直接拼进模板字符串（漏洞 6：SSTI）。

    故意用 Jinja2 的 `from_string` 拼接用户输入——这是真实项目里最常见的
    SSTI 成因（把用户输入当模板而非当数据）。
    """
    name = request.args.get("name", "world")
    try:
        from jinja2 import TemplateSyntaxError, UndefinedError
        from jinja2.sandbox import SandboxedEnvironment

        rendered = SandboxedEnvironment().from_string("你好，" + name).render(name=name)
    except ImportError:
        try:
            rendered = "你好，" + name.format(name=name)
        except (KeyError, IndexError, ValueError):
            rendered = "你好，" + name
    except (TemplateSyntaxError, UndefinedError):
        rendered = "你好，" + name
    return f"<h1>{rendered}</h1>"


@app.route("/api/users")
def api_users() -> str:
    """无需登录即返回用户列表（漏洞 7：未授权访问 / 敏感数据泄露）。"""
    return jsonify({"code": 0, "data": list(MOCK_PROFILES.values())})


@app.route("/api/user")
def api_user() -> tuple[str, int] | str:
    """按 uid 返回资料，不校验归属（漏洞 8：IDOR / 水平越权）。"""
    raw_uid = request.args.get("uid", "1")
    try:
        uid = int(raw_uid)
    except ValueError:
        return jsonify({"code": 1, "msg": "uid 必须是数字"}), 400
    profile = MOCK_PROFILES.get(uid)
    if profile is None:
        return jsonify({"code": 1, "msg": "用户不存在"}), 404
    return jsonify({"code": 0, "data": profile, "viewer": _current_user() or "anonymous"})


@app.route("/api/order")
def api_order() -> tuple[str, int] | str:
    """订单详情：只凭 order_id 即可读（漏洞 9：越权读取订单）。"""
    order_id = request.args.get("order_id", "1001")
    orders = {
        "1001": {"order_id": "1001", "owner": "alice", "amount": 199.0, "address": "北京市朝阳区演示路 1 号", "mobile": "13800000001"},
        "1002": {"order_id": "1002", "owner": "bob", "amount": 88.0, "address": "上海市浦东新区演示路 2 号", "mobile": "13800000002"},
    }
    order = orders.get(str(order_id))
    if order is None:
        return jsonify({"code": 1, "msg": "订单不存在"}), 404
    return jsonify({"code": 0, "data": order})


@app.route("/admin")
def admin() -> tuple[str, int]:
    """受保护路径：只有 admin 会话可访问（供枚举与访问控制验证）。"""
    if _current_user() == "admin":
        return "后台管理页面（仅演示）", 200
    return "403 需要管理员权限", 403


# ---------------------------------------------------------------------------
# 竞态 / 业务逻辑 / 加密实现（v0.4 追加）
#
# 这三类问题的共同点：**一条命令、一个请求都测不出来**。要么需要并发，
# 要么需要多步状态机，要么需要自己造一个凭据。靶场必须先把它们放进来，
# 否则"我们也能测这三类"这句话无法验证。
# ---------------------------------------------------------------------------

#: 优惠券：故意用"先查后写 + 中间 sleep"实现——真实项目里最常见的竞态成因。
COUPONS: dict[str, dict[str, object]] = {
    "HH-RACE-100": {"amount": 100, "redeemed_by": []},
    "HH-ONCE-200": {"amount": 200, "redeemed_by": []},
}
WALLET: dict[str, int] = {"alice": 0, "bob": 0}


@app.route("/wallet")
def wallet() -> str:
    """查看当前身份余额（竞态验证需要可观测的状态）。"""
    who = _current_user() or "anonymous"
    return jsonify({"code": 0, "user": who, "balance": WALLET.get(who, 0)})


@app.route("/coupon", methods=["GET", "POST"])
def coupon() -> tuple[str, int] | str:
    """兑换优惠券：**check-then-act 之间没有原子性**（漏洞 11：竞态 / 重复兑换）。

    实现刻意还原真实缺陷模式：
      1. 读优惠券，确认没被当前用户兑换过；
      2. `time.sleep(0.15)` 模拟后续业务处理（真实系统里是查库/调用下游）；
      3. 再把用户写进已兑换名单、给余额加钱。
    并发请求会在第 1 步都读到"未兑换"，于是同一张单次券被兑换多次。
    正确实现应当是原子 UPDATE ... WHERE 唯一约束（或用锁）。
    """
    code = request.values.get("code", "")
    who = _current_user() or "anonymous"
    entry = COUPONS.get(code)
    if entry is None:
        return jsonify({"code": 1, "msg": "优惠券不存在"}), 404
    if who == "anonymous":
        return jsonify({"code": 1, "msg": "请先登录"}), 401
    redeemed = entry["redeemed_by"]
    assert isinstance(redeemed, list)
    if who in redeemed:
        return jsonify({"code": 1, "msg": "该券已被你兑换过", "balance": WALLET.get(who, 0)}), 409
    time.sleep(0.15)  # ← 竞态窗口：真实代码里这段是查库/调下游
    redeemed.append(who)
    amount = int(entry["amount"])  # type: ignore[arg-type]
    WALLET[who] = WALLET.get(who, 0) + amount
    return jsonify(
        {"code": 0, "msg": f"兑换成功 +{amount}", "balance": WALLET[who], "code_used": code}
    )


@app.route("/api/reset_token", methods=["POST"])
def reset_token() -> tuple[str, int] | str:
    """一次性重置令牌：同样缺原子性（漏洞 12：令牌并发消费）。

    并发提交同一 token 会拿到多个有效的新会话——真实场景里等于一次令牌多次用。
    """
    token = request.values.get("token", "")
    username = request.values.get("username", "alice")
    valid = {"alice": "reset-alice-0001", "bob": "reset-bob-0002"}
    if token != valid.get(username):
        return jsonify({"code": 1, "msg": "令牌无效"}), 400
    time.sleep(0.15)  # ← 竞态窗口
    issued = f"{username}:tok-{username}-demo-{int(time.time() * 1000) % 100000}"
    return jsonify({"code": 0, "msg": "密码已重置", "session": issued})


@app.route("/api/jwt_login", methods=["POST"])
def jwt_login() -> tuple[str, int] | str:
    """签发 HS256 JWT（密钥即 /actuator/env 泄露的那个）。

    漏洞 13（加密/认证实现）：密钥泄露 + 实现接受 `alg=none`。
    只要能把两件事连起来——从 /actuator/env 读到 `app.jwt.secret`，
    就能自己签一个 `{"user":"attacker","role":"admin"}` 的令牌。
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if DEMO_USERS.get(username) != password:
        return jsonify({"code": 1, "msg": "用户名或密码错误"}), 401
    role = "admin" if username == "admin" else "user"
    return jsonify({"code": 0, "token": _sign_jwt({"user": username, "role": role})})


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sign_jwt(payload: dict[str, object], alg: str = "HS256") -> str:
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode()
    if alg.lower() == "none":
        return f"{header}.{body}."
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(signature)}"


def _verify_jwt(token: str) -> dict[str, object] | None:
    """**故意不安全**的校验：接受 alg=none，且不做算法白名单。"""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    header_raw, body_raw, signature = parts
    try:
        header = json.loads(base64.urlsafe_b64decode(header_raw + "=" * (-len(header_raw) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(body_raw + "=" * (-len(body_raw) % 4)))
    except (ValueError, TypeError):
        return None
    alg = str(header.get("alg") or "")
    if alg.lower() == "none":
        return payload  # ← 漏洞：无签名也认
    expected = _sign_jwt(payload).rsplit(".", 1)[-1]
    return payload if hmac.compare_digest(signature, expected) else None


@app.route("/api/admin/export")
def admin_export() -> tuple[str, int] | str:
    """受 JWT 保护的接口（漏洞 13 的利用目标）：只有 role=admin 的令牌能导出。"""
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else request.args.get("token", "")
    payload = _verify_jwt(token)
    if not payload:
        return jsonify({"code": 1, "msg": "缺少或无效的 Bearer 令牌"}), 401
    if str(payload.get("role")) != "admin":
        return jsonify({"code": 1, "msg": "需要管理员角色", "you": payload}), 403
    return jsonify(
        {
            "code": 0,
            "msg": "管理员导出成功",
            "export": [
                {"username": "alice", "idcard": "110101199001011234", "mobile": "13800000001"},
                {"username": "bob", "idcard": "110101199202022345", "mobile": "13800000002"},
            ],
            "token_payload": payload,
        }
    )


@app.route("/actuator/env")
def actuator_env() -> str:
    """模拟未授权的 Spring Boot Actuator（漏洞 10：配置泄露）。"""
    return jsonify(
        {
            "activeProfiles": ["prod"],
            "propertySources": [
                {
                    "name": "applicationConfig",
                    "properties": {
                        "spring.datasource.url": {"value": "jdbc:mysql://127.0.0.1:3306/demo"},
                        "spring.datasource.password": {"value": "Demo#DbPass2024"},
                        "app.jwt.secret": {"value": "hexhound-demo-jwt-secret-do-not-use"},
                    },
                }
            ],
        }
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HexHound 靶场（仅本地授权测试）")
    parser.add_argument("--host", default="0.0.0.0",
                        help="监听地址。默认 0.0.0.0：容器/WSL 里的工具需要从"
                             "另一个网络命名空间访问宿主上的靶场，只绑 127.0.0.1 会连不上。"
                             "只想本机可见就用 --host 127.0.0.1。")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    os.makedirs(BASE_DIR / "static", exist_ok=True)
    init_db()
    if args.host == "0.0.0.0":
        print(f"靶场监听 http://0.0.0.0:{args.port}（局域网内可见；容器/WSL 用宿主 IP 访问）")
    app.run(host=args.host, port=args.port)
