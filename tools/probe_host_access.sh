#!/usr/bin/env bash
# 探测"从 WSL 怎么访问宿主机上跑的服务"。
# Windows 上靶场监听 127.0.0.1:5000，WSL2 是独立网络命名空间，不能直接用 127.0.0.1。
# 常见可达地址：default gateway（即宿主 vEthernet 地址）。

echo "--- WSL 网络 ---"
ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 | sed 's/^/  wsl ip:      /'
GW=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
echo "  gateway:     ${GW:-none}"

echo "--- resolv.conf（WSL 常把宿主写在这）---"
grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | head -3 | sed 's/^/  /'

echo "--- 逐个候选地址试 5000 端口 ---"
for cand in "$GW" $(grep -oP '^nameserver \K[\d.]+' /etc/resolv.conf 2>/dev/null | head -2) 127.0.0.1; do
  [[ -z "$cand" ]] && continue
  code=$(curl -sS -m 4 -o /dev/null -w "%{http_code}" "http://${cand}:5000/" 2>/dev/null)
  if [[ "$code" != "000" && -n "$code" ]]; then
    echo "  [OK]   http://${cand}:5000/  -> HTTP $code"
  else
    echo "  [fail] http://${cand}:5000/"
  fi
done
