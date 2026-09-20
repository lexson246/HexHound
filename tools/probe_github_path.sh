#!/usr/bin/env bash
# 找出 GitHub 的可达路径（WSL 侧），并验证。
#
# 背景：Windows 上装了 Steam++ / Watt Toolkit 这类加速器，它在本地 443 起反代，
# 并把 github.com 写进 Windows hosts 指向 127.0.0.1。浏览器因此能上 GitHub。
# 但 WSL **不读 Windows hosts**，有自己的 resolv.conf，所以 WSL 里的 curl/apt
# 直连真 GitHub 会被重置——这就是"浏览器能上、命令行上不去"的原因。
#
# 本脚本探测：宿主加速器是否可用（把 github 指到宿主 IP 试一下）。
set -uo pipefail

HOST_GW=$(ip route show default | awk '/default/ {print $3; exit}')
echo "宿主网关: ${HOST_GW:-未探测到}"

probe() {
  local desc="$1"; shift
  local code
  code=$(curl -sS -m 10 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || echo 000)
  printf '  %-42s %s\n' "$desc" "$code"
}

echo "--- 直连（WSL 的解析结果）---"
probe "https://github.com" https://github.com
probe "https://api.github.com/zen" https://api.github.com/zen

echo "--- 指到宿主加速器（--resolve）---"
if [[ -n "${HOST_GW:-}" ]]; then
  probe "github.com -> ${HOST_GW}" --resolve "github.com:443:${HOST_GW}" https://github.com
  probe "api.github.com -> ${HOST_GW}" --resolve "api.github.com:443:${HOST_GW}" https://api.github.com/zen
  probe "objects.githubusercontent.com -> ${HOST_GW}" \
        --resolve "objects.githubusercontent.com:443:${HOST_GW}" \
        https://objects.githubusercontent.com
fi

echo "--- 走 GitHub 代理镜像（无线加速器时的退路）---"
probe "ghproxy.net" https://ghproxy.net
probe "gh-proxy.com" https://gh-proxy.com
