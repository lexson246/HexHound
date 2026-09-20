#!/usr/bin/env bash
# HexHound 工具链安装脚本（Debian/Ubuntu/WSL/容器通用）。
#
# 装的是 HexHound 会调用的那批工具（对应 src/hexhound/sandbox.py 的 TOOL_ALLOWLIST）：
#   nmap / sqlmap / ffuf / gobuster / nuclei / whatweb / nikto
# 刻意不装 Metasploit / 利用框架：HexHound 只做只读验证。
#
# 网络适配（本机实测的坑）：
#   - github.com 被 hosts 屏蔽 → Go 工具优先走 GitHub 代理镜像
#   - ffuf 在 Ubuntu 源里就有 → 优先 apt，省得下载
#
# 用法（需要 root）：
#   bash docker/install-tools.sh            # 安装
#   bash docker/install-tools.sh --check    # 只检查已装了哪些
set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" = "--check" ]] && CHECK_ONLY=1

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
  amd64|x86_64) GOARCH="amd64" ;;
  arm64|aarch64) GOARCH="arm64" ;;
  *) GOARCH="amd64" ;;
esac
DEST="/usr/local/bin"
#: GitHub 代理（按可用性顺序；直连放最后）
GH_PROXIES=("https://ghproxy.net/" "https://gh-proxy.com/" "")

log()  { printf '\033[36m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [[ "$CHECK_ONLY" = "1" ]]; then
  for tool in nmap sqlmap ffuf gobuster nuclei whatweb nikto curl jq; do
    if have "$tool"; then ok "$tool -> $(command -v "$tool")"; else warn "$tool 未安装"; fi
  done
  exit 0
fi

if [[ "$(id -u)" != "0" ]]; then
  warn "需要 root 权限安装系统包。"
  exit 1
fi

# ---------------------------------------------------------------- 1) apt 包
log "apt-get update ..."
apt-get update -qq || warn "apt update 有告警，继续"

log "安装 apt 包 ..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  nmap sqlmap nikto whatweb gobuster curl jq ca-certificates unzip wget \
  || warn "部分 apt 包失败，继续"

# ffuf 从 24.04 起就在源里；没有才走下二进制
if ! have ffuf; then
  log "尝试从 apt 安装 ffuf ..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ffuf \
    || warn "apt 里没有 ffuf，稍后用二进制方式装"
fi

# ---------------------------------------------------------------- 2) 二进制工具
# download_with_mirrors <相对路径> <输出文件>
# 依次尝试 GH_PROXIES 里的代理 + 直连，任一成功即返回 0
#
# 注意：如果这台机器装了 Steam++ / Watt Toolkit 类加速器，**宿主的 Windows 侧**
# 通常能直连 GitHub（走本地 443 反代），而 WSL 不能（不读 Windows hosts）。
# 这种情况下更可靠的做法是：在 Windows 侧下载二进制，再用
# `hexhound sandbox install` 的宿主通道送进来（见 src/hexhound/sandbox.py 的
# install_binary_via_host）。本脚本负责其余情况。
download_with_mirrors() {
  local rel="$1" out="$2" proxy url code
  for proxy in "${GH_PROXIES[@]}"; do
    url="${proxy}https://github.com/${rel}"
    code=$(curl -fsSL --retry 2 --max-time 900 -o "$out" "$url" 2>/dev/null && echo 0 || echo 1)
    if [[ "$code" = "0" && -s "$out" ]]; then
      return 0
    fi
  done
  return 1
}

install_go_tool() {
  # $1=名字 $2=owner/repo $3=版本 $4=资产名模板（{v} 占位）
  local name="$1" repo="$2" version="$3" asset_template="$4"
  if have "$name"; then
    ok "$name 已存在，跳过"
    return 0
  fi
  local asset="${asset_template//\{v\}/$version}"
  asset="${asset//\{arch\}/$GOARCH}"   # 早期版本漏了这行，导致 URL 里带着字面量 {arch} 去下载
  local rel="${repo}/releases/download/v${version}/${asset}"
  local tmp; tmp="$(mktemp -d)"
  log "下载 $name v$version ..."
  if ! download_with_mirrors "$rel" "$tmp/pkg"; then
    warn "$name 下载失败（直连与代理都不通）：$rel"
    rm -rf "$tmp"; return 1
  fi
  case "$asset" in
    *.zip)
      unzip -q -o "$tmp/pkg" -d "$tmp" 2>/dev/null || { warn "$name 解压失败"; rm -rf "$tmp"; return 1; }
      ;;
    *.tar.gz|*.tgz)
      mkdir -p "$tmp/x" && tar -xzf "$tmp/pkg" -C "$tmp/x" 2>/dev/null \
        || { warn "$name 解压失败"; rm -rf "$tmp"; return 1; }
      tmp="$tmp/x"
      ;;
    *.gz)
      gunzip -c "$tmp/pkg" > "$DEST/$name" && chmod 0755 "$DEST/$name"
      rm -rf "$tmp"
      have "$name" && ok "$name 就绪" || warn "$name 仍不可用"
      return 0
      ;;
  esac
  local bin; bin="$(find "$tmp" -maxdepth 3 -type f -name "$name" | head -1)"
  if [[ -z "$bin" ]]; then
    warn "$name 解压后找不到可执行文件"
    rm -rf "$tmp"; return 1
  fi
  install -m 0755 "$bin" "$DEST/$name"
  rm -rf "$tmp"
  have "$name" && ok "$name 就绪" || warn "$name 仍不可用"
}

install_go_tool nuclei projectdiscovery/nuclei 3.3.7 "nuclei_{v}_linux_{arch}.zip"
install_go_tool ffuf   ffuf/ffuf              2.1.0 "ffuf_{v}_linux_{arch}.tar.gz"

# ---------------------------------------------------------------- 3) 词表
if [[ ! -f /usr/share/wordlists/hexhound-common.txt ]]; then
  log "准备目录爆破词表 ..."
  mkdir -p /usr/share/wordlists
  if [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
    ln -sf /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/hexhound-common.txt
  else
    cat > /usr/share/wordlists/hexhound-common.txt <<'EOF'
admin
login
api
api/v1
api/v2
user
users
config
backup
backup.zip
.env
.git/config
swagger-ui.html
actuator
actuator/env
health
metrics
upload
uploads
files
download
export
proxy
redirect
graphql
phpmyadmin
console
test
debug
server-status
EOF
  fi
fi

# ---------------------------------------------------------------- 4) 汇总
echo
log "安装结果："
missing=0
for tool in nmap sqlmap ffuf gobuster nuclei whatweb nikto curl jq; do
  if have "$tool"; then ok "$tool"; else warn "$tool 不可用"; missing=$((missing+1)); fi
done
echo
if [[ "$missing" -gt 0 ]]; then
  warn "有 $missing 个工具不可用。nuclei 需要能访问 GitHub（脚本会走镜像代理）。"
else
  log "全部就绪。"
fi
log "提示：nuclei 首次运行会拉模板库（约 1 分钟）。"
