#!/usr/bin/env bash
# 把靶场跑在 WSL 里：这样容器/WSL 工具（127.0.0.1 直达）和 Windows 侧都能访问。
# 目的：解决"WSL2 独立网络命名空间 + Windows 防火墙"导致工具打不到宿主靶场的问题。
set -uo pipefail

LAB_SRC="/mnt/c/Users/LeXSon/Documents/ChatGPT/HexHound 2/vulnlab"
LAB_DST="/opt/hexhound-lab"
PORT="${1:-5000}"

echo "[+] 安装 flask ..."
if ! python3 -c 'import flask' 2>/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3-flask 2>&1 | tail -2
fi
python3 -c 'import flask; print("    flask", flask.__version__)' 2>&1 | tail -1

echo "[+] 布置靶场到 ${LAB_DST} ..."
mkdir -p "$LAB_DST/static"
cp -f "$LAB_SRC/app.py" "$LAB_DST/app.py"
cp -f "$LAB_SRC/static/app.js" "$LAB_DST/static/app.js" 2>/dev/null || true
cp -f "$LAB_SRC/.env.demo" "$LAB_DST/.env.demo" 2>/dev/null || true
cp -f "$LAB_SRC/secret.txt" "$LAB_DST/secret.txt" 2>/dev/null || true
ls -1 "$LAB_DST" | sed 's/^/    /'

echo "[+] 停掉旧实例（如有）..."
# 注意：按命令行匹配是不够的——旧实例可能是 `python3 app.py`（相对路径）启动的，
# `pkill -f /opt/hexhound-lab/app.py` 匹配不到，于是端口被旧代码占着、新代码起不来
# （实测踩过：改了靶场却一直返回旧的 404）。所以同时按**端口**清。
pkill -f "hexhound-lab" 2>/dev/null || true
pkill -f "${LAB_DST}/app.py" 2>/dev/null || true
pkill -f "python3 app.py" 2>/dev/null || true
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${PORT}/tcp" 2>/dev/null || true
fi
sleep 1
if curl -sS --noproxy '*' -m 2 -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null; then
  echo "    [!!] 端口 ${PORT} 仍被占用：可能是别处的实例（Windows 侧或另一个 WSL 进程）"
fi

echo "[+] 启动靶场（0.0.0.0:${PORT}，日志 /tmp/hexhound-lab.log）..."
cd "$LAB_DST"
HEXHOUND_LAB=1 nohup python3 app.py --host 0.0.0.0 --port "$PORT" > /tmp/hexhound-lab.log 2>&1 &
sleep 3

echo "[+] 验证："
for url in "http://127.0.0.1:${PORT}/" "http://127.0.0.1:${PORT}/api/users"; do
  code=$(curl -sS --noproxy '*' -m 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  echo "    $code  $url"
done
echo
echo "[+] 靶场日志末尾："
tail -4 /tmp/hexhound-lab.log | sed 's/^/    /'
echo
echo "    停止：pkill -f '${LAB_DST}/app.py'"
