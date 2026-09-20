#!/usr/bin/env bash
# 把 nuclei 模板库装进 WSL（模板已在 Windows 侧下载并解压好）。
#
# 为什么绕这一圈：Windows 上装了 Steam++/Watt Toolkit 类加速器，GitHub 只在
# Windows 侧可达；WSL 不读 Windows hosts，直连 GitHub 会被重置。
# 所以路径是：Windows 下载 → 解压 → WSL 原生 cp（Windows tar.exe 处理不了
# 模板里某个特殊文件名，cp 可以）。
set -uo pipefail

SRC="/mnt/c/Users/LeXSon/AppData/Local/Temp/nuclei-tpl-check/nuclei-templates-10.0.0"
DEST="/root/.local/nuclei-templates"

echo "[+] 源目录检查"
if [[ ! -d "$SRC" ]]; then
  echo "    找不到 $SRC（先在 Windows 侧下载并解压模板包）"
  exit 1
fi
echo "    源内模板数：$(find "$SRC" -name '*.yaml' | wc -l)"

echo "[+] 复制到 $DEST"
rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -r "$SRC" "$DEST" 2>/dev/null || {
  # 遇到无法复制的个别文件时，逐文件复制并统计失败数
  mkdir -p "$DEST"
  failed=0
  while IFS= read -r -d '' f; do
    rel="${f#$SRC/}"
    mkdir -p "$DEST/$(dirname "$rel")"
    cp "$f" "$DEST/$rel" 2>/dev/null || failed=$((failed+1))
  done < <(find "$SRC" -type f -print0)
  echo "    逐文件复制完成，失败 $failed 个"
}

count=$(find "$DEST" -name '*.yaml' 2>/dev/null | wc -l)
echo "    目标内模板数：$count"

echo "[+] 校验 nuclei 能识别模板"
nuclei -tl 2>/dev/null | wc -l | sed 's/^/    可用模板：/'
echo
if [[ "$count" -gt 1000 ]]; then
  echo "[OK] 模板库就绪"
else
  echo "[!] 模板数量偏少（$count），可能复制不完整"
  exit 1
fi
