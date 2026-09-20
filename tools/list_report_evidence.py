"""列出报告附录里的每条真工具证据（编号 / 工具 / 状态），排查脚本通道执行情况。

用法：python tools/list_report_evidence.py reports/xxx.md
"""
import io
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
start = text.find("## 真工具执行记录")
seg = text[start:] if start >= 0 else text

pattern = re.compile(r"\*\*([^*\n]+)\*\*\s*·\s*`([^`]+)`\s*·\s*([^·\n]+)·\s*([0-9.]+)s")
entries = list(pattern.finditer(seg))
print(f"附录证据 {len(entries)} 条（报告 {path}）")
for match in entries:
    print(f"  {match.group(1):10s} {match.group(2):26s} {match.group(3).strip():10s} {match.group(4)}s")
print("python 代码块:", len(re.findall(r"```python", seg)))
