"""一次性排查脚本：从报告里提取真工具证据清单与脚本代码块（自查用）。"""
import io
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
path = sys.argv[1] if len(sys.argv) > 1 else "reports/lab_race_crypto2.md"
text = open(path, encoding="utf-8").read()
start = text.find("## 真工具执行记录")
seg = text[start:] if start >= 0 else ""
print("报告:", path, "| 附录长度:", len(seg))
for match in re.finditer(r"\*\*(W\d+-T\d+)\*\* · `([^`]+)` · ([^·]+)· ([0-9.]+)s", seg):
    print(f"  {match.group(1):10s} {match.group(2):24s} {match.group(3).strip():8s} {match.group(4)}s")
scripts = re.findall(r"```python\n(.*?)```", seg, re.S)
print("脚本代码块数量:", len(scripts))
for script in scripts[:2]:
    print("--- 脚本前 500 字符 ---")
    print(script[:500])
