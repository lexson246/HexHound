"""检查报告附录里是否包含指定的 T 编号证据（含脚本正文与输出）。

用法：python tools/check_evidence_ids.py reports/xxx.md W5-T8 W5-T9
"""
import io
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
path = sys.argv[1]
ids = sys.argv[2:]
text = open(path, encoding="utf-8").read()
start = text.find("## 真工具执行记录")
appendix = text[start:] if start >= 0 else ""
print(f"报告 {path} | 附录 {len(appendix)} 字符")
for eid in ids:
    index = appendix.find(f"**{eid}**")
    state = "找到" if index >= 0 else "缺失"
    print(f"\n{eid}: {state}")
    if index < 0:
        continue
    print("  条目:", appendix[index:index + 140].splitlines()[0])
    chunk = appendix[index:index + 3000]
    script = re.search(r"```python\n(.*?)```", chunk, re.S)
    output = re.search(r"\n```\n(.*?)\n```", chunk, re.S)
    if script:
        first = script.group(1).strip().splitlines()[0]
        print("  脚本首行:", first[:110])
        print("  脚本行数:", len(script.group(1).strip().splitlines()))
    if output:
        print("  输出:", output.group(1).strip()[:300].replace("\n", " | "))
