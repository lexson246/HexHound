"""从报告附录里找出「自定义脚本」证据并打印其执行输出（排查脚本通道为何没出结论）。

用法：python tools/inspect_script_runs.py reports/xxx.md
"""
import io
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
start = text.find("## 真工具执行记录")
seg = text[start:] if start >= 0 else text

# 附录结构：**W2-T9** · `python3（自定义脚本）` · 成功 · 1.2s  + 代码块 + 输出块
blocks = re.split(r"\n\*\*(W\d+-T\d+)\*\* · `([^`]+)` · ([^·]+)· ([0-9.]+)s\n", seg)
print("证据条目数:", (len(blocks) - 1) // 5)
for index in range(1, len(blocks), 5):
    eid, tool, status, duration = blocks[index], blocks[index + 1], blocks[index + 2].strip(), blocks[index + 3]
    body = blocks[index + 4]
    if "自定义脚本" not in tool:
        continue
    script = re.search(r"```python\n(.*?)```", body, re.S)
    output = re.search(r"```\n(.*?)\n```", body, re.S)
    print(f"\n=== {eid} · {status} · {duration}s ===")
    print("脚本首行:", (script.group(1).strip().splitlines() or [""])[0] if script else "（无）")
    out = output.group(1).strip() if output else "（无输出）"
    print("输出（前 700 字符）:")
    print(out[:700])
