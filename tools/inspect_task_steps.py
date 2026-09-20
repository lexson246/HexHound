"""从报告的执行轨迹里抽出某个子任务的步骤摘要（排查某角色为何没出结论）。

用法：python tools/inspect_task_steps.py reports/xxx.md S1
"""
import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
path, task_id = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
start = text.find("## 执行轨迹")
seg = text[start:] if start >= 0 else text
rows = [line for line in seg.splitlines() if line.startswith(f"| {task_id} ")]
print(f"{task_id} 步骤数: {len(rows)}")
for row in rows:
    cells = [cell.strip() for cell in row.strip("|").split("|")]
    if len(cells) >= 5:
        print(f"  [{cells[1]:>3s}] {cells[2]:22s} | {cells[3][:70]}")
        print(f"        观察: {cells[4][:150]}")
