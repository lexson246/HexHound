"""查看某条 finding 的证据链与对应附录条目（复核"证据可回查"是否成立）。

用法：python tools/inspect_finding_evidence.py reports/xxx.md <finding-id>
"""
import io
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
path, fid = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()

# 1) 找到该 finding 的章节
start = text.find(f"：{fid}")
if start < 0:
    start = text.find(fid)
section_end = text.find("\n### ", start + 10)
section = text[start:section_end if section_end > 0 else start + 4000]
print("=== finding 内容（节选）===")
for line in section.splitlines():
    if any(k in line for k in ("漏洞标题", "漏洞证明", "复核方式", "证据", "漏洞等级", "T编号", "T9", "T1")):
        print(" ", line[:220])

refs = sorted(set(re.findall(r"\b([A-Z]\d+)-(T\d+)\b", section)))
print("\n引用的工具证据编号:", [f"{a}-{b}" for a, b in refs] or "（无）")

# 2) 在附录里找这些编号
appendix = text[text.find("## 真工具执行记录"):]
for worker, tid in refs:
    eid = f"{worker}-{tid}"
    index = appendix.find(f"**{eid}**")
    print(f"\n=== 附录 {eid} ===")
    if index < 0:
        print("  [XX] 附录里找不到该编号——证据无法回查")
        continue
    chunk = appendix[index:index + 1600]
    headline = chunk.splitlines()[0]
    print(" ", headline[:200])
    script = re.search(r"```python\n(.*?)```", chunk, re.S)
    output = re.search(r"\n```\n(.*?)\n```", chunk, re.S)
    if script:
        print("  脚本前 6 行:")
        for line in script.group(1).strip().splitlines()[:6]:
            print("   ", line[:120])
    if output:
        print("  输出前 400 字符:")
        print("   ", output.group(1).strip()[:400].replace("\n", "\n    "))
