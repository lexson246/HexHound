"""用真实运行数据 A/B 对比新旧 diff 判据（自查用，可删）。

拿最近一次运行的 surface.json（findings + coverage）与真实记忆文件，
分别在"旧判据"（只看 findings）与"新判据"（再加上 reported 覆盖）下统计分类，
确认那个误导性的"疑似已修复"确实被消除了。
"""
import io
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from hexhound.diff import diff_findings  # noqa: E402
from hexhound.surface import normalize_endpoint  # noqa: E402

run_dir = Path(sys.argv[1])
surface = json.loads((run_dir / "surface.json").read_text(encoding="utf-8"))
memory_path = Path.home() / ".hexhound" / "memory" / "http---127.0.0.1-5000.json"
memory = json.loads(memory_path.read_text(encoding="utf-8"))


def endpoints_of(items):
    out = set()
    for item in items:
        url = str(item.get("url") or "")
        if url:
            out.add(normalize_endpoint(url))
    return {u for u in out if u}


def coverage_entries(surface: dict):
    """surface.json 里 coverage 可能是 dict 也可能是 list（落盘格式），两种都认。"""
    raw = surface.get("coverage", {})
    return list(raw.values()) if isinstance(raw, dict) else list(raw or [])


touched = endpoints_of(surface.get("findings", []))
for entry in coverage_entries(surface):
    if str(entry.get("status")) in ("not_tested", "blocked"):
        continue
    target = str(entry.get("target") or "")
    if "http" in target:
        touched.add(normalize_endpoint(target.split()[0]))

reported = set()
for entry in coverage_entries(surface):
    if str(entry.get("status")) != "reported":
        continue
    target = str(entry.get("target") or "")
    if "http" in target:
        reported.add(normalize_endpoint(target.split()[0]))

current = surface.get("findings", [])
previous = memory.get("findings", [])

old = diff_findings(previous, current, touched_endpoints=touched)
new = diff_findings(previous, current, touched_endpoints=touched, still_affected=reported)

print(f"历史条目 {len(previous)} 条 | 本次 finding {len(current)} 条 | 覆盖端点 {len(touched)} 个 | reported 端点 {len(reported)} 个")
print("旧判据 counts:", old.counts())
print("新判据 counts:", new.counts())
print("\n旧判据里被判成「疑似已修复」、新判据改判 unknown 的条目：")
new_unknown = {item["fingerprint"] for item in new.unknown}
moved = [item for item in old.fixed if item["fingerprint"] in new_unknown]
for item in moved:
    print(f"  {item['id']:8s} {item['type']:10s} {item['url']}")
print(f"共 {len(moved)} 条改判")
