"""Probe: does the real sandbox now return readable whatweb output and tech?

Verifies the Phase 1A fix end-to-end against the bundled lab running in WSL.
No public targets, no destructive actions -- one fingerprint request to 127.0.0.1.
"""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.sandbox import Sandbox, sandbox_report  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402

TARGET = "http://127.0.0.1:5000/"
ALLOWED = frozenset({"127.0.0.1", "localhost"})


def main() -> int:
    sandbox = Sandbox(allowed_hosts=ALLOWED, map_loopback=False, verbose=False)
    probe = sandbox.probe()
    print("runtime:", probe.get("runtime"), "ok:", probe.get("ok"))
    if not probe.get("ok"):
        print("SKIP: sandbox unavailable:", probe.get("reason"))
        return 0

    print("\n--- ExecResult.output (sanitised) ---")
    result = sandbox.whatweb(TARGET)
    output = result.output
    print(f"ok={result.ok} rc={result.exit_code} chars={len(output)}")
    print(output[:600])
    assert "\x1b" not in output, "ANSI escape survived into ExecResult.output"
    assert output.strip(), "whatweb returned empty output (the -q regression)"

    print("\n--- raw bytes sanity: no ANSI, no NUL ---")
    print("contains ESC:", "\x1b" in output, "| contains NUL:", "\x00" in output)

    print("\n--- through the tool registry ---")
    surface = AttackSurface(target=TARGET)
    registry = ToolRegistry(
        base_dir=Path("."),
        allowed_hosts=ALLOWED,
        timeout=10,
        mode="blackbox",
        role="recon",
        surface=surface,
        sandbox=sandbox,
    )
    print("web_fingerprint available:", registry.has("web_fingerprint"))
    text = registry.execute("web_fingerprint", {"url": TARGET})
    print(text[:800])
    print("\nsurface.tech:", dict(surface.tech))
    assert surface.tech, "tech was not populated -- fingerprint parsing still broken"

    print("\n--- report shape ---")
    print(sandbox_report(sandbox))
    print("\nPASS: whatweb output is readable, non-empty, and parsed into tech.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
