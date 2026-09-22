"""Desktop and CLI packaging use separate entry points."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

from hexhound import cli, desktop


def test_packaged_entries(monkeypatch):
    for name, target in (("hexhound_desktop", desktop), ("hexhound_cli", cli)):
        path = Path(__file__).resolve().parents[1] / "packaging" / f"{name}.py"
        spec = importlib.util.spec_from_file_location(name, path)
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        with monkeypatch.context() as patch:
            patch.setattr(entry.multiprocessing, "freeze_support", lambda: None)
            launch = MagicMock()
            patch.setattr(target, "main", launch)
            entry.main()
            launch.assert_called_once_with()
