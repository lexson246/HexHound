from unittest.mock import patch

from hexhound.sandbox import detect_runtime
from hexhound.screenshot import _find_browser


def test_installed_tools_win_unless_runtime_explicit():
    with (
        patch("hexhound.sandbox._find_wsl", return_value="wsl.exe"),
        patch("hexhound.sandbox._wsl_distros", return_value=["Ubuntu", "HexHound-Tools"]),
        patch("hexhound.sandbox._find_docker", return_value="docker.exe"),
    ):
        runtime = detect_runtime()
        assert runtime.kind == "wsl" and runtime.distro == "HexHound-Tools"
        assert detect_runtime("docker").kind == "docker"
        assert detect_runtime("wsl", "Ubuntu").distro == "Ubuntu"


def test_screenshot_prefers_bundled_browser(tmp_path):
    browser = (
        tmp_path / "chromium_headless_shell-1243"
        / "chrome-headless-shell-win64" / "chrome-headless-shell.exe"
    )
    browser.parent.mkdir(parents=True)
    browser.touch()
    with patch.dict("os.environ", {"PLAYWRIGHT_BROWSERS_PATH": str(tmp_path)}):
        assert _find_browser() == str(browser)
