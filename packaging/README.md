# Windows packaging

The desktop and CLI executables have different entry points:

```powershell
python -m pip install -e ".[dev,lab,desktop]"
python -m PyInstaller --noconfirm --clean HexHound-desktop.spec
python -m PyInstaller --noconfirm --clean HexHound.spec
```

Outputs: `dist/HexHound-desktop.exe` (desktop window) and `dist/hexhound.exe` (CLI).
The full installer renames the desktop build to `hexhound.exe` when installing it.

## Full offline installer

Requires Windows x64, WSL 2 for image preparation and Inno Setup 6. Build inputs go in
the ignored `.tmp/installer-deps/` directory; they are not committed to Git.

| Input | Source |
| --- | --- |
| `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` | [Microsoft offline installer](https://go.microsoft.com/fwlink/?linkid=2124701) |
| `wsl-x64.msi` | [Microsoft WSL 2.7.14 x64](https://github.com/microsoft/WSL/releases/tag/2.7.14) |
| Ubuntu Base amd64 archive | [Ubuntu Base 24.04](https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/) |
| `nuclei.zip` | [Nuclei 3.3.7 Linux amd64](https://github.com/projectdiscovery/nuclei/releases/tag/v3.3.7) |
| `nuclei-templates.tar.gz` | [Templates v10.1.5 source archive](https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.1.5) |
| `nikto.tar.gz` | [Nikto 2.5.0 source archive](https://github.com/sullo/nikto/releases/tag/2.5.0) |

Verify Microsoft Authenticode signatures and published archive checksums before use.
Install browser files using the same Python environment used to build the executable:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\.tmp\installer-deps\browsers"
python -m playwright install chromium
```

Import Ubuntu Base into a **new, disposable** WSL distribution. Run
`prepare-tools-image.sh <Linux path to installer-deps>` inside that distribution,
then terminate it and export it to `.tmp/installer-deps/hexhound-tools.tar`.
Never export a personal distribution: it may contain credentials and user data.
The preparation script cleans transient files and is only for disposable builds.

Create `.tmp/installer-deps/COMPONENTS.txt` recording component versions, source URLs,
SHA256 hashes and license locations. Preserve third-party license files. Compile:

```powershell
ISCC.exe packaging\HexHound-Setup.iss
```

Before release, scan source history and decompressed package contents for private
configuration and credentials. Test installation, native launch, a local screenshot,
tools import and uninstall using an isolated user configuration. Upload the installer
and its SHA256 file as release assets. Cloud model connectivity and first-time Windows
feature activation need separate testing; local smoke tests do not prove those paths.
