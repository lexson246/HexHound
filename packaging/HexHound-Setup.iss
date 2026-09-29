#define AppVersion "0.1.0"
#define Deps "..\.tmp\installer-deps"
[Setup]
AppId={{6750A06C-3295-42C7-BE15-6C1E726B60C5}
AppName=HexHound
AppVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\HexHound
DefaultGroupName=HexHound
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir=..\dist
OutputBaseFilename=HexHound-Setup-Full-Offline-x64
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
InfoAfterFile=installer-readme.txt
UninstallDisplayIcon={app}\hexhound.exe
SetupLogging=yes
DiskSpanning=no
CloseApplications=yes

[Files]
Source: "..\dist\HexHound-desktop.exe"; DestDir: "{app}"; DestName: "hexhound.exe"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "installer-readme.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Deps}\COMPONENTS.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "setup-runtime.ps1"; DestDir: "{app}\runtime"; Flags: ignoreversion
Source: "{#Deps}\wsl-x64.msi"; DestDir: "{app}\runtime"; Flags: ignoreversion
Source: "{#Deps}\hexhound-tools.tar"; DestDir: "{app}\runtime"; Flags: ignoreversion
Source: "{#Deps}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "{#Deps}\browsers\*"; DestDir: "{app}\browsers"; Excludes: ".links\*"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: checkedonce

[Icons]
Name: "{group}\HexHound"; Filename: "{app}\hexhound.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\HexHound"; Filename: "{app}\hexhound.exe"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\HexHound - Finish runtime setup"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\runtime\setup-runtime.ps1"""; WorkingDir: "{app}"
Name: "{group}\Uninstall HexHound"; Filename: "{uninstallexe}"

[Run]
Filename: "{tmp}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; Parameters: "/silent /install"; StatusMsg: "Installing desktop runtime..."; Flags: waituntilterminated; Check: NeedsWebView; AfterInstall: VerifyWebView
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\runtime\setup-runtime.ps1"""; Description: "Set up offline Linux tools (may require administrator rights and restart)"; Flags: postinstall skipifsilent
Filename: "{app}\hexhound.exe"; Description: "Launch HexHound"; Flags: postinstall nowait skipifsilent unchecked

[Code]
function NeedsWebView: Boolean;
var Version: String;
begin
  Result := not ((RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0')) or
    (RegQueryStringValue(HKLM32, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0')));
end;

procedure VerifyWebView;
begin
  if NeedsWebView then
    RaiseException('WebView2 installation failed. Please run Setup again.');
end;
