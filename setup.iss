[Setup]
AppName=D2 Monitor
AppVersion=1.0
DefaultDirName={pf}\D2Monitor
DefaultGroupName=D2 Monitor
OutputDir=userdocs:Inno Setup Examples Output
OutputBaseFilename=D2MonitorSetup
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin

[Files]
; Add your script and any other necessary files here
Source: "C:\\D2_Free.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\\config.ini.template"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Run]
; Check and install Python if not found
Filename: "{tmp}\python-installer.exe"; Parameters: "/quiet InstallAllUsers=1 PrependPath=1"; Check: not PythonIsInstalled(); Flags: runhidden
; Install Python packages
Filename: "{app}\Python\python.exe"; Parameters: "-m pip install boto3 watchdog"; WorkingDir: "{app}"; Flags: runascurrentuser runhidden; StatusMsg: "Installing Python dependencies..."

[Code]
function PythonIsInstalled(): Boolean;
begin
  Result := RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Python\PythonCore\3.8');
end;

procedure InitializeWizard();
var
  PythonInstallerPath: string;
begin
  if not PythonIsInstalled() then
  begin
    if not IsAdminLoggedOn() then
    begin
      MsgBox('Python installation requires administrative privileges. Please restart the setup as an administrator.', mbError, MB_OK);
      Abort();
    end
    else
    begin
      // Download Python Installer
      PythonInstallerPath := ExpandConstant('{tmp}\python-installer.exe');
      if not DownloadFile('https://www.python.org/ftp/python/3.8.0/python-3.8.0-amd64.exe', PythonInstallerPath) then
      begin
        MsgBox('Failed to download Python installer.', mbError, MB_OK);
        Abort();
      end;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Create scheduled task for script
    if not Exec('schtasks', '/Create /F /SC ONLOGON /RL HIGHEST /TN "D2Monitor" /TR "' + ExpandConstant('{app}\your_script.py') + '"', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode) then
    begin
      MsgBox('Failed to create scheduled task. Error code: ' + IntToStr(ErrorCode), mbError, MB_OK);
    end;
  end;
end;

