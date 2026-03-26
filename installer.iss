[Setup]
AppName=Bifrost
AppVersion=1.0.0
DefaultDirName={autopf}\Bifrost
DefaultGroupName=Bifrost
OutputDir=dist
OutputBaseFilename=Bifrost_installer
Compression=lzma
SolidCompression=yes

[Files]
Source: "bifrost\*"; \
  DestDir: "{app}"; \
  Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Bifrost"; Filename: "{app}\bifrost.exe"
Name: "{autodesktop}\Bifrost";  Filename: "{app}\bifrost.exe"

[Run]
Filename: "{app}\bifrost.exe"; \
  Description: "Launch Bifrost"; \
  Flags: nowait postinstall skipifsilent
