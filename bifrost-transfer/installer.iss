#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef BranchSuffix
  #define BranchSuffix "local"
#endif
#ifndef AppName
  #define AppName "bifrost-transfer"
#endif

[Setup]
AppName=Bifrost-transfer
AppVersion={#AppVersion}
DefaultDirName={autopf}\Bifrost-transfer
DefaultGroupName=Bifrost-transfer
OutputDir=installer
OutputBaseFilename={#AppName}-{#BranchSuffix}-windows
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\*"; \
  DestDir: "{app}"; \
  Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Bifrost-transfer"; Filename: "{app}\bifrost-transfer.exe"
Name: "{autodesktop}\Bifrost-transfer";  Filename: "{app}\bifrost-transfer.exe"

[Run]
Filename: "{app}\bifrost-transfer.exe"; \
  Description: "Launch Bifrost Transfer"; \
  Flags: nowait postinstall skipifsilent
