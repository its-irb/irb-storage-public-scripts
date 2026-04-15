#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef BranchSuffix
  #define BranchSuffix "local"
#endif

[Setup]
AppName=Bifrost
AppVersion={#AppVersion}
DefaultDirName={autopf}\Bifrost
DefaultGroupName=Bifrost
OutputDir=installer
OutputBaseFilename=bifrost-{#BranchSuffix}-windows
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\*"; \
  DestDir: "{app}"; \
  Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Bifrost"; Filename: "{app}\bifrost.exe"
Name: "{autodesktop}\Bifrost";  Filename: "{app}\bifrost.exe"

[Run]
Filename: "{app}\bifrost.exe"; \
  Description: "Launch Bifrost"; \
  Flags: nowait postinstall skipifsilent
