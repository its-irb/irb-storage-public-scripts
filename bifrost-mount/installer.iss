#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef BranchSuffix
  #define BranchSuffix "local"
#endif
#ifndef AppName
  #define AppName "bifrost-mount"
#endif

[Setup]
AppName=Bifrost-mount
AppVersion={#AppVersion}
DefaultDirName={autopf}\Bifrost-mount
DefaultGroupName=Bifrost-mount
OutputDir=installer
OutputBaseFilename={#AppName}-{#BranchSuffix}-windows
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\*"; \
  DestDir: "{app}"; \
  Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Bifrost-mount"; Filename: "{app}\bifrost-mount.exe"
Name: "{autodesktop}\Bifrost-mount";  Filename: "{app}\bifrost-mount.exe"

[Run]
Filename: "{app}\bifrost-mount.exe"; \
  Description: "Launch Bifrost-mount"; \
  Flags: nowait postinstall skipifsilent
