param([string]$app = "bifrost-mount")

$root = (Get-Location).Path
python -m build shared/ --outdir "$app/src/"
$wheel = (Get-ChildItem "$app/src/bifrost_backend-*.whl").FullName.Replace('\', '/')

$toml = "$app/pyproject.toml"
(Get-Content $toml -Raw) `
  -replace '"bifrost-backend",', "`"bifrost-backend @ file:///$wheel`"," |
  Set-Content $toml -NoNewline

Set-Location $app
flet build windows
Set-Location ..

# Revertir
(Get-Content $toml -Raw) `
  -replace "`"bifrost-backend @ file:///[^`"]+`",", '"bifrost-backend",' |
  Set-Content $toml -NoNewline