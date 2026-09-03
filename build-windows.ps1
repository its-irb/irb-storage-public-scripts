param([string]$app = "bifrost-transfer")

$toml = "$app/pyproject.toml"

Copy-Item "$app/pyproject-template.toml" $toml -Force

(Get-Content $toml -Raw) `
  -replace '"bifrost-shared @ file:///__BUILDPATH__/shared"', "`"bifrost-shared @ file://$root/../shared`"" |
  Set-Content $toml -NoNewline

Write-Host "=== pyproject.toml tras reemplazo ==="
Select-String "bifrost-shared" "$app/pyproject.toml"
Write-Host "======================================"



Push-Location "$app/src"
bash ../../shared/windows-assets-downloader.sh
Pop-Location

Set-Location $app
uv sync --reinstall-package bifrost-shared
flet build windows
Set-Location ..