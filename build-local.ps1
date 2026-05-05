param([string]$app = "bifrost-mount")

$root = (Get-Location).Path
python -m build shared/ --outdir "$app/"

$wheel = (Get-ChildItem "$app/bifrost_shared-*.whl").FullName.Replace('\', '/')

if (-not $wheel) {
    Write-Error "No se encontró bifrost_shared-*.whl en $app/"
    exit 1
}

$toml = "$app/pyproject.toml"

(Get-Content $toml -Raw) `
  -replace '"bifrost-shared @ file:///__BUILDPATH__/shared"', "`"bifrost-shared @ file:///$wheel`"" |
  Set-Content $toml -NoNewline

Write-Host "=== pyproject.toml tras reemplazo ==="
Select-String "bifrost-shared" "$app/pyproject.toml"
Write-Host "======================================"

Set-Location $app
flet build windows
Set-Location ..

# Revertir
(Get-Content $toml -Raw) `
  -replace '"bifrost-shared @ file:///[^"]+?"', '"bifrost-shared @ file:///__BUILDPATH__/shared"' |
  Set-Content $toml -NoNewline