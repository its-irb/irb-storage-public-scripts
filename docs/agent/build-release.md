# Build & Release — BIFROST

## Versioning

- CI (`.github/workflows/main.yml`) escribe `__version__ = '1.0.<run_number>'` en `<app>/src/version.py` y `version = "1.0.<run_number>"` en `<app>/pyproject.toml` en cada build.
- Local: `2.0.0.dev` (escrito por `build-macos.sh` y mantenido en dev).
- `src/version.py` contiene el placeholder `2.0.0.dev` commiteado en el repo. CI/build lo sobrescriben en sitio con `1.0.<run_number>` antes de empaquetar (sin commitear el cambio).
- `backend.py` importa `__version__` de `version.py` con fallback `"1.0.1"`.

## Wheel `bifrost-shared` — paso previo obligatorio

Antes de `flet build` hay que generar el wheel y reescribir `__BUILDPATH__` en el `pyproject.toml` de la app:

```toml
"bifrost-shared @ file:///__BUILDPATH__/shared"
```

- **Windows local**: `build-local.ps1 -app <bifrost-mount|bifrost-transfer>` — genera wheel en `<app>/`, reemplaza `__BUILDPATH__` por la ruta real, corre `flet build windows`, revierte el cambio.
- **macOS local**: `<app>/build-macos.sh` — `sed` reemplaza `__BUILDPATH__` por `$(pwd)/..`, `uv sync --project <app>`, descarga assets, `flet build macos`, copia `fuse_t.framework` al bundle (solo mount).
- **CI**: `.github/workflows/main.yml` hace `sed` con `GITHUB_WORKSPACE` para ambas plataformas.

## CI (`.github/workflows/main.yml`)

Trigger: push a `main`, `release`, `develop`, `feature/**` que toque `bifrost-transfer/**`, `bifrost-mount/**`, `shared/**` o el workflow. También `workflow_dispatch`.

Jobs:
- **build-macos** (matrix `[bifrost-transfer, bifrost-mount]`, `macos-latest`): Python 3.12, escribe versión, `uv sync`, descarga rclone (+ fuse-t si mount), `flet build macos`, copia `fuse_t.framework` (mount), crea DMG (`L-Super/create-dmg-actions`), sube artefacto `.dmg`.
- **build-windows** (matrix, `windows-latest`): long paths ON, Python 3.12, `sed` `__BUILDPATH__`, `uv sync`, descarga `rclone.exe` (copia `windows-assets-downloader.sh` a `src/`), `flet build windows`, Inno Setup (`ISCC.exe` con `/DBranchSuffix /DAppVersion /DAppName`), **firma con signtool** (secreto `IRBCODESIGNING` PFX base64 + password, timestamp DigiCert), sube `.exe`.
- **release** (solo `main`/`release`): `softprops/action-gh-release`, tag `v1.0.<run_number>`, recoge artefactos macOS+Windows.

Nota: el job de build Linux (Rocky) se eliminó en commit `46bd9dd`. El modo web OOD se sirve desde el cluster sin build local específico (usa `BIFROST_CLUSTER=1`).

## Assets (rclone / fuse-t)

Descargados por scripts en `shared/` antes de `flet build`:

| Script | Plataforma | Qué descarga |
|---|---|---|
| `macos-assets-downloader.sh` | macOS (mount) | rclone 1.72.1 + `fuse_t.framework` 1.0.49 |
| `macos-rclone-downloader.sh` | macOS (transfer) | rclone 1.72.1 |
| `windows-assets-downloader.sh` | Windows | `rclone.exe` 1.72.1 |
| `linux-assets-downloader.sh` | Linux | rclone 1.72.1 |

CI copia `windows-assets-downloader.sh` dentro de `<app>/src/` antes de ejecutarlo. Los binarios acaban en `<app>/src/assets/bin/` (gitignored salvo `.keep`). En dev local normalmente no hace falta descargarlos si ya están.

## Empaquetado por plataforma

| Plataforma | Comando | Salida |
|---|---|---|
| macOS | `flet build macos` (vía `build-macos.sh` o CI) | `dist/<app>.app` → DMG |
| Windows | `flet build windows` + Inno Setup (`installer.iss`) | `dist/<app>/...` → `.exe` firmado |
| Linux | (sin build local; modo web OOD) | proceso Python en cluster |

## `installer.iss` (Inno Setup)

`#define AppName`, `AppVersion`, `BranchSuffix`. Empaqueta `dist/*` en `{autopf}\Bifrost-<app>`, crea iconos en programas y escritorio, lanza la app post-install. Cada app tiene el suyo (`bifrost-mount/installer.iss`, `bifrost-transfer/installer.iss`).

## Regenerar dependencias

Si se añaden/actualizan deps Python:
```bash
python -m pip freeze > src/pip-requirements.txt
uv add -r pip-requirements.txt
```
(Nota: `src/pip-requirements.txt` no existe actualmente en el repo; los deps congelados viven en cada `<app>/pyproject.toml` y en `shared/pyproject.toml`.)

## Autoupdate (runtime)

`backend.check_update_version()` consulta la última release del repo GitHub (`REPO = "its-irb/irb-storage-public-scripts"`). `should_check_for_updates()` controla la frecuencia. `download_new_binary("bifrost-<flavour>")` descarga el binario nuevo. `build_update_content` (en `frontend.py`) ofrece al usuario actualizar. Ver `frontend.md`.
