# Build & Release — BIFROST

## Versioning

- **CI** escribe `__version__ = '1.0.<github.run_number>'` en `<app>/src/version.py` y `version = "1.0.<run_number>"` en `<app>/pyproject.toml` en cada build.
- **Local**: `2.0.0.dev` (lo escribe `build-macos.sh`; mantenido así en dev).
- `src/version.py` contiene el placeholder `2.0.0.dev` commiteado en el repo. CI/build lo sobrescriben en sitio con `1.0.<run_number>` antes de empaquetar (el cambio no se commitea).
- `backend.py` importa `__version__` con fallback `"1.0.1"` si falta `version.py`.

## Paso previo obligatorio: wheel `bifrost-shared`

Antes de `flet build` hay que generar el wheel y reescribir el placeholder `__BUILDPATH__` en `<app>/pyproject.toml`:

```toml
"bifrost-shared @ file:///__BUILDPATH__/shared"
```

Tres caminos:

### Windows local — `build-local.ps1`

```powershell
.\build-local.ps1 -app bifrost-mount      # o bifrost-transfer
```

Flujo: `python -m build shared/ --outdir <app>/` → localiza `bifrost_shared-*.whl` → reemplaza `__BUILDPATH__` por la ruta real del wheel en `<app>/pyproject.toml` → `cd <app>; flet build windows` → revierte el reemplazo.

### macOS local — `<app>/build-macos.sh`

```bash
cd bifrost-mount && bash build-macos.sh     # o bifrost-transfer
```

Flujo: `sed` reemplaza `__BUILDPATH__` por `$(pwd)/..` y la versión por `2.0.0.dev` → `uv sync --project <app>` → activa venv → descarga rclone (y fuse-t si mount) → escribe `version.py` → `flet build macos -o ./dist --project <app>` → (mount) copia `fuse_t.framework` a `dist/bifrost-mount.app/Contents/Frameworks/`.

### CI — `.github/workflows/main.yml`

CI hace `sed` con `GITHUB_WORKSPACE` (en macOS usa `sed -i ''`, en Windows `sed -i`). Ver detalle abajo.

## CI (`.github/workflows/main.yml`)

**Trigger**: push a `main`, `release`, `develop`, `feature/**` que toque `bifrost-transfer/**`, `bifrost-mount/**`, `shared/**` o el propio workflow. También `workflow_dispatch`.

### Job `build-macos` (matrix `[bifrost-transfer, bifrost-mount]`, `macos-latest`)

1. Checkout (actions/checkout@v6.0.2).
2. Python 3.12 (actions/setup-python@v6.2.0).
3. Escribe `__version__ = '1.0.<run_number>'` en `<app>/src/version.py`.
4. `sed` versión en `<app>/pyproject.toml`.
5. `sed` `__BUILDPATH__` → `GITHUB_WORKSPACE` en `<app>/pyproject.toml`.
6. `pip install uv` + `uv sync --project <app>` + añade `.venv/bin` al PATH.
7. Descarga assets: si `bifrost-mount` → `macos-assets-downloader.sh` (rclone + fuse-t); si `bifrost-transfer` → `macos-rclone-downloader.sh` (rclone solo).
8. Limpia nombre de rama (`/` → `-`).
9. `flet build macos --output dist --no-rich-output` (con `echo "y"` para confirmar).
10. (mount) Debug del bundle + copia `fuse_t.framework` a `Contents/Frameworks/`.
11. Crea DMG con `L-Super/create-dmg-actions@v1.0.3` (`<app>-macos.dmg`).
12. Sube artefacto (`.dmg`).

### Job `build-windows` (matrix, `windows-latest`)

1. Checkout.
2. Enable long paths (`git config core.longpaths true` + registro).
3. Python 3.12.
4. `sed` `__BUILDPATH__` → `GITHUB_WORKSPACE`.
5. `sed` versión en `<app>/pyproject.toml`.
6. `uv sync --project <app>`.
7. Copia `shared/windows-assets-downloader.sh` dentro de `<app>/src/` y lo ejecuta (descarga `rclone.exe`).
8. Limpia nombre de rama.
9. Escribe `__version__` en `<app>/src/version.py`.
10. `uv run flet build windows --output dist --no-rich-output -v` con `PYTHONUTF8=1`.
11. Crea `installer/`.
12. **Inno Setup**: `ISCC.exe /DBranchSuffix=<branch> /DAppVersion=1.0.<run> /DAppName=<app> <app>/installer.iss` → genera `<app>/installer/<app>-<branch>-windows.exe`.
13. **Firma con signtool**: decodifica PFX desde secreto `IRBCODESIGNING` (base64) + password `IRBCODESIGNING_PASSWORD`, busca `signtool.exe` en Windows Kits, firma con `/fd sha256 /t http://timestamp.digicert.com`, borra el PFX.
14. Sube artefacto (`.exe`).

### Job `release` (solo `main`/`release`)

`needs: [build-macos, build-windows]`. Descarga todos los artefactos (`merge-multiple: true`), crea GitHub Release con `softprops/action-gh-release@v2`, tag `v1.0.<run_number>`, adjunta `dist/*`.

### Nota histórica

El job de build Linux (Rocky Linux) se eliminó en commit `46bd9dd` ("Remove Rocky Linux build job from workflow"). El modo web OOD se sirve desde el cluster sin build local específico: el proceso Python corre directamente con `BIFROST_CLUSTER=1` y el `rclone` del PATH.

## Assets (rclone / fuse-t)

Descargados por scripts en `shared/` antes de `flet build`:

| Script | Plataforma | Qué descarga | Destino |
|---|---|---|---|
| `macos-assets-downloader.sh` | macOS (mount) | rclone 1.72.1 + `fuse_t.framework` 1.0.49 | `./assets/bin/rclone` + `../frameworks/fuse_t.framework` |
| `macos-rclone-downloader.sh` | macOS (transfer) | rclone 1.72.1 | `./assets/bin/rclone` |
| `windows-assets-downloader.sh` | Windows | `rclone.exe` 1.72.1 | `./assets/bin/rclone.exe` |
| `linux-assets-downloader.sh` | Linux | rclone 1.72.1 | `./assets/bin/rclone` |

Los scripts se ejecutan **desde `<app>/src/`** (usan rutas relativas `./assets/bin`). En CI Windows se copia el script a `<app>/src/` antes de ejecutarlo. Los binarios acaban en `<app>/src/assets/bin/` (gitignored salvo `.keep`). En dev local normalmente ya están si se han descargado antes.

## `installer.iss` (Inno Setup)

Cada app tiene el suyo (`bifrost-mount/installer.iss`, `bifrost-transfer/installer.iss`). Define `AppName`, `AppVersion`, `BranchSuffix` (con defaults `local`/`1.0.0`). Empaqueta `dist/*` en `{autopf}\Bifrost-<app>`, crea iconos en programas y escritorio, lanza la app post-install (`Flags: nowait postinstall skipifsilent`).

## Autoupdate (runtime)

`backend.check_update_version(force_update=False)` consulta la última release del repo GitHub (`REPO = "its-irb/irb-storage-public-scripts"`) comparando versiones semánticas (`_parse_version`). `should_check_for_updates()` controla la frecuencia (no spamea al usuario). `get_update_file_suffix()` devuelve el sufijo de plataforma (`-macos.dmg`, `-windows.exe`, etc.). `download_new_binary(file_name)` descarga el binario nuevo.

`build_update_content` (en `frontend.py`, compartido por ambas apps) muestra el chequeo inicial y, si hay versión nueva, ofrece "Update now" / "Continue anyway":

- **Windows**: lanza un `.bat` (escrito por `_escribir_y_lanzar_updater_windows`) que espera 2s, ejecuta el `.exe` descargado en modo silencioso Inno Setup (`/SILENT /SUPPRESSMSGBOXES /NOCANCEL`), y reabre la app desde `%ProgramFiles(x86)%\Bifrost-<flavour>\`. Luego `os._exit(0)`.
- **macOS**: `hdiutil attach` del DMG, determina el mount point, y mediante `osascript ... with administrator privileges` ejecuta un script que hace `pkill` de la app, espera, `rm -rf /Applications/bifrost-<flavour>.app`, `ditto` desde el DMG, `hdiutil detach`, `xattr -d com.apple.quarantine` recursivo, y `open`. Luego `os._exit(0)`.
- **Linux**: `os.replace` el binario descargado sobre `sys.argv[0]`, `chmod +x`, y muestra diálogo pidiendo reiniciar.

## Regenerar dependencias

Si se añaden/actualizan deps Python:

```bash
python -m pip freeze > src/pip-requirements.txt
uv add -r pip-requirements.txt
```

Los deps congelados viven en cada `<app>/pyproject.toml` y en `shared/pyproject.toml`. `uv.lock` está gitignored. No existe `src/pip-requirements.txt` en el repo actualmente (la instrucción es para crearlo cuando haga falta).
