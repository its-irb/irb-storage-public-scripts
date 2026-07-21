# bifrost-mount — build e instalación

Ficheros y reglas para compilar, empaquetar e instalar bifrost-mount.

## Ficheros de build

- `bifrost-mount/pyproject.toml` — deps congeladas; referencia
  `bifrost-shared @ file:///__BUILDPATH__/shared`.
- `bifrost-mount/installer.iss` — Inno Setup (Windows).
- `bifrost-mount/build-macos.sh` — build local macOS.
- `bifrost-mount/frameworks/` — `fuse_t.framework` (macOS). **Raíz de la
  app, no bajo `src/`.**
- `build-local.ps1` (raíz repo) — build local Windows.
- `shared/*-assets-downloader.sh` — rclone + fuse-t.
- `.github/workflows/main.yml` — CI 3 plataformas.

## Invariantes

- `__BUILDPATH__` en `pyproject.toml` se sustituye antes de build (CI con
  `sed`, `build-local.ps1` con wheel real, `build-macos.sh` con `pwd`).
- `frameworks/` en raíz de app — CI y `build-macos.sh` esperan esa ruta.
- `src/version.py` lo escribe CI (`1.0.<run_number>`). No commitear.
- Deps congeladas en `pyproject.toml`. Actualizar con `pip freeze` + `uv
  add -r`.
- `config.py` importable como módulo top-level (`from config import
  APP_INFO`).

## CI — 3 plataformas

| Plataforma | Herramienta | Artefacto |
|---|---|---|
| macOS | `flet build macos` + DMG | `bifrost-mount-macos.dmg` |
| Windows | `flet build windows` + Inno Setup | `.exe` |
| Rocky Linux 9 | PyInstaller onefile | `bifrost-mount-linux` |

Linux usa PyInstaller onefile porque `flet build linux` no soporta Rocky
Linux 9 (solo Debian/Ubuntu).

## Asset downloaders

- rclone: `shared/{windows,macos,linux}-assets-downloader.sh` →
  `src/assets/bin/rclone`.
- fuse-t (solo macOS, solo bifrost-mount):
  `shared/macos-assets-downloader.sh` → `frameworks/fuse_t.framework`.

## Decisión de diseño

Bifrost-mount es **read-only** (`rclone mount --read-only`). Evita buffer
issues y pérdida de datos. Para writes, bifrost-transfer.

## Instalación de usuarios

ITS ha hecho instalación remota masiva en Windows y macOS. Los binarios
están en GitHub releases (`its-irb/irb-storage-public-scripts/releases`).
Auto-update al iniciar. Linux: pendiente de confirmar distribución.
