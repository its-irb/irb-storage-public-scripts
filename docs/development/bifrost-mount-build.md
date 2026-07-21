# Build y empaquetado de bifrost-mount

Guía para compilar y empaquetar bifrost-mount desde el código fuente.

## Ficheros implicados

| Fichero | Función |
|---|---|
| `bifrost-mount/pyproject.toml` | Configuración de `flet build` y dependencias congeladas. Referencia `bifrost-shared @ file:///__BUILDPATH__/shared`. |
| `bifrost-mount/installer.iss` | Configuración Inno Setup para el instalador Windows (`.exe`). |
| `bifrost-mount/build-macos.sh` | Build local para macOS. |
| `bifrost-mount/frameworks/` | Contiene `fuse_t.framework` (macOS). Está en la **raíz de la app**, no bajo `src/`. |
| `bifrost-mount/src/assets/bin/` | Destino del binario `rclone` descargado por los asset downloaders. |
| `build-local.ps1` (raíz del repo) | Build local para Windows. Genera el wheel `bifrost-shared` y ejecuta `flet build windows`. |
| `shared/*-assets-downloader.sh` | Scripts que descargan rclone y fuse-t según la plataforma. |
| `.github/workflows/main.yml` | CI: build de macOS, Windows y Rocky Linux. |

## Mecanismo `__BUILDPATH__` + wheel `bifrost-shared`

El `pyproject.toml` de bifrost-mount referencia el backend compartido como:

```
bifrost-shared @ file:///__BUILDPATH__/shared
```

El placeholder `__BUILDPATH__` se sustituye por la ruta real antes de
construir:

- **CI** (`main.yml`): sustitución con `sed` usando `${GITHUB_WORKSPACE}`.
- **Windows local** (`build-local.ps1`): genera el wheel con
  `python -m build shared/`, sustituye la línea por la ruta del wheel
  generado y revierte el cambio al terminar.
- **macOS local** (`build-macos.sh`): sustitución con `sed` usando
  `$(pwd)/..`.

## Asset downloaders

Antes de empaquetar, hay que descargar los binarios externos a
`src/assets/bin/`:

- **rclone** (todas las plataformas): `shared/{windows,macos,linux}-assets-downloader.sh`
  o `shared/macos-rclone-downloader.sh`.
- **fuse-t** (solo macOS, solo bifrost-mount): `shared/macos-assets-downloader.sh`
  descarga también `fuse_t.framework` a `bifrost-mount/frameworks/`.

Estos scripts los ejecuta el CI automáticamente. En builds locales macOS,
`build-macos.sh` los invoca.

## Builds locales

### macOS

```bash
cd bifrost-mount
./build-macos.sh
```

El script sustituye `__BUILDPATH__`, instala dependencias con `uv sync`,
descarga rclone y fuse-t, ejecuta `flet build macos` y copia
`fuse_t.framework` al bundle `.app/Contents/Frameworks/`.

### Windows

```powershell
.\build-local.ps1 -app bifrost-mount
```

Genera el wheel de `bifrost-shared`, sustituye la referencia en
`pyproject.toml`, ejecuta `flet build windows` y revierte el cambio.

No hay build local documentado para Linux. El CI usa PyInstaller onefile
sobre Rocky Linux 9 (ver abajo).

## CI — 3 plataformas

`.github/workflows/main.yml` define tres jobs en paralelo:

| Job | Plataforma | Herramienta | Artefacto |
|---|---|---|---|
| `build-macos` | macOS | `flet build macos` + create-dmg | `bifrost-mount-macos.dmg` |
| `build-windows` | Windows | `flet build windows` + Inno Setup | `bifrost-mount-<branch>-windows.exe` |
| `build-rocky` | Rocky Linux 9 | PyInstaller onefile | `bifrost-mount-linux` |

La versión se inyecta como `1.0.<run_number>` en `src/version.py` y
`pyproject.toml`.

El job `build-macos` copia `fuse_t.framework` al bundle después de
`flet build`. En Windows, Inno Setup empaqueta la carpeta `dist/` en un
único `.exe`. En Linux, como `flet build linux` no soporta Rocky Linux 9
(solo Debian/Ubuntu), se usa PyInstaller onefile con `--collect-all flet`
y hidden-imports de uvicorn.

## Invariantes a preservar

1. **`frameworks/` en la raíz de la app**, no bajo `src/`. El CI y
   `build-macos.sh` esperan esa ruta.
2. **`src/version.py` lo escribe el CI** en cada build. No commitear el
   fichero generado (ver `.gitignore`).
3. **Las dependencias están congeladas** en `pyproject.toml` por app. Si
   se actualizan, regenerar con `pip freeze > src/pip-requirements.txt` y
   `uv add -r src/pip-requirements.txt`.
4. **fuse-t va embebido** en `.app/Contents/Frameworks/` para macOS. El
   backend lo localiza vía `CGOFUSE_LIBFUSE_PATH`.
5. **`config.py` debe ser importable como módulo top-level**: el backend
   hace `from config import APP_INFO`.

## Decisión de diseño: solo lectura

Bifrost-mount monta los buckets con `rclone mount --read-only --links`.
Esto es intencional: evita problemas de buffer y asegura que no se pierdan
datos. Para subir, modificar o borrar datos, existe bifrost-transfer.
