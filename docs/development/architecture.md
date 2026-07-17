# Arquitectura — BIFROST

## Intención

BIFROST da acceso al almacenamiento MinIO S3 del IRB Barcelona a través de dos aplicaciones de escritorio Flet/Python:

- **bifrost-transfer** — sube datos desde carpetas de red (SMB/CIFS) o locales a buckets MinIO, con verificación de integridad y etiquetado de metadatos por perfil. Incluye un **Tag Manager** para editar tags S3 sin re-subir. Funciona en modo desktop (macOS/Windows) y modo web (Open OnDemand en cluster Linux).
- **bifrost-mount** — monta carpetas de buckets MinIO como unidad local. Solo desktop.

El repositorio es un monorepo con un wheel compartido (`bifrost-shared`) que contiene toda la lógica de negocio y los componentes de UI comunes. Las apps son capas finas de vistas Flet que orquestan el backend.

## Estructura del repositorio

```
bifrost-mount/            # App de montado (desktop)
  src/
    main.py               # GUI Flet — punto de entrada (~1398 LOC)
    config.py             # APP_INFO = {"flavour": "mount", ...}
    version.py            # __version__ (placeholder 2.0.0.dev; CI lo sobrescribe en build)
    assets/bin/           # rclone empaquetado (descargado en build)
    frameworks/           # fuse_t.framework (macOS, descargado en build)
  pyproject.toml          # Config flet build + deps congeladas
  installer.iss           # Inno Setup (Windows)
  build-macos.sh          # Build local macOS

bifrost-transfer/         # App de transferencia (desktop + web)
  src/
    main.py               # GUI Flet (~4130 LOC: desktop + web + Tag Manager)
    config.py             # APP_INFO = {"flavour": "transfer", ...}
    version.py            # __version__
    meta_fields.py        # Perfiles de metadatos, LAB_ACRONYMS, lab filter (~540 LOC)
    assets/bin/           # rclone empaquetado
    storage/              # Datos temporales de transferencia
  pyproject.toml
  installer.iss
  build-macos.sh

shared/                   # Wheel bifrost-shared
  pyproject.toml          # Define paquetes bifrost_backend + bifrost_frontend (hatchling)
  bifrost_backend/
    __init__.py
    backend.py            # ~1791 LOC — toda la lógica de negocio
  bifrost_frontend/
    __init__.py
    frontend.py           # ~388 LOC — paleta + componentes Flet
  linux-assets-downloader.sh
  macos-assets-downloader.sh     # rclone + fuse-t (mount)
  macos-rclone-downloader.sh     # rclone solo (transfer)
  windows-assets-downloader.sh

old/                      # Scripts legacy (no usar)
build-local.ps1           # Build local Windows (genera wheel + flet build)
.github/workflows/main.yml  # CI macOS + Windows + release
docs/                     # Documentación (agent/development/user)
CLAUDE.md                 # Memoria del arnés Claude (consumida por la tool)
CLAUDE_BACKEND.md
CLAUDE_FRONTEND.md
README.md                 # Puerta de entrada pública (inglés)
package.json              # commitlint + husky + commitizen (tooling de commits)
commitlint.config.js
.husky/{commit-msg, pre-commit}
```

## Wheel compartido `bifrost-shared`

`shared/pyproject.toml` declara dos paquetes empaquetados en un único wheel:

```toml
[project]
name = "bifrost-shared"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["flet==0.84.0", "boto3==1.42.12", "ldap3==2.9.1", "cryptography==46.0.7", ...]

[tool.hatch.build.targets.wheel]
packages = ["bifrost_backend", "bifrost_frontend"]
```

Cada app lo referencia en su `pyproject.toml` con un placeholder:

```toml
"bifrost-shared @ file:///__BUILDPATH__/shared"
```

`__BUILDPATH__` se reescribe a la ruta real del wheel generado en build time (CI o `build-local.ps1` o `build-macos.sh`). En desarrollo hay dos opciones (ver `setup.md`): `uv sync --project <app>` (gestiona todo) o `pip install -e shared/` (editable) descomentando además el bloque `sys.path` de `main.py`.

## Acoplamiento app ↔ shared

Cada `main.py` arranca con:

```python
from bifrost_backend import backend
from bifrost_frontend.frontend import *      # paleta + componentes
from config import APP_INFO                  # {"flavour": "mount"|"transfer", ...}
from version import __version__              # (transfer además importa meta_fields)
```

Puntos clave del acoplamiento:

1. **`config.py` es top-level en cada app** (`bifrost-<flavour>/src/config.py`). El backend hace `from config import APP_INFO`, por eso cada app tiene el suyo con un único dict.
2. **`APP_INFO["flavour"]`** lo usa el backend en dev para resolver rutas de assets: construye `bifrost-<flavour>/src/assets/bin/` relativo a `shared/`.
3. **Acoplamiento backend → frontend**: `backend.py` importa `show_dialog, C_ERROR` de `bifrost_frontend.frontend` y los usa en errores no recuperables (`safe_thread` los muestra en diálogo). No es un backend puro / desacoplado.
4. **`bifrost_frontend.frontend` importa `bifrost_backend.backend`** (y `config.APP_INFO`). Hay dependencia circular entre los dos paquetes del wheel; se resuelve porque Python permite importar módulos de un paquete a otro en runtime.

## Entry points

### Desktop (ambas apps)

`flet run` desde la carpeta de la app. Internamente cada `main.py` termina con:

```python
if __name__ == "__main__":
    ft.run(main)
```

`main(page: ft.Page)` arma el flujo de vistas y configura la ventana (título, colores, tamaño, tema oscuro). En desktop, `main.py` empieza con `show_screen(build_update_content(page, on_continue=go_login))` (chequeo de updates) salvo en modo web.

### Web (solo transfer, OOD)

`BIFROST_CLUSTER=1` activa el bloque ASGI al final de `bifrost-transfer/src/main.py`:

```python
if os.environ.get("BIFROST_CLUSTER") == "1":
    from flet.fastapi import FletApp, app_manager
    from fastapi import FastAPI, WebSocket
    app = FastAPI()
    flet_asgi_app = ft.app(main, export_asgi_app=True)
    app.mount(WEBPATH, flet_asgi_app)

    @app.websocket(WEBSOCKET_ENDPOINT)
    async def flet_app(websocket: WebSocket):
        token = websocket.cookies.get("bifrost_auth_token")
        if not SECRET_TOKEN or token != SECRET_TOKEN:
            await websocket.close(code=1008); return
        await FletApp(loop=..., main=main).handle(websocket)
```

OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → `IS_WEB=True`. El servidor ASGI es **Hypercorn** (event loop asyncio único). Cada pestaña del navegador abre un WebSocket independiente con su propio objeto `page`. Ver `web-mode.md`.

## Detección de modo

```python
# bifrost-transfer/src/main.py
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → `IS_WEB=True`.
- `flet run --web` activa modo web en dev local (`"--web" in sys.argv`).
- `BIFROST_CLUSTER=1` activa `IS_WEB=True` y el flujo CIFS/shares del cluster Linux.
- Adicionalmente, dentro de `main(page)`: `IS_WEB = IS_WEB or page.web`.

`bifrost-mount` no tiene modo web.

## Flujo de vistas

```
# bifrost-mount (desktop):
view_update → view_login → view_minio → view_credentials (auto) → view_mount

# bifrost-transfer (desktop Mac/Windows):
view_update → view_login → view_minio → view_credentials (auto) → view_copy

# bifrost-transfer (Linux cluster, BIFROST_CLUSTER=1):
view_update → view_login → view_shares → view_minio → view_credentials → view_copy
```

- `view_update` — `build_update_content` (en `frontend.py`, compartido): chequea updates y ofrece actualizar o continuar.
- `view_login` — `_build_login_content`: valida LDAP (salvo `BIFROST_NO_LDAP=1`). En web, pre-rellena username si hay sesión previa.
- `view_shares` — `_build_shares_content` (solo cluster Linux): monta shares SMB/CIFS accesibles para el usuario. Los mounts CIFS son **siempre read-only** (`montar_share_rclone` usa `--read-only`); solo sirven como origen de copia.
- `view_minio` — `_build_minio_content`: selección de servidor MinIO (`backend.MINIO_SERVERS`).
- `view_credentials` — `_build_credentials_content`: **automática**. Si STS con >3 días → skip directo a `view_mount`/`view_copy`. Si <3 días o sin credenciales → renueva por 7 días mostrando progreso.
- `view_mount` (mount) — `_build_mount_bucket`: navegador de buckets + montaje. El montaje S3 es **siempre read-only** (`mount_rclone_S3_prefix_to_folder` usa `--read-only --links`); el usuario puede leer pero no modificar, crear ni borrar ficheros. Para subir datos se usa Bifrost Transfer.
- `view_copy` (transfer) — `_build_copy_content`: navegador rclone de destino, selector de origen, opciones de copia, log en vivo. Botón "Mount CIFS" (web) y acceso a Tag Manager (`on_tags=go_tags`).

`view_copy` contiene un navegador de carpetas rclone (`build_rclone_browser`) para elegir destino, un selector de origen (local o share SMB), opciones de copia y un panel de log en vivo (`ft.ListView auto_scroll=True`).

## Servidores MinIO (`backend.MINIO_SERVERS`)

```python
MINIO_SERVERS = {
    "minio-archive": {"IRB": {"profile": "minio-archive", "endpoint": "https://minio-archive.sc.irbbarcelona.org:9000"}},
    "irbminio":      {"IRB": {"profile": "irbminio",      "endpoint": "http://irbminio.sc.irbbarcelona.org:9000"}},
    "minio":         {"IRB": {"profile": "minio",         "endpoint": "https://minio.sc.irbbarcelona.org:9000",
                              "extra_rclone_config": {"no_check_bucket": "true", "region": "eu-south-2"}}},
}
DEFAULT_S3_REGION = "eu-south-2"
REPO = "its-irb/irb-storage-public-scripts"
```

Cada entrada tiene perfil rclone y endpoint. `minio` añade config extra (no_check_bucket + región).

## Dependencias clave

- **Flet 0.84.0** — framework de UI (ASGI en web vía `flet-web` + `hypercorn`).
- **boto3/botocore 1.42.12** — tagging S3 directo (sin rclone).
- **ldap3 2.9.1** — autenticación LDAP IRB.
- **PyJWT** — decodificación de session tokens STS MinIO.
- **requests/urllib3** — llamadas a la API STS de MinIO.
- **cryptography** — dependencia transitiva.
- **rclone 1.72.1** (binario externo, empaquetado en `assets/bin/`).
- **fuse-t 1.0.49** (macOS, mount) / **WinFsp** (Windows, mount, no empaquetable).

Python ≥3.11 (shared), 3.12 (CI). Cada `pyproject.toml` congela las versiones exactas.

## Sin tests automatizados

No hay suite de tests. Los cambios se validan ejecutando las apps manualmente con `flet run` (ver `setup.md`). No hay framework de testing configurado.

## Decisiones y restricciones

- **Monorepo + wheel compartido** en lugar de submódulos: simplifica el build y el versionado conjunto, pero obliga a regenerar el wheel y reescribir `__BUILDPATH__` en cada build.
- **Backend acoplado al frontend** (`show_dialog`, `C_ERROR`): trade-off deliberado para mostrar errores no recuperables directamente al usuario sin duplicar lógica de diálogos.
- **`config.py` top-level por app** en lugar de en `shared/`: permite que el backend resuelva rutas de assets según el flavour sin inyección de dependencias.
- **Sin tests**: proyecto interno con superficie funcional acotada y validación manual; introducir tests requeriría mocking de LDAP/MinIO/rclone/Flet.
- **Modo web solo en transfer**: mount requiere FUSE a nivel kernel, inviable en navegador.
