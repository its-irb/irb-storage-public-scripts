# Arquitectura — BIFROST

## Qué es

BIFROST proporciona dos apps de escritorio Flet/Python para acceder al almacenamiento MinIO S3 del IRB Barcelona:

| App | Carpeta | Función | Modos |
|---|---|---|---|
| **bifrost-transfer** | `bifrost-transfer/` | Subir datos a buckets MinIO desde carpetas de red (SMB/CIFS) o locales, con verificación de integridad y etiquetado por perfil. Incluye **Tag Manager**. | Desktop + Web (OOD) |
| **bifrost-mount** | `bifrost-mount/` | Montar carpetas MinIO como unidad local. | Desktop |

## Layout del repo

```
bifrost-mount/            # App de montado (desktop)
  src/{main.py, config.py, version.py, meta_fields? no, assets/bin/, frameworks/}
  pyproject.toml installer.iss build-macos.sh

bifrost-transfer/         # App de transferencia (desktop + web)
  src/{main.py, config.py, version.py, meta_fields.py, assets/bin/, storage/}
  pyproject.toml installer.iss build-macos.sh

shared/                   # Wheel bifrost-shared (ver abajo)
  pyproject.toml
  bifrost_backend/{__init__.py, backend.py}     # ~1791 LOC — toda la lógica
  bifrost_frontend/{__init__.py, frontend.py}   # ~388 LOC — paleta + componentes
  {linux,macos,macos-rclone,windows}-assets-downloader.sh

old/                      # Scripts legacy (no usar)
build-local.ps1           # Build local Windows (genera wheel + flet build)
.github/workflows/main.yml  # CI macOS + Windows + release
docs/                     # Esta documentación
CLAUDE*.md                # Memoria del arnés Claude (consumida por la tool, no docs puras)
```

## Wheel compartido `bifrost-shared`

`shared/pyproject.toml` declara dos paquetes (`bifrost_backend`, `bifrost_frontend`) empaquetados como un único wheel `bifrost-shared`. Cada app lo referencia en su `pyproject.toml`:

```toml
"bifrost-shared @ file:///__BUILDPATH__/shared"
```

`__BUILDPATH__` lo reescribe el script de build (CI o `build-local.ps1`) a la ruta real del wheel generado. En desarrollo, instalar con `pip install -e shared/` o `uv sync --project <app>` (este último usa el `pyproject.toml` de la app).

## Acoplamiento app ↔ shared

Cada `main.py` arranca así:

```python
from bifrost_backend import backend
from bifrost_frontend.frontend import *      # paleta + componentes
from config import APP_INFO                  # {"flavour": "mount"|"transfer", ...}
```

- `config.py` es **top-level** en cada app (`bifrost-<flavour>/src/config.py`). El backend hace `from config import APP_INFO`, por eso cada app tiene el suyo.
- `APP_INFO["flavour"]` lo usa el backend para resolver rutas de assets en dev (`bifrost-<flavour>/src/assets/bin/`).
- **Acoplamiento backend → frontend**: `backend.py` importa `show_dialog, C_ERROR` de `bifrost_frontend.frontend`. No es un backend puro: muestra diálogos directamente en errores no recuperables.

## Entry points

- Desktop: `flet run` desde la carpeta de la app. Internamente `ft.run(main)` (cada `main.py` termina con `if __name__ == "__main__": ft.run(main)`).
- Web (transfer, OOD): `BIFROST_CLUSTER=1` activa el bloque ASGI al final de `bifrost-transfer/src/main.py` (FastAPI + `ft.app(main, export_asgi_app=True)` montado en `WEBPATH`). OOD importa `main.py` como módulo → `__name__ != "__main__"` → `IS_WEB=True`.

## Flujo de vistas

```
# bifrost-mount (desktop):
view_update → view_login → view_minio → view_credentials (auto) → view_mount

# bifrost-transfer (desktop):
view_update → view_login → view_minio → view_credentials (auto) → view_copy

# bifrost-transfer (Linux cluster, BIFROST_CLUSTER=1):
view_update → view_login → view_shares → view_minio → view_credentials → view_copy
```

`view_credentials` es automático: si quedan >3 días en las STS se salta; <3 días o sin credenciales → renueva por 7 días. Constantes `STS_RENEWAL_THRESHOLD_DAYS=3`, `STS_AUTO_RENEWAL_DAYS=7` en cada `main.py`.

## Servidores MinIO

Definidos en `backend.MINIO_SERVERS` (dict): `minio-archive`, `irbminio`, `minio` (este último con `extra_rclone_config`: `no_check_bucket`, `region=eu-south-2`). Endpoint y perfil rclone por servidor. `DEFAULT_S3_REGION = "eu-south-2"`. Repo GitHub: `its-irb/irb-storage-public-scripts`.

## Sin tests automatizados

No hay suite de tests. Los cambios se validan con `flet run` manualmente.
