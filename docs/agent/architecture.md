# Arquitectura

## Componentes

| Componente | Carpeta | Función |
|---|---|---|
| **bifrost-transfer** | `bifrost-transfer/` | Copia datos desde carpetas de red (SMB/CIFS), servidores SFTP o rutas locales a buckets MinIO S3, con verificación de integridad y etiquetado por perfil de metadatos. Incluye **Tag Manager** (etiquetado masivo sin re-subida) y **modo web** (Open OnDemand). |
| **bifrost-mount** | `bifrost-mount/` | Monta carpetas MinIO S3 como unidad local (Windows/macOS/Linux). Solo modo desktop. |
| **bifrost-shared** | `shared/` | Paquete wheel común: `bifrost_backend.backend` (toda la lógica de negocio) y `bifrost_frontend.frontend` (paleta + componentes Flet). |

Ambas apps son Flet con punto de entrada `src/main.py` y `pyproject.toml` por app.

## Estructura del repositorio

```text
bifrost-mount/            # App de montado (desktop)
  src/
    main.py               # GUI Flet — punto de entrada
    config.py             # APP_INFO = {"flavour": "mount", ...}
    version.py            # __version__ (lo escribe CI/build)
    assets/bin/           # rclone bundled
    frameworks/           # fuse_t.framework (macOS)
  pyproject-template.toml # Plantilla; pyproject.toml se genera localmente (no versionado)
  installer.iss           # Inno Setup (instalador Windows)
  build-macos.sh

bifrost-transfer/         # App de transferencia (desktop + web)
  src/
    main.py               # GUI Flet
    meta_fields.py        # Perfiles, campos de metadatos, filtro por laboratorio
    config.py             # APP_INFO = {"flavour": "transfer", ...}
    version.py
    assets/bin/
    storage/              # Datos temporales de transferencia
  pyproject-template.toml
  installer.iss
  build-macos.sh

shared/                   # Paquete bifrost-shared (wheel local)
  bifrost_backend/backend.py
  bifrost_frontend/frontend.py
  pyproject.toml          # Define el paquete "bifrost-shared"
  requirements.txt        # Deps comunes en dev
  *-assets-downloader.sh  # Descarga rclone/fuse-t para CI

old/                      # Scripts legacy (no usar)
build-windows.ps1         # Build local de Windows (pyproject desde plantilla + rclone + flet build)
.github/workflows/main.yml  # CI: build macOS/Windows + release
```

## Compartido vs específico

**Compartido (`shared/`)**:
- `bifrost_backend.backend` — LDAP, rclone (exec, perfiles, copy/check, listing), STS, SMB/CIFS, tagging boto3, `ui_call()`, `safe_thread()`, autoupdate.
- `bifrost_frontend.frontend` — paleta (`C_BG`, `C_PRIMARY`, …), botones (`btn_primary`, `btn_secondary`), `show_dialog`. Cada app hace `from bifrost_frontend.frontend import *`.

**Específico por app**:
- `src/main.py` — flujo de vistas Flet (login → minio → credenciales → mount/copy) y toda la UI específica. En `bifrost-transfer` incluye además el Tag Manager y el modo web.
- `src/meta_fields.py` — **solo en `bifrost-transfer`**: `FieldType`, `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS`, `build_lab_filter_widget`, `detect_profile`. Fuente canónica de perfiles y campos.
- `src/config.py` — solo `APP_INFO`. El backend lee `APP_INFO["flavour"]` para resolver rutas de assets en dev.
- `src/version.py` — escrito por CI/build (`__version__ = "1.0.<run_number>"`).
- `installer.iss`, `build-macos.sh`, `pyproject-template.toml` (deps congeladas por app).

## Acoplamiento e invariantes

- Las apps importan el backend vía `from bifrost_backend import backend` y
  `from config import APP_INFO`. **`config.py` debe ser importable como módulo
  top-level en cada app** (por eso cada app tiene el suyo aunque solo contenga
  `APP_INFO`).
- El `pyproject.toml` de cada app referencia
  `bifrost-shared @ file:///__BUILDPATH__/shared`; el script de build (CI o
  `build-windows.ps1` o `build-macos.sh`) sustituye `__BUILDPATH__` por la
  ruta real del paquete compartido.
  `pyproject.toml` no está versionado: se genera desde `pyproject-template.toml`.
- El backend importa del frontend (`show_dialog`, `C_ERROR` de
  `bifrost_frontend.frontend`): no es un backend desacoplado. No introduzcas
  importaciones circulares nuevas.
- **Regla de thread-safety**: toda mutación de `control.controls` o llamada a
  `page.update()` desde un hilo de background debe ir envuelta en
  `backend.ui_call(page, fn)`. Usar `page.run_thread()` directamente provoca
  `IndexError` en `_compare_lists`. Para crear hilos, `backend.safe_thread(page, target)`.
  Ver [backend.md](backend.md) y [frontend.md](frontend.md).
- `TAG_PROFILES` y `LAB_ACRONYMS` solo se definen en
  `bifrost-transfer/src/meta_fields.py`; el formulario de copia y el Tag
  Manager consumen de ahí. No duplicar definiciones en `main.py`.

## Flujos de alto nivel

- Desktop: login (LDAP) → selección de servidor MinIO → obtención automática
  de credenciales STS temporales → vista de acción (mount o copy).
- Web (solo transfer, Open OnDemand): igual, con sesión persistente en
  `_WEB_SESSIONS` y reconexión de pestañas. Ver [frontend.md](frontend.md).

## Zona legacy

`old/` contiene scripts legacy (`backend-old.py`,
`minio-sts-credentials-request.py`): no usar ni modificar.
