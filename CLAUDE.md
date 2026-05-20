# CLAUDE.md — BIFROST

Repositorio de **herramientas de acceso al almacenamiento MinIO S3 — IRB Barcelona**. Contiene dos aplicaciones de escritorio (Flet/Python) que comparten backend y parte del frontend.

> Lee también `CLAUDE_BACKEND.md` (lógica compartida en `shared/`) y `CLAUDE_FRONTEND.md` (apps Flet y modo web). El `README.md` raíz mantiene la documentación canónica para usuarios; este fichero está pensado para Claude.

---

## Aplicaciones

| App | Carpeta | Función |
|---|---|---|
| **bifrost-transfer** | `bifrost-transfer/` | Copia datos desde carpetas de red (SMB/CIFS) o local a buckets MinIO S3, con verificación de integridad y etiquetado de metadatos. Incluye **Tag Manager** para navegar buckets/carpetas/ficheros S3 y aplicar tagsets masivamente sin re-subida. Soporta **modo desktop y modo web** (Open OnDemand). |
| **bifrost-mount** | `bifrost-mount/` | Monta carpetas MinIO S3 como unidad local (Windows/macOS/Linux). Solo modo desktop. |

Ambas son apps Flet con punto de entrada `src/main.py` y configuración `pyproject.toml` por app.

---

## Estructura del repositorio

```
bifrost-mount/            # App de montado (desktop)
  src/
    main.py               # GUI Flet — punto de entrada
    config.py             # APP_INFO = {"flavour": "mount", ...}
    version.py            # __version__ (lo escribe CI)
    assets/bin/           # rclone bundled
    frameworks/           # fuse_t.framework (macOS)
  pyproject.toml          # Config flet build + deps congeladas
  installer.iss           # Inno Setup (instalador Windows)
  build-macos.sh

bifrost-transfer/         # App de transferencia (desktop + web)
  src/
    main.py               # GUI Flet
    config.py             # APP_INFO = {"flavour": "transfer", ...}
    version.py
    assets/bin/
    storage/              # datos temporales de transferencia
  pyproject.toml
  installer.iss
  build-macos.sh

shared/                   # Paquete bifrost-shared (wheel local)
  bifrost_backend/
    backend.py            # Lógica de negocio (LDAP, rclone, SMB, S3, STS, ui_call/safe_thread)
    __init__.py
  bifrost_frontend/
    frontend.py           # Paleta de colores + componentes Flet reutilizables
    __init__.py
  pyproject.toml          # Define paquete "bifrost-shared"
  requirements.txt        # Compartido por ambas apps en dev
  *-assets-downloader.sh  # Scripts para descargar rclone/fuse-t en CI

old/                      # Scripts legacy (no usar)
build-local.ps1           # Build local de Windows (genera wheel + flet build)
.github/workflows/main.yml  # CI: build macOS/Windows + release
README.md                 # Doc canónica (en español)
```

---

## Código compartido vs específico

**Compartido (`shared/`)** — se empaqueta como wheel `bifrost-shared`:
- `bifrost_backend.backend` — *todo* el negocio: rclone exec resolution, STS credentials, LDAP auth, SMB/CIFS shares, perfiles rclone, copy/check, `ui_call()`, `safe_thread()`. Incluye también 5 funciones boto3 para tagging S3: `get_s3_client_from_profile`, `list_prefix_contents`, `get_object_tags`, `apply_tags_to_object`, `apply_tags_to_prefix`.
- `bifrost_frontend.frontend` — paleta de colores (`C_BG`, `C_PRIMARY`, …), botones (`btn_primary`, `btn_secondary`), helpers comunes. Cada app hace `from bifrost_frontend.frontend import *`.

**Específico por app**:
- `src/main.py` — flujo de vistas Flet (login → minio → credentials → mount/copy). Es donde está toda la UI específica. En `bifrost-transfer` incluye además `TAG_PROFILES` (constante que centraliza los campos de metadatos para el formulario de copia y el Tag Manager) y `_build_tag_manager_content` (vista Tag Manager).
- `src/config.py` — solo `APP_INFO = {"flavour": "mount"|"transfer", "name": ..., "description": ...}`. El backend lee `APP_INFO["flavour"]` para resolver rutas de assets en dev.
- `src/version.py` — escrito por CI en cada build (`__version__ = "1.0.<run_number>"`).
- `installer.iss`, `build-macos.sh`, `pyproject.toml` (con su lista de deps congelada por app).

El acoplamiento app↔shared se hace vía `from bifrost_backend import backend` y `from config import APP_INFO`. El `pyproject.toml` de cada app referencia `bifrost-shared @ file:///__BUILDPATH__/shared`, que el script de build (CI o `build-local.ps1`) sustituye por la ruta real del wheel.

---

## Cómo ejecutar (desarrollo)

Desde la carpeta de la app (`bifrost-mount/` o `bifrost-transfer/`):

```bash
# Primera vez:
python -m venv .venv
source .venv/bin/activate          # macOS/Linux
# .\.venv\Scripts\Activate.ps1     # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install -r ../shared/requirements.txt

# Cada ejecución:
flet run
```

Flags útiles:

```bash
flet run --customuser     # Login con usuario distinto al del sistema
flet run --update         # Forzar autoupdate
python src/main.py --web  # (solo transfer) modo web
BIFROST_DEV=1 flet run    # (solo transfer) simular modo web en local
BIFROST_CLUSTER=1 BIFROST_DEV=1 flet run  # forzar flujo CIFS de cluster
BIFROST_LINUX=1 python src/main.py        # (mount) simular Linux cluster
```

Requisito previo: estar conectado a la VPN de Nexica (Forticlient). Las dependencias binarias (`rclone`, `fuse-t`) se descargan/empaquetan automáticamente — no hace falta instalarlas.

---

## Build / empaquetar

Cada app se empaqueta con `flet build`. El proceso requiere generar primero el wheel `bifrost-shared` y sustituir `__BUILDPATH__` en `pyproject.toml`.

**Local (Windows)** — `build-local.ps1` automatiza el flujo:
```powershell
.\build-local.ps1 -app bifrost-mount       # o bifrost-transfer
```

**CI** — `.github/workflows/main.yml` builda macOS (`flet build macos`) y Windows (`flet build windows` + Inno Setup) para ambas apps en push a `main`, `release`, `develop`, `feature/**`. La versión se inyecta como `1.0.<run_number>` en `version.py` y `pyproject.toml`.

**macOS local** — `bifrost-mount/build-macos.sh` o `bifrost-transfer/build-macos.sh`.

**Instalador Windows** — `installer.iss` (Inno Setup) empaqueta toda la carpeta generada por flet en un único `.exe`.

Si se añaden/actualizan dependencias Python, regenerar:
```bash
python -m pip freeze > src/pip-requirements.txt
uv add -r pip-requirements.txt
```

---

## Tests

**No hay suite de tests automatizada.** Los cambios se validan ejecutando las apps manualmente (`flet run`).

---

## Autoupdate

Cuando hay una release nueva en GitHub, la app pregunta al usuario si quiere actualizarse y descarga el binario nuevo del repo. Ver `backend.check_update_version()`, `should_check_for_updates()`, `download_new_binary()` en `shared/bifrost_backend/backend.py`.

---

## Variables de entorno

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_DEV=1` | transfer | Activa `IS_WEB`/`DEV_WEB` para simular modo web en local |
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_LINUX_CLUSTER` (incluye flujo CIFS/shares) |
| `BIFROST_LINUX=1` | mount | Activa flujo de Linux cluster en `bifrost-mount` |
| `FLET_ASSETS_DIR` | ambas | Lo setea Flet en runtime; el backend lo usa para localizar el `rclone` empaquetado |
| `FLET_APP_STORAGE_TEMP` | ambas | Setado por Flet; usado para debug de localización de binarios |

---

## Convenciones y gotchas críticas

1. **Thread-safety en Flet**: toda mutación de `control.controls` o llamada a `page.update()` desde un hilo de background **debe** envolverse en `backend.ui_call(page, fn)`. Usar `page.run_thread()` directamente causa `IndexError` en `_compare_lists` (ver detalle en `CLAUDE_FRONTEND.md`). Para crear hilos, usar `backend.safe_thread(page, target)` — captura excepciones y las muestra en diálogo.
2. **Codificación de consola en Windows**: `main.py` reenvuelve `sys.stdout`/`sys.stderr` en UTF-8 al arrancar (el bloque `TextIOWrapper`). No tocar.
3. **Idioma**: comentarios, docstrings y mensajes de UI están en **español**. El README es canónico y está en español.
4. **El backend importa del frontend**: `backend.py` importa `show_dialog` y `C_ERROR` de `bifrost_frontend.frontend`. Hay acoplamiento (no es un backend "puro").
5. **`config.py` debe ser importable como módulo top-level** en cada app — el backend hace `from config import APP_INFO`. Por eso cada app tiene su propio `config.py` aunque solo contenga `APP_INFO`.
6. **Credenciales STS**: si quedan >3 días se reutilizan; <3 días se renuevan automáticamente por 7 días. Constantes `STS_RENEWAL_THRESHOLD_DAYS` / `STS_AUTO_RENEWAL_DAYS` en `main.py`.
7. **No commitear `.venv/`, `dist/`, `build/`, `src/version.py` generado**. Ver `.gitignore`.
8. **`TAG_PROFILES` es la fuente canónica de campos de metadatos en `bifrost-transfer`**: tanto el formulario de copia (`meta_labels`) como el editor del Tag Manager leen de `TAG_PROFILES` en `main.py`. Si hay que añadir o renombrar un campo, cambiarlo solo aquí.
9. **Auto-instalación de WinFsp (solo `bifrost-mount`, Windows)**: si falta WinFsp al montar, el backend levanta `WinFspMissingError` (subclase de `EnvironmentError`) y la UI ofrece descargar e instalar la última release oficial desde `github.com/winfsp/winfsp` vía `backend.install_winfsp_windows()`. Requiere UAC; el MSI se cachea en `%TEMP%`. Los mensajes de este flujo están en **inglés** (excepción al punto 3) para alinearse con el resto de la UI de `bifrost-mount`. `bifrost-transfer` no tiene este flujo.

---

## Wiki del proyecto

Hay una base de conocimiento incremental en `docs/wiki/` que acumula **decisiones técnicas, estado de infra (MinIO/Nexica/IRB) y gotchas de usuarios** entre sesiones. Antes de responder preguntas sobre el "por qué" de patrones del repo o sobre infra externa, consulta `docs/wiki/index.md`.

El protocolo completo (ingest, query, lint, formato de páginas, reglas de seguridad, **convención de cierre de tarea**) está en `docs/wiki/CLAUDE_WIKI.md` — léelo antes de crear/modificar páginas. Las fuentes brutas viven en `docs/wiki/raw/` y están gitignored; el resto de la wiki sí se commitea.
