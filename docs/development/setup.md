# Preparación del entorno de desarrollo — BIFROST

## Requisitos previos

- **Python ≥3.11** (3.12 en CI). Recomendado 3.12.
- **VPN Nexica (Forticlient)** activa para alcanzar MinIO y LDAP. Sin VPN, las apps no pueden autenticar ni acceder a buckets (salvo `BIFROST_NO_LDAP=1` para máquinas con MinIO pero sin LDAP, ej. IVIS).
- **rclone** y **fuse-t**/**WinFsp**: no hace falta instalarlos manualmente. Se descargan en build y se empaquetan. En dev, los scripts `shared/*-downloader.sh` los colocan en `<app>/src/assets/bin/`. Si no están, `backend.get_rclone_executable()` busca en PATH como último recurso.
- **uv** (recomendado) para gestionar entornos sincronizados desde `pyproject.toml`. Alternativa: `pip` + `venv`.

## Setup con uv (recomendado)

Desde la raíz del repo, para una app concreta (`bifrost-mount` o `bifrost-transfer`):

```bash
# 1. Sincroniza el entorno leyendo <app>/pyproject.toml (crea <app>/.venv)
uv sync --project bifrost-transfer

# 2. Activar
source bifrost-transfer/.venv/bin/activate          # macOS/Linux
# .\bifrost-transfer\.venv\Scripts\Activate.ps1     # Windows PowerShell

# 3. (Opcional) descargar rclone para dev local
cd bifrost-transfer/src && bash ../../shared/macos-rclone-downloader.sh   # macOS
# bash ../../shared/linux-assets-downloader.sh                             # Linux
# bash ../../shared/windows-assets-downloader.sh                           # Windows (copiarlo antes a src/)

# 4. Ejecutar
flet run
```

`uv sync` resuelve `bifrost-shared @ file:///__BUILDPATH__/shared`: como `__BUILDPATH__` no existe, **debes** instalar el wheel a mano la primera vez o usar la alternativa editable (abajo).

## Setup con pip + venv + wheel instalado

```bash
python -m venv .venv
source .venv/bin/activate          # macOS/Linux
# .\.venv\Scripts\Activate.ps1     # Windows
python -m pip install --upgrade pip

# Instalar el paquete compartido en modo editable desde shared/
python -m pip install -e shared/

# Instalar el resto de deps de la app
python -m pip install flet==0.84.0 boto3==1.42.12 ldap3==2.9.1 cryptography==46.0.7 \
    pyjwt python-dateutil requests urllib3 idna python-dotenv

flet run
```

## Alternativa editable sin instalar el wheel

Cada `main.py` tiene un bloque comentado al inicio:

```python
# _shared = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
# if os.path.isdir(_shared):
#     sys.path.insert(0, os.path.abspath(_shared))
```

Descomentar para que `bifrost_backend` y `bifrost_frontend` se resuelvan desde `shared/` sin instalar el wheel. Útil para iterar rápido en el backend sin reinstalar. **No commitear el bloque descomentado** (rompe el build empaquetado).

## Ejecutar

Desde la carpeta de la app:

```bash
flet run                              # desktop normal
flet run --customuser                 # login con usuario distinto al del sistema
flet run --update                     # forzar autoupdate al arrancar
```

Solo `bifrost-transfer` (modo web):

```bash
flet run --web                              # modo web para dev local
BIFROST_CLUSTER=1 python src/main.py --web  # simular producción OOD (con flujo CIFS)
```

## Verificar que rclone es localizable

`backend.get_rclone_executable()` sigue esta prioridad:

1. `FLET_ASSETS_DIR/bin/rclone[.exe]` (apps empaquetadas).
2. `bifrost-<flavour>/src/assets/bin/rclone[.exe]` (dev, relativo a `shared/`).
3. `shutil.which("rclone")` (PATH del sistema, modo cluster).

Si los tres fallan lanza `EnvironmentError`. Para debuggear: setear `FLET_APP_STORAGE_TEMP` y observar logs; o descomentar temporalmente prints en `get_rclone_executable`.

## Variables de entorno útiles en dev

| Variable | Efecto |
|---|---|
| `BIFROST_NO_LDAP=1` | Salta validación LDAP (máquinas con MinIO pero sin LDAP). El usuario sigue introduciendo user+pass para STS. |
| `BIFROST_CLUSTER=1` | (transfer) activa `IS_WEB` y el flujo CIFS del cluster. |
| `FLET_ASSETS_DIR` | Lo setea Flet runtime; backend lo usa para rclone empaquetado. |

## Logs de sesión

Cada app escribe un log con timestamp en `~/`:

| App | Ruta |
|---|---|
| bifrost-mount | `~/bifrost-mount-logs/bifrost-mount-YYYY-MM-DD_HH-MM-SS.log` |
| bifrost-transfer | `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log` |

Útil para diagnosticar copias/montajes fallidos. El log de transfer se vuelca automáticamente al terminar cada copy/check (`_autosave_log`).

## Depuración

- **Threading/UI**: los crashes por `IndexError: list index out of range` indican que se mutó UI sin `ui_call` (ver `thread-safety.md`).
- **Web**: para reproducir bugs de OOD, usar `BIFROST_CLUSTER=1 python src/main.py --web` y abrir/cerrar pestañas durante una copia.
- **Subprocess**: `backend._subprocess_kwargs()` añade `CREATE_NO_WINDOW` en Windows; si un `subprocess` nuevo no lo usa, aparece ventana de consola.
- **rclone config**: `backend.obtener_ruta_rclone_conf()` devuelve la ruta al `rclone.conf` usado (dependiente de plataforma).

## Tooling de commits

El repo usa conventional commits vía husky + commitlint:

```bash
npm install              # instala husky, commitlint, commitizen
npm run commit           # asistente interactivo (commitizen)
```

Los hooks `.husky/commit-msg` validan el formato y `.husky/pre-commit` corre comprobaciones. Mensajes fuera de `@commitlint/config-conventional` se rechazan.

## Qué NO commitear

`.gitignore` excluye: `.venv/`, `dist/`, `build/`, `*/src/build/`, `*.whl`, `uv.lock`, `src/assets/*` (salvo `.keep`, `icon.png`, `splash.png`), `frameworks/*` (salvo `.keep`). Nota: `src/version.py` **sí** se commitea (contiene el placeholder `2.0.0.dev`); CI lo sobrescribe en build sin commitear el cambio. Ver `.gitignore` para el detalle.
