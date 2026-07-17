# Convenciones — BIFROST

## Idioma

- **Comentarios, docstrings, nombres de funciones (backend)**: español. Mantener al añadir código nuevo.
- **UI de `bifrost-transfer`**: mezcla inglés/español (histórico). Mensajes nuevos: alinear con el contexto circundante.
- **UI de `bifrost-mount`** (flujo WinFsp): inglés (alineado con esa UI).
- **Documentación interna** (`docs/`, `CLAUDE*.md`): español.
- **`README.md`**: inglés (puerta de entrada pública).

## Paleta y componentes (`shared/bifrost_frontend/frontend.py`)

```
C_BG="#0D1117"  C_SURFACE="#161B22"  C_SURFACE2="#21262D"  C_BORDER="#30363D"
C_PRIMARY="#58A6FF"  C_ACCENT="#3FB950"  C_WARNING="#D29922"  C_ERROR="#F85149"
C_TEXT="#E6EDF3"  C_TEXT_DIM="#8B949E"  C_OVERLAY="#1C2027"  FONT_MONO="Courier New"
```

Tema oscuro estilo GitHub. Componentes: `btn_primary`, `btn_secondary`, `card`, `section_title`, `field_label`, `styled_field`, `status_badge`, `show_dialog`, `build_header`, `build_update_content`. Las apps hacen `from bifrost_frontend.frontend import *`. **No hardcodear hex**; usar constantes.

## Diálogos

`show_dialog(page, title, message, color=C_TEXT, actions=None)`. Error: `color=C_ERROR`. Éxito: `color=C_ACCENT`. Aviso: `color=C_WARNING`. Cierra con `page.pop_dialog()`.

## Hilos y UI

- `backend.ui_call(page, fn)` para toda mutación de UI desde background (regla absoluta, ver `frontend.md`).
- `backend.safe_thread(page, target)` para hilos de usuario (captura excepciones → diálogo).
- `threading.Timer` que mute UI: `lambda: ui_call(page, fn)`.
- Nunca `log_list.controls.append(...)` directo desde hilo; pasar por `_dispatch_log` (transfer/web) o `log_fn` (mount).

## Logs persistentes

| App | Directorio |
|---|---|
| bifrost-mount | `~/bifrost-mount-logs/bifrost-mount-YYYY-MM-DD_HH-MM-SS.log` |
| bifrost-transfer | `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log` |

Transfer vuelca el buffer al final de cada copy/check (`_autosave_log`). Crítico en web: buffer cap 5000, replay 200.

## Variables de entorno

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_WEB` (modo web completo; señal producción OOD) |
| `BIFROST_NO_LDAP=1` | ambas | Salta validación LDAP en login (máquinas con MinIO pero sin LDAP, ej. IVIS). Usuario sigue introduciendo user+pass (necesarios para STS). Badge header: `DESKTOP (NO LDAP)`. En Windows: `setx BIFROST_NO_LDAP 1 /M` para todos los usuarios. |
| `FLET_ASSETS_DIR` | ambas | Lo setea Flet runtime; backend lo usa para localizar rclone empaquetado |
| `FLET_APP_STORAGE_TEMP` | ambas | Setado por Flet; debug de localización de binarios |
| `FLET_WEBSOCKET_HANDLER_ENDPOINT`, `WEBPATH`, `password` | transfer (OOD) | Configuración ASGI en cluster (ver final de `bifrost-transfer/src/main.py`) |

## Credenciales STS

- `STS_RENEWAL_THRESHOLD_DAYS = 3` — si quedan >3 días, se reutilizan.
- `STS_AUTO_RENEWAL_DAYS = 7` — si <3 días o no hay, se renuevan automáticamente por 7 días mostrando progreso.
- No hay botón manual de renovación en el flujo normal.
- `backend.get_credentials(endpoint, username, password, durationseconds)`.

## Servidores MinIO (`backend.MINIO_SERVERS`)

`minio-archive` (https), `irbminio` (http), `minio` (https, con `extra_rclone_config`: `no_check_bucket=true`, `region=eu-south-2`). `DEFAULT_S3_REGION="eu-south-2"`.

## Requisitos previos de red

**VPN Nexica (Forticlient)** activa para acceder a MinIO y LDAP (salvo `BIFROST_NO_LDAP=1`).

## Git

- `.husky/` con `commit-msg` (commitlint `@commitlint/config-conventional`) y `pre-commit`. Mensajes commit en formato conventional commits.
- `commitizen` (`npm run commit`) disponible.
- **No commitear**: `.venv/`, `dist/`, `build/`, `*.whl`, `uv.lock`, `src/assets/*` (salvo `.keep`, `icon.png`, `splash.png`), `frameworks/*` (salvo `.keep`). Ver `.gitignore`. (`src/version.py` sí se commitea con el placeholder `2.0.0.dev`; CI lo sobrescribe en build sin commitear.)
- `old/` contiene scripts legacy (no usar).

## Sin tests

No hay suite de tests. Validación manual con `flet run`.

## Reglas críticas (no romper)

1. Thread-safety: `ui_call` para mutar UI desde background (ver `frontend.md`).
2. `TAG_PROFILES`/`LAB_ACRONYMS`/`build_meta_fields`/`detect_profile`/`build_lab_filter_widget` se editan **solo** en `bifrost-transfer/src/meta_fields.py`.
3. `config.py` top-level en cada app (`from config import APP_INFO` en backend).
4. `get_rclone_executable()` para cualquier path de rclone; nunca asumir.
5. `_subprocess_kwargs()` para subprocess; no hardcodear flags Windows.
6. No tocar el bloque `TextIOWrapper` UTF-8 de `sys.stdout`/`sys.stderr` al inicio de `main.py`.
7. `backend.py` no es puro: importa `show_dialog, C_ERROR` del frontend y los usa en errores no recuperables.
