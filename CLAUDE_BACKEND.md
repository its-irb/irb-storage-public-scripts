# CLAUDE_BACKEND.md — Backend compartido (`shared/`)

Documenta el paquete `bifrost-shared`, que contiene **toda la lógica de negocio** y los helpers Flet compartidos por `bifrost-mount` y `bifrost-transfer`.

---

## Layout

```
shared/
  pyproject.toml          # Define el paquete bifrost-shared (hatchling)
  requirements.txt        # Deps en común — usado en dev y en CI
  uv.lock
  bifrost_backend/
    __init__.py
    backend.py            # ~1700 LOC — toda la lógica
  bifrost_frontend/
    __init__.py
    frontend.py           # ~370 LOC — paleta + componentes Flet
  linux-assets-downloader.sh
  macos-assets-downloader.sh
  macos-rclone-downloader.sh
  windows-assets-downloader.sh
```

`pyproject.toml` declara los dos paquetes:
```toml
[tool.hatch.build.targets.wheel]
packages = ["bifrost_backend", "bifrost_frontend"]
```

Se distribuye como un único wheel `bifrost-shared` que cada app referencia en su `pyproject.toml` vía `bifrost-shared @ file:///__BUILDPATH__/shared`. `__BUILDPATH__` lo reescribe el script de build (CI o `build-local.ps1`) a la ruta real del wheel generado.

---

## `bifrost_backend.backend` — secciones

El módulo está organizado por bloques delimitados con `# ====` y agrupa toda la lógica que no es UI:

| Sección | Funciones clave |
|---|---|
| **Rclone resolution** | `get_rclone_executable()` — busca rclone en (1) `FLET_ASSETS_DIR/bin/`, (2) `sys._MEIPASS`, (3) junto al ejecutable, (4) PATH. En dev usa `APP_INFO["flavour"]` para construir la ruta a `bifrost-<flavour>/src/assets/bin/`. |
| **Constantes/versión** | `_parse_version()`, `check_update_version()`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary()` — lógica de autoupdate. |
| **Sistema** | `obtener_num_cpus()`, `get_rclone_paths()`, `obtener_ruta_rclone_conf()`, `traducir_ruta_a_remote()`, `detect_rclone_installed()`, `open_file()`, `launch_rclonebrowser()`. |
| **Checks de FS userland** | `_check_winfsp_windows()`, `_check_fuse_macos()`, `_check_fuse_linux()`, `_macos_app_bundle_frameworks()`. |
| **STS / MinIO** | `get_credentials(endpoint, username, password, durationseconds)` → dict de credenciales temporales. `get_usuario_from_session_token()`, `get_expiration_from_session_token()`. |
| **Rclone profiles** | `configure_rclone()`, `get_rclone_session_token()`, `obtener_perfiles_rclone_config()`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`. |
| **LDAP** | `get_ldap_groups()`, `validar_credenciales_ldap()`. |
| **SMB/CIFS** | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `configurar_perfiles_smb_si_faltan()`, `montar_shares_seleccionados()`, `construir_recursos_cifs_dict()`. |
| **Mount/unmount** | `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares()`, `desmontar_punto_montaje()`. |
| **Copy/check** | `ejecutar_rclone_copy()`, `ejecutar_rclone_check()`, `resolver_mount_point_destino()`, `construir_tag_string()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| **Rclone listing** | `verificar_ruta_rclone_accesible()`, `rclone_lsd()`, `rclone_lsf()`. |
| **boto3 / S3 tagging** | `get_s3_client_from_profile(profile_name, endpoint)`, `list_prefix_contents(perfil, bucket, prefix)`, `get_object_tags(s3_client, bucket, key)`, `apply_tags_to_object(s3_client, bucket, key, tagset)`, `apply_tags_to_prefix(s3_client, bucket, prefix, tagset)`, `get_bucket_tags(s3_client, bucket)` — devuelve los tags del bucket como `dict[str, str]`; vacío si no hay tags o hay error. |
| **Helpers Flet ⇄ threading** | `ui_call(page, fn)`, `safe_thread(page, target)`. |

### `ui_call(page, fn)` — la regla más importante

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    async def _wrapper(): fn()
    page.run_task(_wrapper)
```

Usa `asyncio.run_coroutine_threadsafe` para encolar `fn` en el event loop de Flet en lugar de ejecutarlo en un `ThreadPoolExecutor` (que es lo que hace `page.run_thread`). **Toda mutación de UI desde un hilo de background debe ir por `ui_call`** para evitar carreras con el diff walker de Flet (ver `CLAUDE_FRONTEND.md` § "El bug IndexError").

### `safe_thread(page, target, daemon=True)`

Crea un `threading.Thread` que envuelve `target` con try/except y muestra cualquier excepción en un diálogo vía `ui_call`. Preferir frente a `threading.Thread` directo para acciones de usuario.

### Acoplamiento backend → frontend

`backend.py` importa:
```python
from bifrost_frontend.frontend import show_dialog, C_ERROR
from config import APP_INFO
```

Esto significa que:
- No se puede importar el backend sin que `config.py` esté en `sys.path` (cada app tiene el suyo).
- El backend muestra diálogos directamente cuando hay errores no recuperables. No es un backend "puro" / desacoplado.

---

## `bifrost_frontend.frontend` — paleta y componentes

Tema oscuro estilo GitHub. Constantes exportadas:

```
C_BG="#0D1117"  C_SURFACE="#161B22"  C_SURFACE2="#21262D"  C_BORDER="#30363D"
C_PRIMARY="#58A6FF"  C_ACCENT="#3FB950"  C_WARNING="#D29922"  C_ERROR="#F85149"
C_TEXT="#E6EDF3"  C_TEXT_DIM="#8B949E"  C_OVERLAY="#1C2027"
FONT_MONO="Courier New"
```

Componentes reutilizables:
- `btn_primary(text, on_click, width, disabled)` — botón principal azul
- `btn_secondary(text, on_click, width)` — outlined
- `show_dialog(page, title, message, ...)` — diálogo modal de error/info
- (entre otros) — ver `shared/bifrost_frontend/frontend.py`

Las apps hacen `from bifrost_frontend.frontend import *` en `main.py` para usar tanto los colores como los componentes sin prefijo.

---

## Cómo instalar shared/ en desarrollo

Las apps usan `bifrost-shared @ file:///__BUILDPATH__/shared` en su `pyproject.toml`, pero en desarrollo lo más práctico es instalar el wheel localmente:

```bash
cd shared
python -m build .         # genera dist/bifrost_shared-*.whl
pip install dist/bifrost_shared-*.whl
```

Alternativa: `pip install -r shared/requirements.txt` instala todas las deps pero **no** el paquete `bifrost-shared` en sí. Si arranca `flet run` desde la app sin tener `bifrost_backend`/`bifrost_frontend` instalados, hay un bloque comentado en `main.py` que añade `shared/` a `sys.path`:

```python
# _shared = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
# if os.path.isdir(_shared):
#     sys.path.insert(0, os.path.abspath(_shared))
```

Descomentarlo si se quiere desarrollar sin instalar el wheel.

---

## Scripts de descarga de assets

| Script | Para qué |
|---|---|
| `macos-assets-downloader.sh` | Descarga `rclone` + `fuse-t.framework` (usado por `bifrost-mount` en macOS) |
| `macos-rclone-downloader.sh` | Descarga solo `rclone` (usado por `bifrost-transfer` en macOS) |
| `windows-assets-downloader.sh` | Descarga `rclone.exe` para Windows |
| `linux-assets-downloader.sh` | Descarga `rclone` para Linux |

CI los invoca antes de `flet build`. En dev local generalmente no hacen falta porque el repo ya trae los binarios bajo `bifrost-*/src/assets/bin/`.

---

## Convenciones de código en el backend

- **Idioma**: docstrings y comentarios en español; nombres de funciones también (`obtener_shares_accesibles`, `montar_share_rclone`, …). Mantener consistencia al añadir funciones nuevas.
- **Errores**: lanzar excepciones o devolver `None`/`False`. Para errores que el usuario debe ver, usar `show_dialog(page, ..., color=C_ERROR)` o lanzar y dejar que `safe_thread` lo capture.
- **Subprocess**: usar `_subprocess_kwargs()` para obtener flags consistentes (CREATE_NO_WINDOW en Windows, etc.). No hardcodear.
- **rclone**: nunca asumir un path; siempre `get_rclone_executable()`.
- **Logs**: la copia/check stream-ea líneas al frontend vía callbacks. No imprimir directamente a stdout desde funciones de copy/check — pasar `log_fn`.
