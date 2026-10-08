# Shared backend — `shared/bifrost_backend/backend.py`

Single module (~2083 lines) with all the non-UI logic, organised in blocks
delimited by `# ====`.

## Sections and key functions

| Section | Key functions |
|---|---|
| **Rclone resolution** | `get_rclone_executable()` — looks for rclone in (1) `FLET_ASSETS_DIR/bin/`, (2) `sys._MEIPASS`, (3) next to the executable, (4) PATH. In dev it uses `APP_INFO["flavour"]` to build the path to `bifrost-<flavour>/src/assets/bin/`. |
| **Version / autoupdate** | `_parse_version()`, `check_update_version()`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary()`. |
| **System** | `obtener_num_cpus()`, `get_rclone_paths()`, `obtener_ruta_rclone_conf()`, `traducir_ruta_a_remote()`, `detect_rclone_installed()`, `open_file()`, `launch_rclonebrowser()`. |
| **Userland FS checks** | `_check_winfsp_windows()`, `_check_fuse_macos()`, `_check_fuse_linux()`, `_macos_app_bundle_frameworks()`. |
| **STS / MinIO** | `get_credentials(endpoint, username, password, durationseconds)` → temporary credentials; `get_usuario_from_session_token()`, `get_expiration_from_session_token()`. |
| **Rclone profiles** | `configure_rclone()`, `get_rclone_session_token()`, `obtener_perfiles_rclone_config()`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`; SFTP: `crear_perfil_rclone_sftp()`, `generar_nombre_perfil_sftp()`, `validar_conexion_sftp()`, `limpiar_perfiles_rclone_con_prefijo()`. |
| **LDAP** | `get_ldap_groups()`, `validar_credenciales_ldap()`. |
| **SMB/CIFS** | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `configurar_perfiles_smb_si_faltan()`, `montar_shares_seleccionados()`, `construir_recursos_cifs_dict()`. |
| **Mount/unmount** | `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares()`, `desmontar_punto_montaje()`. |
| **Copy/check** | `ejecutar_rclone_copy()`, `ejecutar_rclone_check()`, `resolver_mount_point_destino()`, `construir_tag_string()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| **Rclone listing** | `verificar_ruta_rclone_accesible()`, `rclone_lsd()`, `rclone_lsf()`, `rclone_lsjson()`. |
| **boto3 / S3 tagging** | `get_s3_client_from_profile()`, `list_prefix_contents()`, `get_object_tags()`, `apply_tags_to_object()`, `apply_tags_to_prefix()`, `get_bucket_tags()` (returns `dict[str, str]`; empty if there are no tags or on error). |
| **Flet ⇄ threading helpers** | `ui_call(page, fn)`, `safe_thread(page, target)`. |

## `ui_call(page, fn)` — the most important rule

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    async def _wrapper(): fn()
    page.run_task(_wrapper)
```

It queues `fn` on the Flet event loop through
`asyncio.run_coroutine_threadsafe`, instead of running it in a
`ThreadPoolExecutor` (which is what `page.run_thread` does). **Every UI
mutation from a background thread must go through `ui_call`** to avoid races
with Flet's diff walker (`IndexError` in `_compare_lists`; details in
`docs/development/frontend.md`).

## `safe_thread(page, target, daemon=True)`

Creates a `threading.Thread` that wraps `target` in try/except and shows any
exception in a dialog through `ui_call`. Prefer it over a bare
`threading.Thread` for user actions.

## Backend coupling

```python
from bifrost_frontend.frontend import show_dialog, C_ERROR
from config import APP_INFO
```

Consequences:

- The backend cannot be imported unless `config.py` is on `sys.path` (each app
  has its own).
- The backend shows dialogs directly on unrecoverable errors; it is not a
  "pure" backend. Keep this pattern when adding new errors.

## Code conventions in the backend

- **Language**: docstrings, comments and function names are in Spanish
  (`obtener_shares_accesibles`, `montar_share_rclone`, …).
- **Errors**: raise exceptions or return `None`/`False`. For errors the user
  must see, use `show_dialog(page, ..., color=C_ERROR)` or raise and let
  `safe_thread` catch it.
- **Subprocess**: use `_subprocess_kwargs()` (consistent flags, for example
  `CREATE_NO_WINDOW` on Windows). Do not hardcode flags.
- **rclone**: never assume a path; always `get_rclone_executable()`.
- **Logs**: copy/check stream lines to the frontend through callbacks
  (`log_fn`). Do not print to stdout from copy/check functions.

## Autoupdate

`check_update_version()`, `should_check_for_updates()` and
`download_new_binary()` check GitHub releases and download the new binary. On
macOS, `get_update_file_suffix()` picks the file suffix from the machine
architecture (`platform.machine()`: arm64 → `-macos.dmg`, x86_64 →
`-macos-intel.dmg`; Intel stopgap until Nov-2026). See
[operations.md](operations.md) for the versioning flow.
