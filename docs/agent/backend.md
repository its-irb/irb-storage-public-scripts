# Backend compartido — `shared/bifrost_backend/backend.py`

Módulo único (~2083 líneas) con toda la lógica no-UI, organizado en bloques
delimitados por `# ====`.

## Secciones y funciones clave

| Sección | Funciones clave |
|---|---|
| **Rclone resolution** | `get_rclone_executable()` — busca rclone en (1) `FLET_ASSETS_DIR/bin/`, (2) `sys._MEIPASS`, (3) junto al ejecutable, (4) PATH. En dev usa `APP_INFO["flavour"]` para construir la ruta a `bifrost-<flavour>/src/assets/bin/`. |
| **Versión / autoupdate** | `_parse_version()`, `check_update_version()`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary()`. |
| **Sistema** | `obtener_num_cpus()`, `get_rclone_paths()`, `obtener_ruta_rclone_conf()`, `traducir_ruta_a_remote()`, `detect_rclone_installed()`, `open_file()`, `launch_rclonebrowser()`. |
| **Checks de FS userland** | `_check_winfsp_windows()`, `_check_fuse_macos()`, `_check_fuse_linux()`, `_macos_app_bundle_frameworks()`. |
| **STS / MinIO** | `get_credentials(endpoint, username, password, durationseconds)` → credenciales temporales; `get_usuario_from_session_token()`, `get_expiration_from_session_token()`. |
| **Perfiles rclone** | `configure_rclone()`, `get_rclone_session_token()`, `obtener_perfiles_rclone_config()`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`. |
| **LDAP** | `get_ldap_groups()`, `validar_credenciales_ldap()`. |
| **SMB/CIFS** | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `configurar_perfiles_smb_si_faltan()`, `montar_shares_seleccionados()`, `construir_recursos_cifs_dict()`. |
| **Mount/unmount** | `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares()`, `desmontar_punto_montaje()`. |
| **Copy/check** | `ejecutar_rclone_copy()`, `ejecutar_rclone_check()`, `resolver_mount_point_destino()`, `construir_tag_string()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| **Listing rclone** | `verificar_ruta_rclone_accesible()`, `rclone_lsd()`, `rclone_lsf()`, `rclone_lsjson()`. |
| **boto3 / S3 tagging** | `get_s3_client_from_profile()`, `list_prefix_contents()`, `get_object_tags()`, `apply_tags_to_object()`, `apply_tags_to_prefix()`, `get_bucket_tags()` (devuelve `dict[str, str]`; vacío si no hay tags o error). |
| **Helpers Flet ⇄ threading** | `ui_call(page, fn)`, `safe_thread(page, target)`. |

## `ui_call(page, fn)` — regla más importante

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    async def _wrapper(): fn()
    page.run_task(_wrapper)
```

Encola `fn` en el event loop de Flet vía `asyncio.run_coroutine_threadsafe`,
en lugar de ejecutarla en un `ThreadPoolExecutor` (lo que hace
`page.run_thread`). **Toda mutación de UI desde un hilo de background debe ir
por `ui_call`** para evitar carreras con el diff walker de Flet
(`IndexError` en `_compare_lists`; detalle en
[frontend.md](frontend.md) de la capa de desarrollo).

## `safe_thread(page, target, daemon=True)`

Crea un `threading.Thread` que envuelve `target` con try/except y muestra
cualquier excepción en un diálogo vía `ui_call`. Preferirlo frente a
`threading.Thread` directo para acciones de usuario.

## Acoplamiento del backend

```python
from bifrost_frontend.frontend import show_dialog, C_ERROR
from config import APP_INFO
```

Consecuencias:

- No se puede importar el backend sin que `config.py` esté en `sys.path`
  (cada app tiene el suyo).
- El backend muestra diálogos directamente en errores no recuperables; no es
  un backend "puro". Mantén este patrón al añadir errores nuevos.

## Convenciones de código en el backend

- **Idioma**: docstrings, comentarios y nombres de funciones en español
  (`obtener_shares_accesibles`, `montar_share_rclone`, …).
- **Errores**: lanzar excepciones o devolver `None`/`False`. Para errores que
  el usuario debe ver, `show_dialog(page, ..., color=C_ERROR)` o lanzar y
  dejar que `safe_thread` lo capture.
- **Subprocess**: usar `_subprocess_kwargs()` (flags consistentes, p. ej.
  `CREATE_NO_WINDOW` en Windows). No hardcodear flags.
- **rclone**: nunca asumir un path; siempre `get_rclone_executable()`.
- **Logs**: copy/check stream-ea líneas al frontend vía callbacks (`log_fn`).
  No imprimir a stdout desde funciones de copy/check.

## Autoupdate

`check_update_version()`, `should_check_for_updates()` y
`download_new_binary()` implementan la comprobación de releases de GitHub y la
descarga del binario nuevo. Ver [operations.md](operations.md) para el flujo
de versionado.
