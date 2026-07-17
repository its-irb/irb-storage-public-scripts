# Backend — `shared/bifrost_backend/backend.py`

~1791 LOC. Toda la lógica de negocio (no UI). Organizado por bloques delimitados con `# ====`. Importa `show_dialog, C_ERROR` de `bifrost_frontend.frontend` y `APP_INFO` de `config` (acoplamiento, ver `architecture.md`).

## Invariantes críticos

### `ui_call(page, fn)` — regla absoluta

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    if not page.session or not page.session.connection:
        return  # WebSocket cerrado (reconexión OOD) → no actualizar
    async def _wrapper(): fn()
    page.run_task(_wrapper)
```

Usa `page.run_task` (encola coroutine en el event loop asyncio de Flet) **en lugar de** `page.run_thread` (ThreadPoolExecutor en paralelo real). **Toda mutación de `control.controls` o `page.update()` desde un hilo de background debe ir por `ui_call`** para evitar carreras con el diff walker de Flet (`IndexError: list index out of range` en `object_patch.py:_compare_lists`). Ver `frontend.md` § thread-safety.

### `safe_thread(page, target, daemon=True)`

`threading.Thread` que envuelve `target` con try/except y muestra excepciones en diálogo vía `ui_call`. **Preferir frente a `threading.Thread` directo** para acciones de usuario. Si necesitas un `threading.Timer`, envuelve el callback en `lambda: ui_call(page, fn)`.

## Secciones (por orden en el fichero)

| Sección | Funciones clave |
|---|---|
| **Rclone resolution** | `get_rclone_executable()` — prioridad: (1) `FLET_ASSETS_DIR/bin/rclone[.exe]`, (2) `bifrost-<flavour>/src/assets/bin/` (dev), (3) PATH. Lanza `EnvironmentError` si no encuentra. `_ensure_executable()` aplica `chmod +x`. |
| **Constantes/versión** | `MINIO_SERVERS`, `DEFAULT_S3_REGION`, `REPO`. `__version__` importada de `version.py` (fallback `"1.0.1"`). |
| **Updates** | `_parse_version`, `check_update_version(force_update)`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary(file_name)` — autoupdate desde GitHub releases. |
| **Sistema** | `obtener_num_cpus()`, `obtener_ruta_rclone_conf()`, `traducir_ruta_a_remote()`, `open_file()`. |
| **FS userland checks** | `_check_winfsp_windows()`, `_check_fuse_macos()`, `_check_fuse_linux()`, `_macos_app_bundle_frameworks()`. |
| **WinFsp (Windows, mount)** | `WinFspMissingError(EnvironmentError)` — lanzada si falta WinFsp al montar. `install_winfsp_windows(page, on_progress)` descarga+instala la última release oficial desde `github.com/winfsp/winfsp` (UAC, MSI cacheado en `%TEMP%`). Solo `bifrost-mount`. |
| **Subprocess kwargs** | `_subprocess_kwargs()` — flags consistentes (`CREATE_NO_WINDOW` en Windows). No hardcodear. |
| **STS / MinIO** | `get_credentials(endpoint, username, password, durationseconds=86400)` → dict credenciales temporales. `get_usuario_from_session_token()`, `get_expiration_from_session_token()`. `configure_rclone(...)`, `get_rclone_session_token(profile_name)`. |
| **LDAP** | `get_ldap_groups(usuario)`, `validar_credenciales_ldap(credenciales_ldap) → (bool, str|None)`. |
| **SMB/CIFS** | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `configurar_perfiles_smb_si_faltan()`, `montar_shares_seleccionados()`, `construir_recursos_cifs_dict()`. |
| **Rclone profiles** | `obtener_perfiles_rclone_config(config_path)`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`. |
| **S3 tagging (boto3)** | `get_s3_client_from_profile(profile_name, endpoint)`, `list_prefix_contents(perfil, bucket, prefix) → (dirs, files)`, `rclone_list_files_only()`, `get_object_tags(s3_client, bucket, key) → dict`, `apply_tags_to_object(s3_client, bucket, key, tagset)`, `apply_tags_to_prefix(s3_client, bucket, prefix, tagset)`, `get_bucket_tags(s3_client, bucket) → dict` (vacío si no hay tags o error). |
| **Mount/unmount** | `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares(usuario)`, `desmontar_punto_montaje(mount_point, log_fn)`, `mount_rclone_S3_prefix_to_folder()`, `desmontar_todos_los_mounts_s3()`, `resolver_mount_point_destino()`. |
| **Copy/check** | `ejecutar_rclone_copy(origen, destino_perfil, destino_path, rclone_config_path, metadatos_dict, flags_adicionales, num_cores, log_fn, on_success, on_finish, expose_proceso)` — lanza `rclone copy` con `--checksum --check-first --copy-links`, excluye `.DS_Store`/`Thumbs.db`/`.snapshot`/`.Trash`/`.cache`, aplica tags vía `--header-upload x-amz-tagging:<tags>`. `nice(10)` en Unix. Si `expose_proceso` es dict, guarda `Popen` en `expose_proceso["proc"]`. `ejecutar_rclone_check()`, `construir_tag_string()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| **Rclone listing** | `rclone_lsd(perfil, path, timeout=15)`. |
| **Helpers Flet⇄threading** | `ui_call`, `safe_thread` (ver arriba). |

## Convenciones de código

- **Idioma**: docstrings, comentarios y nombres de funciones en español (`obtener_shares_accesibles`, `montar_share_rclone`). Mantener al añadir funciones nuevas. Excepción: mensajes del flujo WinFsp en inglés (alineados con la UI de `bifrost-mount`).
- **Subprocess**: siempre `_subprocess_kwargs()`. Nunca hardcodear flags.
- **rclone**: nunca asumir path; siempre `get_rclone_executable()`.
- **Logs copy/check**: pasar `log_fn`; no imprimir a stdout directamente.
- **Errores de usuario**: `show_dialog(page, ..., color=C_ERROR)` o lanzar y dejar que `safe_thread` capture.
