# Backend compartido — `shared/`

## Layout y empaquetado

```text
shared/
  pyproject.toml          # Paquete bifrost-shared (hatchling)
  requirements.txt        # Deps comunes — dev y CI
  uv.lock
  bifrost_backend/
    __init__.py
    backend.py            # ~2083 líneas — toda la lógica
  bifrost_frontend/
    __init__.py
    frontend.py           # ~434 líneas — paleta + componentes Flet
  linux-assets-downloader.sh
  macos-assets-downloader-arm.sh
  macos-assets-downloader-intel.sh
  macos-rclone-downloader-arm.sh
  macos-rclone-downloader-intel.sh
  windows-assets-downloader.sh
```

`pyproject.toml` declara los dos paquetes:

```toml
[tool.hatch.build.targets.wheel]
packages = ["bifrost_backend", "bifrost_frontend"]
```

Se distribuye como un único wheel `bifrost-shared` que cada app referencia en
su `pyproject.toml` vía `bifrost-shared @ file:///__BUILDPATH__/shared`;
`__BUILDPATH__` lo reescribe el script de build (CI, `build-windows.ps1` o
`build-macos.sh`) a la ruta real del paquete compartido.

## `bifrost_backend.backend` — organización

El módulo agrupa la lógica no-UI en bloques delimitados por `# ====`:

| Sección | Funciones clave |
|---|---|
| **Rclone resolution** | `get_rclone_executable()` — resuelve el binario en (1) `FLET_ASSETS_DIR/bin/`, (2) `sys._MEIPASS`, (3) junto al ejecutable, (4) PATH. En dev usa `APP_INFO["flavour"]` para construir `bifrost-<flavour>/src/assets/bin/`. |
| **Constantes/versión** | `_parse_version()`, `check_update_version()`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary()` — autoupdate. |
| **Sistema** | `obtener_num_cpus()`, `get_rclone_paths()`, `obtener_ruta_rclone_conf()`, `traducir_ruta_a_remote()`, `detect_rclone_installed()`, `open_file()`, `launch_rclonebrowser()`. |
| **Checks de FS userland** | `_check_winfsp_windows()`, `_check_fuse_macos()`, `_check_fuse_linux()`, `_macos_app_bundle_frameworks()`. |
| **STS / MinIO** | `get_credentials(endpoint, username, password, durationseconds)` → dict de credenciales temporales; `get_usuario_from_session_token()`, `get_expiration_from_session_token()`. |
| **Perfiles rclone** | `configure_rclone()`, `get_rclone_session_token()`, `obtener_perfiles_rclone_config()`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`, `limpiar_perfiles_rclone_con_prefijo()`. |
| **LDAP** | `get_ldap_groups()`, `validar_credenciales_ldap()`. |
| **SMB/CIFS** | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `configurar_perfiles_smb_si_faltan()`, `montar_shares_seleccionados()`, `construir_recursos_cifs_dict()`. |
| **Mount/unmount** | `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares()`, `desmontar_punto_montaje()`. |
| **Copy/check** | `ejecutar_rclone_copy()`, `ejecutar_rclone_check()`, `resolver_mount_point_destino()`, `construir_tag_string()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| **Listing** | `verificar_ruta_rclone_accesible()`, `rclone_lsd()` (solo carpetas — S3 destino), `rclone_lsf()`, `rclone_lsjson()` (carpetas + ficheros — SFTP). |
| **boto3 / S3 tagging** | `get_s3_client_from_profile(profile_name, endpoint)`, `list_prefix_contents(perfil, bucket, prefix)`, `get_object_tags(s3_client, bucket, key)`, `apply_tags_to_object(...)`, `apply_tags_to_prefix(...)`, `get_bucket_tags(s3_client, bucket)` → `dict[str, str]`; vacío si no hay tags o hay error. |
| **Helpers Flet ⇄ threading** | `ui_call(page, fn)`, `safe_thread(page, target)`. |

## `ui_call(page, fn)` — la decisión de concurrencia central

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    async def _wrapper(): fn()
    page.run_task(_wrapper)
```

Encola `fn` en el event loop asyncio de Flet mediante
`asyncio.run_coroutine_threadsafe`, en lugar de ejecutarla en un
`ThreadPoolExecutor` (lo que hace `page.run_thread`). El diff walker de Flet
(`ObjectPatch.from_diff` → `_compare_lists`) recorre `control.controls` en el
thread del event loop sin lock; si un worker del pool muta esa lista en
paralelo, el walker encuentra una lista cambiada a mitad de recorrido y
lanza `IndexError`. Asyncio es cooperativo: como `_compare_lists` no tiene
ningún `await`, la coroutine encolada no puede interrumpirla. El análisis
completo del bug está en [frontend.md](frontend.md).

## `safe_thread(page, target, daemon=True)`

Envuelve `target` en un `threading.Thread` con try/except; cualquier
excepción se muestra en un diálogo vía `ui_call`. Es la forma estándar de
lanzar acciones de usuario en background.

## Acoplamiento backend → frontend

```python
from bifrost_frontend.frontend import show_dialog, C_ERROR
from config import APP_INFO
```

Consecuencias de diseño:

- No se puede importar el backend sin `config.py` en `sys.path` (cada app
  tiene el suyo, importable como módulo top-level).
- El backend muestra diálogos directamente en errores no recuperables; no es
  un backend puro/desacoplado. Es un compromiso asumido: separarlo exigiría
  rediseñar la propagación de errores en toda la pila.

## Instalación de `shared/` en desarrollo

Las apps referencian el wheel vía `__BUILDPATH__`; en desarrollo:

```bash
cd shared
python -m build .         # genera dist/bifrost_shared-*.whl
pip install dist/bifrost_shared-*.whl
```

Alternativas:

Instalar solo las dependencias (sin el paquete `bifrost-shared`):

```bash
pip install -r shared/requirements.txt
```

Con `uv` en la app, el paquete se instala desde la ruta local; tras
modificar `shared/`:

```bash
uv sync --reinstall-package bifrost-shared
```

`main.py` contiene un bloque comentado que añade `shared/` a `sys.path`
para desarrollar sin instalar el wheel.

## Scripts de descarga de assets

| Script | Para qué |
|---|---|
| `macos-assets-downloader-arm.sh` | `rclone` + `fuse-t.framework` (`bifrost-mount` en macOS) — arquitectura auto-detectada (job ARM de la CI y dev local) |
| `macos-assets-downloader-intel.sh` | lo anterior con `rclone` `osx-amd64` hardcodeado (job Intel de la CI, stopgap hasta nov-2026) |
| `macos-rclone-downloader-arm.sh` | solo `rclone` (`bifrost-transfer` en macOS) — arquitectura auto-detectada |
| `macos-rclone-downloader-intel.sh` | solo `rclone` `osx-amd64` hardcodeado (job Intel de la CI) |
| `windows-assets-downloader.sh` | `rclone.exe` |
| `linux-assets-downloader.sh` | `rclone` (clúster Linux) |

CI los invoca antes de cada `flet build` (los runners salen limpios). En dev
local hay que ejecutarlos **al menos una vez**: los binarios se descargan en
`bifrost-*/src/assets/bin/` (y `frameworks/` en mount/macOS) y quedan en
disco como ficheros no versionados (gitignores; solo se versionan los
`.keep`).

## Convenciones de código

- **Idioma**: docstrings, comentarios y nombres de funciones en español.
- **Errores**: lanzar excepciones o devolver `None`/`False`. Para errores
  visibles al usuario, `show_dialog(page, ..., color=C_ERROR)` o lanzar y
  dejar que `safe_thread` capture.
- **Subprocess**: usar `_subprocess_kwargs()` (flags consistentes, p. ej.
  `CREATE_NO_WINDOW` en Windows). No hardcodear.
- **rclone**: nunca asumir un path; siempre `get_rclone_executable()`.
- **Logs**: copy/check stream-ea líneas al frontend vía callbacks (`log_fn`);
  no imprimir a stdout desde esas funciones.

## Autoupdate

`check_update_version()` consulta las releases de GitHub;
`should_check_for_updates()` decide si toca comprobar;
`download_new_binary()` descarga el binario de la release nueva. En macOS el
sufijo del archivo lo elige `get_update_file_suffix()` según la arquitectura
(`platform.machine()`: arm64 → `-macos.dmg`, x86_64 → `-macos-intel.dmg`,
stopgap Intel hasta nov-2026). El flujo de versionado
(`1.0.<run_number>`) y la publicación están en
[build-and-ci.md](build-and-ci.md).
