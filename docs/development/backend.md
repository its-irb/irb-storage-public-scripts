# Backend compartido — `shared/`

## Layout y empaquetado

```text
shared/
  pyproject.toml          # Paquete bifrost-shared (hatchling)
  bifrost_backend/
    __init__.py           # Desactiva el aviso InsecureRequestWarning de urllib3 (verify=False hacia MinIO)
    backend.py            # Fachada: reexporta la API pública (backend.X)
    common/               # auth, constants, rclone, ui_helpers, updates
    mount/                # preflight (WinFsp/FUSE), s3_mount
    transfer/             # copy_check, ldap_groups, rclone_ops, s3_tags, sftp, smb
  bifrost_frontend/
    __init__.py
    frontend.py           # Fachada: reexporta theme, components y views
    theme.py              # Paleta C_*, fuentes, apply_theme
    components.py         # Botones, campos, show_dialog, show_confirm, build_header
    views/                # update, login, minio, credentials (vistas comunes)
  linux-assets-downloader.sh
  macos-assets-downloader.sh
  macos-rclone-downloader.sh
  windows-assets-downloader.sh
```

`pyproject.toml` declara los dos paquetes (los subpaquetes se incluyen solos):

```toml
[tool.hatch.build.targets.wheel]
packages = ["bifrost_backend", "bifrost_frontend"]
```

Se distribuye como un único wheel `bifrost-shared` que cada app referencia en
su `pyproject.toml` vía `bifrost-shared @ file:///__BUILDPATH__/shared`;
`__BUILDPATH__` lo reescribe el script de build (CI, `build-windows.ps1` o
`build-macos.sh`) a la ruta real del paquete compartido.

## `bifrost_backend` — organización

El backend está dividido en módulos por área. `backend.py` es una fachada de
compatibilidad que reexporta la API pública, de modo que las apps siguen
llamando a `backend.X` (`from bifrost_backend import backend`).

| Módulo | Funciones clave |
|---|---|
| `common/auth.py` — STS, perfil rclone, LDAP | `get_credentials(endpoint, username, password, durationseconds)` → dict de credenciales temporales (timeout HTTP de 30 s); `configure_rclone()`; `get_session_info(perfil)` → `SessionInfo`; `validar_credenciales_ldap()`. |
| `common/constants.py` | `MINIO_SERVERS`, `DEFAULT_S3_REGION`, `REPO`, `__version__`, `EMOJI_FONT_FILENAME`, `LDAP_SERVER_URL`, `LDAP_BASE_DN`, `STS_RENEWAL_THRESHOLD_DAYS` (3), `STS_AUTO_RENEWAL_DAYS` (7), `NO_LDAP` (`BIFROST_NO_LDAP=1`). |
| `common/rclone.py` — resolución de rclone | `get_rclone_executable()` — resuelve el binario en (1) `FLET_ASSETS_DIR/bin/` (apps empaquetadas), (2) `bifrost-<flavour>/src/assets/bin/` del repo (desarrollo; se construye con `APP_INFO["flavour"]`), (3) PATH (modo web/clúster); si no lo encuentra lanza `EnvironmentError`. `obtener_ruta_rclone_conf()` (ejecuta `rclone config file`; el resultado se cachea con `lru_cache`), `rclone_lsd()` (solo carpetas — S3 destino), `_subprocess_kwargs()`. |
| `common/updates.py` — autoupdate | `_parse_version()`, `check_update_version()`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary()`, `get_emoji_font_asset_path()`. |
| `common/ui_helpers.py` — Flet ⇄ threading | `ui_call(page, fn)`, `safe_thread(page, target)`. |
| `common/logs.py` — log técnico, informes y exportación | `setup_logging()`, `log_dir()`, `report_path()`, `write_report()`, `rclone_log_path()`, `open_in_file_browser()`, `export_logs_zip(sessions=EXPORTED_SESSIONS)` → ruta del zip, en `~/Downloads` (0600) con los logs de las 5 últimas sesiones y los informes de copy, check y Tag Manager de esas sesiones. |
| `common/shutdown.py` — cierre ordenado | `register_shutdown(cleanup, *, server_managed=False)`: se llama una vez, al importar la app y desde el hilo principal (el único donde se pueden instalar manejadores de señal). Ejecuta `cleanup` **una sola vez por proceso**, llegue el cierre por donde llegue: salida normal (`atexit`), una señal (SIGTERM de Slurm/Open OnDemand o de DCV, Ctrl+C) o el cierre de la ventana (`request_shutdown("window")`, desde `install_window_close`). Limpia en el propio manejador de la señal y no confía en `atexit`, porque en la app empaquetada Flet sustituye `sys.exit` y `atexit` no llega a ejecutarse. `install_signal_handlers()`: `main()` la vuelve a llamar porque `ft.run()` instala al arrancar sus propios manejadores, que no cierran la app y hacen que la segunda señal la mate sin limpiar. `server_managed=True` es para producción en Open OnDemand, donde Hypercorn ejecuta la app en un proceso hijo y el padre decide el cierre: el hijo deja SIGINT al padre, y con SIGTERM (un `scancel`, Delete en Open OnDemand) solo limpia, sin salir, para no cortar a medias el cierre ordenado del padre. `request_shutdown(reason)` deja `APP shutdown requested (reason=…)` en el log. |
| `common/rclone_output.py` — errores para el usuario y salida de rclone | `UserIssue(code, num, title, message, hint, web_hint, tags_hint)`: `num` es el tipo en el código que ve el usuario (tabla en [operations.md](operations.md#logs)); `hint_for(is_web, screen)`; `reference(screen)` → `MNT101-1103-141526`. Catálogo, `classify()`, `error_text()`, `error_key()`, `issue_for_exception()`. `RunSummary` (copy y check): `finish()` fija `ref` si la operación acaba con errores (`error_issue()`), que va en la primera línea de `final_lines()` y en `log_line()`. |
| `mount/preflight.py` — checks de FS userland | `WinFspMissingError`, `_check_winfsp_windows()`, `install_winfsp_windows(on_progress)`, `_get_fuse_macos()`, `_macos_app_bundle_frameworks()`, `_check_fuse_linux()`. |
| `common/rclone_mount.py` — lanzar y comprobar montajes | `mount_and_wait(comando, carpeta, log_path, env=, timeout=30)` → `Popen`: lanza `rclone mount` con un log temporal de solo errores en JSON (`--use-json-log --log-level ERROR`, máx. 10 MB + 1) y solo lo da por bueno si la carpeta se puede listar (rclone monta al instante aunque falle la conexión o las credenciales; la lectura de prueba va en otro hilo porque puede tardar minutos). Si falla → `MountError(issue)` con la causa leída del log de rclone, cuyos errores pasan al log técnico. `drain_rclone_log(log, etiqueta)`: pasa los errores del fichero al log técnico (`bifrost.rclone`, cada texto una vez, sin nombres de ficheros, hasta 100) y lo borra; lo usan el fallo de un montaje y todos los desmontajes. Si la carpeta ya está montada no lanza nada (`MOUNT_BUSY`): la comprobación vería ese montaje y no el nuevo. `is_mounted(carpeta)`, `stop_process(proc)`. Lo usan los montajes de MinIO y de la NetApp. |
| `mount/s3_mount.py` — montaje S3 | `mount_rclone_S3_prefix_to_folder()` → carpeta montada y comprobada (`MountError` / `WinFspMissingError`); si ya está montada y responde, la devuelve sin lanzar otro rclone; si el sistema quitó un montaje de esta sesión (macOS tras un corte de red) y su rclone sigue vivo, lo para antes de volver a montar. `resolver_mount_point_destino()` (única fuente de la carpeta de un bucket), `desmontar_punto_montaje()` → `bool` (termina solo el rclone de ese montaje; para restos de sesiones anteriores, el `rclone mount` cuya línea de comandos tiene exactamente esa carpeta —`ps` en macOS/Linux, PowerShell en Windows—, así rclone desmonta limpio; solo fuerza el desmontaje si la carpeta sigue montada; nunca `taskkill /IM` ni otros rclone, como las copias), `desmontar_todos_los_mounts_s3()` (y helpers de limpieza de puntos de montaje colgados). |
| `transfer/copy_check.py` — copy/check | `ejecutar_rclone_copy()`, `ejecutar_rclone_check()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| `transfer/ldap_groups.py` | `get_ldap_groups()`. |
| `transfer/rclone_ops.py` — listado y sistema | `rclone_lsjson()` (carpetas + ficheros — SFTP), `rclone_list_files_only(perfil, bucket, prefix)` (claves de los ficheros), `list_prefix_folders(perfil, bucket, prefix)` (subcarpetas, terminadas en `/`), `obtener_num_cpus()`, `traducir_ruta_a_remote()`. Los listados lanzan `RuntimeError` si rclone falla (nunca devuelven `[]` por un error). |
| `transfer/s3_tags.py` — boto3 / tagging S3 | `get_s3_client_from_profile(profile_name, endpoint)`, `read_object_tags(s3_client, bucket, key)` → `(etiquetas, fecha de subida)` (la fecha es el `LastModified` del objeto, `None` si no se puede leer; un error al leer las etiquetas se lanza), `apply_tags_to_object(...)` (un fichero; lanza la excepción de boto3), `apply_tags_to_prefix(..., stop=, on_progress=)` y `apply_tags_to_keys(...)` → `TagRun` (por páginas de 1.000, 8 a la vez; `stop` es el Cancel; se para sola ante credenciales caducadas, sin red, reloj o sin permiso en los primeros 20; `TagRun` da `outcome`, `final_lines()`, `problem_lines()` y `log_line()`), `get_bucket_tags(s3_client, bucket)` → `dict[str, str]`; vacío si no hay tags o hay error; `construir_tag_string()`. Todas sustituyen el conjunto entero de etiquetas del objeto. |
| `transfer/sftp.py` — perfiles SFTP efímeros | `crear_perfil_rclone_sftp()`, `generar_nombre_perfil_sftp()`, `validar_conexion_sftp()`, `eliminar_perfil_rclone()`, `limpiar_perfiles_rclone_con_prefijo()`. |
| `transfer/smb.py` — SMB/CIFS y montaje de shares | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `obtener_perfiles_rclone_config()`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`, `configurar_perfiles_smb_si_faltan()`, `montar_share_rclone()` (con `mount_and_wait`; solo se apunta en `mounts_activos` si monta), `montar_shares_seleccionados()` → `dict[share, MountError]`, `construir_recursos_cifs_dict()`, `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares()`. |

## Token de sesión STS — `get_session_info(perfil)`

Lee el `session_token` del perfil en el `rclone.conf` real
(`obtener_ruta_rclone_conf()`, el mismo fichero en el que escribe
`configure_rclone()`; antes se adivinaba la ruta por plataforma y con
`RCLONE_CONFIG` o `XDG_CONFIG_HOME` podía no coincidir) y decodifica el JWT una
sola vez. Devuelve `None` si no hay fichero, perfil o token; si no, un
`SessionInfo(usuario, remaining)` inmutable con:

- `expired` — el token ya ha caducado;
- `needs_renewal(usuario, threshold_days)` — verdadero si el token es de otro
  usuario, no se puede leer o le quedan `threshold_days` días o menos;
- `remaining_text()` — `"6d 23h"`, `"expired"` o `"unknown"` (lo usan el badge
  y los logs).

La ruta de `rclone.conf` se cachea durante toda la vida del proceso; si
`RCLONE_CONFIG` cambiara con la app abierta habría que llamar a
`obtener_ruta_rclone_conf.cache_clear()`.

## LDAP — `validar_credenciales_ldap(creds)`

Devuelve `(True, None)` o `(False, motivo)`:

| Motivo | Cuándo |
|---|---|
| `"invalid"` | No se han pasado credenciales. |
| `"user_not_found"` | El usuario no existe en LDAP. |
| `"invalid_password"` | El usuario existe pero el bind con la contraseña falla. |
| `"vpn"` | No se resuelve el servidor (`LDAPSocketOpenError('invalid server address')`): sin red del IRB / VPN. |
| `"network"` | Cualquier otro `LDAPCommunicationError` (timeout, conexión rechazada). |
| `"error"` | Cualquier otra excepción. |

Conexión y respuesta tienen un timeout de `LDAP_TIMEOUT = 10` s, y el usuario
se escapa en el filtro de búsqueda `(cn=...)`. La vista de login muestra el
mismo mensaje para `user_not_found` e `invalid_password` para no revelar si un
usuario existe; el motivo real queda en el log.

## `ui_call(page, fn)` — la decisión de concurrencia central

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    if not page.session or not page.session.connection:
        return                      # WebSocket cerrado (reconexión web): se omite la actualización
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

Envuelve `target` en un `threading.Thread` con try/except: una excepción no
controlada va al log técnico con su traza y un código (`unexpected error
ref=APP999-…`) y el usuario ve el pop-up de `UNEXPECTED` con ese mismo código
(vía `ui_call`). Es la forma estándar de lanzar acciones de usuario en
background.

## Acoplamiento backend → frontend

```python
# common/ui_helpers.py, dentro de safe_thread (diferido: evita un import circular)
from bifrost_frontend.frontend import show_issue
# common/rclone.py, common/updates.py
from config import APP_INFO
```

Consecuencias de diseño:

- No se puede importar el backend sin `config.py` en `sys.path` (cada app
  tiene el suyo, importable como módulo top-level). `version.py` también se
  importa como módulo top-level, pero con un valor por defecto si falta.
- El único sitio donde el backend muestra un diálogo es `safe_thread`
  (excepciones no capturadas). No es un backend puro/desacoplado; es un
  compromiso asumido: separarlo exigiría rediseñar la propagación de errores
  en toda la pila. El import debe seguir siendo diferido.

## fuse-t en macOS (`bifrost-mount`)

`_get_fuse_macos()` localiza el dylib `fuse_t`:

1. Dentro del `.app` en ejecución: `_macos_app_bundle_frameworks()` obtiene la
   ruta del bundle con `NSBundle.mainBundle` (Flet embebe Python en el mismo
   proceso) → `Contents/Frameworks/fuse_t.framework`.
2. En desarrollo (`flet run`): `FLET_ASSETS_DIR/../../frameworks/fuse_t.framework`,
   es decir, `bifrost-mount/frameworks/`.

Si no existe en ninguno, `mount_rclone_S3_prefix_to_folder()` lanza
`EnvironmentError` ("The folder driver (fuse-t) is missing…", que indica
reinstalar o, desde código, ejecutar `shared/macos-assets-downloader.sh`
desde `bifrost-mount/src`). Si existe, su ruta se pasa a rclone en
`CGOFUSE_LIBFUSE_PATH`.

## Instalación de `shared/` en desarrollo

Las apps referencian el wheel vía `__BUILDPATH__`; en desarrollo:

```bash
cd shared
python -m build .         # genera dist/bifrost_shared-*.whl
pip install dist/bifrost_shared-*.whl
```

Con `uv` en la app, el paquete se instala desde la ruta local; tras
modificar `shared/`:

```bash
uv sync --reinstall-package bifrost-shared
```

El paquete se instala como copia (no editable): hasta reinstalarlo, la app
sigue usando la versión anterior de `shared/` aunque el código del repo haya
cambiado.

El `main.py` de `bifrost-transfer` contiene un bloque comentado que añade
`shared/` a `sys.path` para desarrollar sin instalar el wheel.

## Scripts de descarga de assets

| Script | Para qué |
|---|---|
| `macos-assets-downloader.sh` | `rclone` + `fuse-t.framework` (`bifrost-mount` en macOS) — arquitectura auto-detectada (`uname -m`, override con `RCLONE_ARCH`; el job Intel de la CI lo usa con `RCLONE_ARCH=amd64`, stopgap hasta nov-2026) |
| `macos-rclone-downloader.sh` | solo `rclone` (`bifrost-transfer` en macOS) — arquitectura auto-detectada (mismo mecanismo; job Intel de la CI con `RCLONE_ARCH=amd64`) |
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
  visibles al usuario, lanzar y dejar que `safe_thread` muestre el diálogo, o
  devolver un valor que la vista convierta en mensaje (como hace
  `validar_credenciales_ldap` con su motivo).
- **Subprocess**: usar `_subprocess_kwargs()` (flags consistentes, p. ej.
  `CREATE_NO_WINDOW` en Windows). No hardcodear.
- **rclone**: nunca asumir un path; siempre `get_rclone_executable()`.
- **Logs**: nunca `print()`. Un logger por área (`log = logging.getLogger("bifrost.<área>")`, lista en
  [operations.md](operations.md#logs)); en inglés, una línea por evento, `clave=valor`, argumentos con `%s` (no
  f-strings), sin emojis; nunca contraseñas, listados de ficheros ni valores de etiquetas. INFO para lo que el
  usuario pone en marcha y su resultado, DEBUG para la navegación y el detalle, WARNING para fallos que la app
  controla, `log.exception` cuando la traza ayuda. Copy/check pasan las líneas del panel al frontend con
  callbacks (`log_fn`).

## Autoupdate

`check_update_version()` consulta las releases de GitHub;
`should_check_for_updates()` decide si toca comprobar;
`download_new_binary()` descarga el binario de la release nueva. En macOS el
sufijo del archivo lo elige `get_update_file_suffix()` según la arquitectura
(`platform.machine()`: arm64 → `-macos.dmg`, x86_64 → `-macos-intel.dmg`,
stopgap Intel hasta nov-2026). `check_update_version()` recibe
`force_update` (lo pasa `--update`), pero ahora mismo no hace nada: el bloque
de prueba que simula la versión `999.999.999` está comentado; hay que
descomentarlo para probar la pantalla de actualización. El flujo de
versionado (`1.0.<run_number>`) y la publicación están en
[build-and-ci.md](build-and-ci.md).
