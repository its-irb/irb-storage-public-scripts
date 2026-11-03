# Shared backend — `shared/bifrost_backend/`

Package with all the non-UI logic, split by area. `backend.py` is a
compatibility facade that re-exports the public API, so the apps keep calling
`backend.X` (`from bifrost_backend import backend`). `bifrost_backend/__init__.py`
is not empty: it disables `urllib3`'s `InsecureRequestWarning` for the whole
backend (internal MinIO requests use `verify=False`).

## Modules and key functions

| Module | Key functions |
|---|---|
| `common/auth.py` — STS, rclone profile, LDAP | `get_credentials(endpoint, username, password, durationseconds)` → temporary STS credentials (HTTP timeout 30 s); `configure_rclone()`; `get_session_info(profile)` → `SessionInfo`; `validar_credenciales_ldap()`. |
| `common/constants.py` | `MINIO_SERVERS`, `DEFAULT_S3_REGION`, `REPO`, `__version__`, `EMOJI_FONT_FILENAME`, `LDAP_SERVER_URL`, `LDAP_BASE_DN`, `STS_RENEWAL_THRESHOLD_DAYS` (3), `STS_AUTO_RENEWAL_DAYS` (7), `NO_LDAP` (`BIFROST_NO_LDAP=1`). |
| `common/rclone.py` — rclone resolution | `get_rclone_executable()` — looks for rclone in (1) `FLET_ASSETS_DIR/bin/` (packaged apps), (2) `bifrost-<flavour>/src/assets/bin/` of the repo (dev, built from `APP_INFO["flavour"]`), (3) PATH (web/cluster); raises `EnvironmentError` if not found. `obtener_ruta_rclone_conf()` (runs `rclone config file`; result cached with `lru_cache`), `rclone_lsd()` (folders only — S3 destination), `_subprocess_kwargs()`. |
| `common/updates.py` — autoupdate | `_parse_version()`, `check_update_version()`, `should_check_for_updates()`, `get_update_file_suffix()`, `download_new_binary()`, `get_emoji_font_asset_path()`. |
| `common/ui_helpers.py` — Flet ⇄ threading | `ui_call(page, fn)`, `safe_thread(page, target)`. |
| `common/logs.py` — technical log, reports, export | `setup_logging()`, `log_dir()`, `report_path()`, `write_report()`, `rclone_log_path()`, `open_in_file_browser()`, `export_logs_zip(sessions=EXPORTED_SESSIONS)` → path of the zip, in `~/Downloads` (0600) with the logs of the last 5 sessions and the copy, check and Tag Manager reports of those sessions. |
| `common/rclone_output.py` — user-facing errors, rclone output | `UserIssue(code, num, title, message, hint, web_hint, tags_hint)`: `num` is the type in the code the user sees (see "Error codes" below); `hint_for(is_web, screen)`; `reference(screen)` → `MNT101-1103-141526`. Catalog, `classify()`, `error_text()`, `error_key()`, `issue_for_exception()`. `RunSummary` (copy and check): `finish()` sets `ref` when the operation ends with errors (`error_issue()`); it goes on the first line of `final_lines()` and in `log_line()`. |
| `mount/preflight.py` — userland FS checks | `WinFspMissingError`, `_check_winfsp_windows()`, `install_winfsp_windows(on_progress)`, `_get_fuse_macos()`, `_macos_app_bundle_frameworks()`, `_check_fuse_linux()`. |
| `common/rclone_mount.py` — start and verify mounts | `mount_and_wait()` → `Popen`: starts `rclone mount` with a temporary errors-only JSON log (`--use-json-log --log-level ERROR`, max 10 MB + 1) and only succeeds once the folder can be listed (rclone mounts instantly even with bad credentials or no network; the probe listing runs in another thread because it can take minutes). On failure → `MountError(issue)` with the cause read from rclone's log, whose errors go to the technical log. `drain_rclone_log(log, label)`: moves the file's errors to the technical log (`bifrost.rclone`, each text once, no file names, up to 100) and deletes it; called when a mount fails and on every unmount. If the folder is already mounted it launches nothing (`MOUNT_BUSY`): the probe would see that mount, not the new one. `is_mounted()`, `stop_process()`. Used by MinIO and NetApp mounts. |
| `mount/s3_mount.py` — S3 mount | `mount_rclone_S3_prefix_to_folder()` → verified mount folder (`MountError` / `WinFspMissingError`); if the folder is already mounted and answers, returns it without a second rclone; if the system removed this session's mount (macOS after a network cut) and its rclone is still alive, stops it before mounting again. `resolver_mount_point_destino()` (single source of a bucket's folder), `desmontar_punto_montaje()` → `bool` (stops only that mount's rclone; for leftovers of a previous session, the `rclone mount` whose command line has that exact folder — `ps` on macOS/Linux, PowerShell on Windows — so rclone unmounts cleanly; forces the unmount only if the folder is still mounted; never `taskkill /IM`, never other rclone such as copies), `desmontar_todos_los_mounts_s3()` (+ stale mount-point cleanup helpers). |
| `transfer/copy_check.py` — copy/check | `ejecutar_rclone_copy()`, `ejecutar_rclone_check()`, `es_directorio_rclone()`, `traducir_a_ruta_local_montada()`, `preparar_origen_para_check()`. |
| `transfer/ldap_groups.py` | `get_ldap_groups()`. |
| `transfer/rclone_ops.py` — listing/system | `rclone_lsjson()` (folders + files — SFTP), `rclone_list_files_only()`, `list_prefix_folders()`, `obtener_num_cpus()`, `traducir_ruta_a_remote()`. Listings raise `RuntimeError` when rclone fails (never `[]` on error). |
| `transfer/s3_tags.py` — boto3 / S3 tagging | `get_s3_client_from_profile()`, `read_object_tags()` (→ `(tags, upload date)`; the date is the object's `LastModified`, `None` if it cannot be read), `apply_tags_to_object()` (one file; raises the boto3 exception), `apply_tags_to_prefix()` / `apply_tags_to_keys()` → `TagRun` (pages of 1,000, 8 in parallel; `stop` event = Cancel; stops by itself on expired credentials, no network, clock skew or no permission on the first 20; texts via `final_lines()`, `problem_lines()`, `log_line()`), `get_bucket_tags()` (returns `dict[str, str]`; empty if there are no tags or on error), `construir_tag_string()`. All of them replace the whole tag set of the object. |
| `transfer/sftp.py` — ephemeral SFTP profiles | `crear_perfil_rclone_sftp()`, `generar_nombre_perfil_sftp()`, `validar_conexion_sftp()`, `eliminar_perfil_rclone()`, `limpiar_perfiles_rclone_con_prefijo()`. |
| `transfer/smb.py` — SMB/CIFS + share mounts | `construir_credenciales_smb()`, `obtener_shares_accesibles()`, `obtener_perfiles_rclone_config()`, `crear_perfil_rclone_smb()`, `actualizar_password_perfiles_rclone()`, `configurar_perfiles_smb_si_faltan()`, `montar_share_rclone()` (uses `mount_and_wait`; added to `mounts_activos` only if it mounts), `montar_shares_seleccionados()` → `dict[share, MountError]`, `construir_recursos_cifs_dict()`, `obtener_letra_unidad_disponible()` (Windows), `generar_punto_montaje()`, `montar_share_rclone()`, `desmontar_todos_los_shares()`. |

## STS session token — `get_session_info(profile)`

Reads the `session_token` of the rclone profile from the real `rclone.conf`
(`obtener_ruta_rclone_conf()`, the same file `configure_rclone()` writes) and
decodes the JWT once. Returns `None` when there is no file, profile or token;
otherwise a frozen `SessionInfo(usuario, remaining)` with `expired`,
`needs_renewal(usuario, threshold_days)` (true if the token belongs to another
user, cannot be read or expires in ≤ `threshold_days`) and `remaining_text()`
(`"6d 23h"`, `"expired"`, `"unknown"`). The `rclone.conf` path is cached for
the whole process; call `obtener_ruta_rclone_conf.cache_clear()` if
`RCLONE_CONFIG` changes at runtime.

## LDAP — `validar_credenciales_ldap(creds)`

Returns `(True, None)` or `(False, reason)`. Reasons: `"invalid"` (no
credentials), `"user_not_found"`, `"invalid_password"`, `"vpn"` (server name
cannot be resolved: `LDAPSocketOpenError('invalid server address')`),
`"network"` (any other `LDAPCommunicationError`: timeout, refused connection),
`"error"` (any other exception). Connection and response timeouts are
`LDAP_TIMEOUT = 10` s; the username is escaped in the `(cn=...)` search filter.
The login view shows the same message for `user_not_found` and
`invalid_password` so it does not reveal whether a user exists.

## `ui_call(page, fn)` — the most important rule

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    if not page.session or not page.session.connection:
        return                      # WebSocket closed (web reconnection): skip the update
    async def _wrapper(): fn()
    page.run_task(_wrapper)
```

It queues `fn` on the Flet event loop through
`asyncio.run_coroutine_threadsafe`, instead of running it in a
`ThreadPoolExecutor` (which is what `page.run_thread` does). **Every UI
mutation from a background thread must go through `ui_call`** to avoid races
with Flet's diff walker (`IndexError` in `_compare_lists`; details in
`docs/development/frontend.md`).

## Error codes

Every error the user sees (pop-ups, the error line shown instead of a list, and
the first summary line of a copy, check or Tag Manager operation that failed)
carries a code `<screen><type>-<MMDD>-<HHMMSS>`, for example
`MNT101-1103-141526`. Screen: `MNT` bucket mount, `NET` NetApp, `CPY` copy
(also "Save log" and the copy screen's MinIO browser), `CHK` check, `TAG` Tag
Manager, `APP` updating BIFROST or an unexpected failure. The type is the
`num` of the `UserIssue`; `UserIssue.reference(screen)` builds the code.

| Family | Number | `code` |
|---|---|---|
| 1xx MinIO | 101 · 102 · 103 · 104 · 105 · 106 · 107 · 108 · 109 | `CREDENTIALS_EXPIRED` · `PROFILE_MISSING` · `MINIO_PERMISSION` · `BUCKET_NOT_FOUND` · `OBJECT_GONE` · `WORM_PROTECTED` · `INVALID_TAG` · `MINIO_BUSY` · `CLOCK_SKEW` |
| 2xx network and limits | 201 · 202 · 203 · 204 | `NETWORK` · `TEMPORARY` · `TRANSFER_LIMIT` · `TIME_LIMIT` |
| 3xx source files | 301 · 302 · 303 · 304 · 305 | `SOURCE_NOT_FOUND` · `SOURCE_PERMISSION` · `SOURCE_CHANGING` · `FILE_IN_USE` · `DISK_FULL` |
| 4xx mounts | 401 · 402 · 403 · 404 · 405 | `MOUNT_TIMEOUT` · `MOUNT_BUSY` · `MOUNT_NOT_ALLOWED` · `UNMOUNT_FAILED` · `FUSE_MISSING` |
| 5xx NetApp | 501 · 502 · 503 | `NETAPP_LOGIN` · `NETAPP_SHARE_NOT_FOUND` · `NETAPP_PERMISSION` |
| 9xx BIFROST | 901 · 902 · 903 · 999 | `RCLONE_MISSING` · `RCLONE_OPTIONS` · `FATAL` · `UNEXPECTED` |

Rules: a number is never reused or changed (a code from an old version keeps
its meaning); variants of the same cause share a number (`FUSE_MISSING` for
macOS and Linux, the three `SOURCE_NOT_FOUND`); a new error takes the next free
number of its family. Update this table, the one in
`docs/development/operations.md` and the user one
(`docs/user/troubleshooting.md`, with what to do) in the same commit that adds
or changes a catalog error.

In the technical log: `issue shown: ref=… code=… screen=…` (logger
`bifrost.ui`) every time an error is shown, without its context (in the Tag
Manager it is a file name); `ref=…` at the end of `copy/check/tags finished`
when the operation ends with errors; `unexpected error ref=APP999-…` with the
traceback (`safe_thread`).

## `safe_thread(page, target, daemon=True)`

Creates a `threading.Thread` that wraps `target` in try/except: an unhandled
exception goes to the technical log with its traceback and a code
(`unexpected error ref=APP999-…`), and the user sees the `UNEXPECTED` pop-up
with that same code (through `ui_call`). Prefer it over a bare
`threading.Thread` for user actions.

## Backend coupling

```python
# common/ui_helpers.py, inside safe_thread (lazy: avoids a circular import)
from bifrost_frontend.frontend import show_issue
# common/rclone.py, common/updates.py
from config import APP_INFO
```

Consequences:

- The backend cannot be imported unless `config.py` is on `sys.path` (each app
  has its own).
- The only place where the backend shows a dialog is `safe_thread` (unhandled
  exceptions). Keep the frontend import lazy.

## Code conventions in the backend

- **Language**: docstrings, comments and function names are in Spanish
  (`obtener_shares_accesibles`, `montar_share_rclone`, …).
- **Errors**: raise exceptions or return `None`/`False`. For errors the user
  must see, raise and let `safe_thread` show the dialog, or return a value the
  view turns into a message (as `validar_credenciales_ldap` does).
- **Subprocess**: use `_subprocess_kwargs()` (consistent flags, for example
  `CREATE_NO_WINDOW` on Windows). Do not hardcode flags.
- **rclone**: never assume a path; always `get_rclone_executable()`.
- **Logs**: copy/check stream lines to the frontend through callbacks
  (`log_fn`). Do not print to stdout from copy/check functions.

## fuse-t on macOS (`bifrost-mount`)

`_get_fuse_macos()` returns the `fuse_t` dylib: inside the running `.app`
(`_macos_app_bundle_frameworks()` → `NSBundle.mainBundle` →
`Contents/Frameworks/fuse_t.framework`) or, in dev (`flet run`), at
`FLET_ASSETS_DIR/../../frameworks/fuse_t.framework`, that is
`bifrost-mount/frameworks/`. If neither exists it returns `None` and
`mount_rclone_S3_prefix_to_folder()` raises `EnvironmentError` ("The folder
driver (fuse-t) is missing…", which asks to reinstall or, from source, to run
`shared/macos-assets-downloader.sh` from `bifrost-mount/src`). When found, its
path is passed to rclone as `CGOFUSE_LIBFUSE_PATH`.

## Autoupdate

`check_update_version()`, `should_check_for_updates()` and
`download_new_binary()` check GitHub releases and download the new binary. On
macOS, `get_update_file_suffix()` picks the file suffix from the machine
architecture (`platform.machine()`: arm64 → `-macos.dmg`, x86_64 →
`-macos-intel.dmg`; Intel stopgap until Nov-2026). `check_update_version()`
accepts `force_update`, but it currently has no effect: the test block that
simulates version `999.999.999` is commented out. See
[operations.md](operations.md) for the versioning flow.
