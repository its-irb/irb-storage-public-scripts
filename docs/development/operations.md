# Operaciones — BIFROST

Aspectos operativos: logs, autoupdate, credenciales STS, variables de entorno, dependencias de sistema (WinFsp/fuse-t) y depuración.

## Logs de sesión

Cada app escribe un log con timestamp en el home del usuario:

| App | Ruta | Cuándo se escribe |
|---|---|---|
| bifrost-mount | `~/bifrost-mount-logs/bifrost-mount-YYYY-MM-DD_HH-MM-SS.log` | eventos de usuario (`_log_event`) |
| bifrost-transfer | `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log` | al terminar cada copy/check (`_autosave_log`) + streaming |

En `bifrost-transfer`, `_autosave_log()` vuelca el buffer completo al final de cada copia o verificación (éxito o error). En modo web es crítico porque el buffer en memoria está capeado a 5000 líneas y en reconexión solo se replayean 200 en pantalla; el log completo solo existe en disco (ver `web-mode.md`).

El log incluye el comando rclone completo ejecutado (`🧾 Full command:`) para reproducir incidencias.

## Autoupdate

Cuando hay una release nueva en GitHub, la app pregunta al usuario si quiere actualizarse.

### Lógica (en `backend.py`)

- `check_update_version(force_update=False)` — consulta la última release del repo `its-irb/irb-storage-public-scripts`, compara versiones semánticas con `_parse_version`, devuelve la versión nueva o `None`.
- `should_check_for_updates()` — controla la frecuencia para no spamear al usuario.
- `get_update_file_suffix()` — sufijo por plataforma (`-macos.dmg`, `-windows.exe`, …).
- `download_new_binary(file_name)` — descarga el binario nuevo a temp.

### UI (en `frontend.py`, compartido)

`build_update_content(page, on_continue)` muestra el chequeo inicial (spinner "Checking for updates..."). Si hay versión nueva: "New version available: X" + botones "Update now" / "Continue anyway". Si no: "✓ You are using the latest version." y continúa automáticamente tras 1 s.

### Flujo de actualización por plataforma

- **Windows**: `_escribir_y_lanzar_updater_windows` escribe un `.bat` que espera 2s, ejecuta el `.exe` descargado en modo silencioso Inno Setup (`/SILENT /SUPPRESSMSGBOXES /NOCANCEL`), y reabre la app desde `%ProgramFiles(x86)%\Bifrost-<flavour>\bifrost-<flavour>.exe`. Luego `os._exit(0)`.
- **macOS**: `hdiutil attach` del DMG, determina el mount point, y mediante `osascript ... with administrator privileges` ejecuta un script que: `pkill -x bifrost-<flavour>`, espera a que termine, `chmod -R u+w`, `rm -rf /Applications/bifrost-<flavour>.app`, `ditto` desde el DMG, `hdiutil detach`, `xattr -d com.apple.quarantine` recursivo, `open`. Luego `os._exit(0)`.
- **Linux**: `os.replace` el binario descargado sobre `sys.argv[0]`, `chmod +x`, y muestra diálogo pidiendo reiniciar.

En modo web (OOD) el autoupdate está desactivado (no hay binario que actualizar; el proceso lo gestiona OOD).

## Credenciales STS (MinIO)

### Obtención

`backend.get_credentials(endpoint, username, password, durationseconds=86400)` llama a la API STS de MinIO con las credenciales LDAP del usuario y devuelve un dict con credenciales temporales (AccessKey, SecretKey, SessionToken, Expiration).

`get_usuario_from_session_token(session_token)` decodifica el JWT del session token para extraer el usuario. `get_expiration_from_session_token(session_token)` extrae la fecha de expiración.

### Auto-renovación

Constantes en cada `main.py`:

```python
STS_RENEWAL_THRESHOLD_DAYS = 3
STS_AUTO_RENEWAL_DAYS = 7
```

- Si quedan **>3 días** en las credenciales STS almacenadas → se saltan, va directo a `view_mount`/`view_copy`.
- Si quedan **<3 días** o no hay credenciales → `view_credentials` renueva automáticamente por 7 días, mostrando progreso en un log en pantalla.
- No hay botón manual de renovación en el flujo normal.

`configure_rclone(...)` escribe el perfil rclone con las credenciales STS en `rclone.conf` (`obtener_ruta_rclone_conf()`).

## Autenticación LDAP

`backend.get_ldap_groups(usuario)` devuelve los grupos LDAP del usuario. `backend.validar_credenciales_ldap(credenciales_ldap) → (bool, str|None)` valida user+password contra el LDAP del IRB.

`BIFROST_NO_LDAP=1` (env var) salta la validación LDAP en el login. Pensado para máquinas sin acceso a LDAP pero con acceso a MinIO (ej. IVIS). El usuario igualmente introduce usuario+contraseña (necesarios para STS). El badge del header muestra `DESKTOP (NO LDAP)`. En Windows, definir como variable de sistema (`setx BIFROST_NO_LDAP 1 /M`) para que aplique a todos los usuarios.

## Dependencias de sistema (montaje)

`bifrost-mount` requiere un subsistema FUSE para montar buckets como unidad local:

| Plataforma | Dependencia | Cómo se obtiene |
|---|---|---|
| macOS | **fuse-t** 1.0.49 | Empaquetado en `frameworks/fuse_t.framework`, descargado por `macos-assets-downloader.sh` en build |
| Windows | **WinFsp** | **No empaquetable** (incluye driver kernel). El usuario lo instala. Si falta, la app lo detecta y ofrece instalarlo automáticamente |
| Linux | **FUSE** | Del sistema (modo web OOD no monta) |

### Flujo WinFsp (Windows, mount)

Si al montar `backend._check_winfsp_windows()` devuelve `False`, el backend lanza `WinFspMissingError(EnvironmentError)`. La UI ofrece descargar e instalar la última release oficial de WinFsp desde `github.com/winfsp/winfsp`:

- `_winfsp_latest_msi_url()` consulta la GitHub API para la última release.
- `_download_winfsp_msi(url, tag)` descarga el MSI a `%TEMP%`.
- `install_winfsp_windows(page, on_progress)` lo instala silenciosamente con `msiexec /i ... /qb` (requiere UAC).
- Tras instalar, reintenta el montaje.

Los mensajes de este flujo están en **inglés** (excepción al español habitual de la UI) para alinearse con el resto de la UI de `bifrost-mount`. `bifrost-transfer` no tiene este flujo.

## Variables de entorno

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_WEB` (modo web completo; señal de producción OOD). Activa el bloque ASGI y el flujo CIFS/shares del cluster. |
| `BIFROST_NO_LDAP=1` | ambas | Salta validación LDAP en login. Badge header `DESKTOP (NO LDAP)`. |
| `FLET_ASSETS_DIR` | ambas | Lo setea Flet runtime; el backend lo usa (prioridad 1) para localizar `rclone` empaquetado. |
| `FLET_APP_STORAGE_TEMP` | ambas | Setado por Flet; útil para debug de localización de binarios. |
| `FLET_WEBSOCKET_HANDLER_ENDPOINT` | transfer (OOD) | Endpoint WebSocket para el bloque ASGI en cluster. |
| `WEBPATH` | transfer (OOD) | Path donde montar la app ASGI en FastAPI. |
| `password` | transfer (OOD) | Token de auth del WebSocket (leído de la cookie `bifrost_auth_token`). Si vacío, auth desactivada (con warning). |
| `PYTHONUTF8=1` | build Windows | Fuerza UTF-8 en build CI de Windows. |

## Resolución de rclone

`backend.get_rclone_executable()` prioridad:

1. `FLET_ASSETS_DIR/bin/rclone[.exe]` (apps empaquetadas — Flet setea esta var en runtime).
2. `bifrost-<flavour>/src/assets/bin/rclone[.exe]` (dev, relativo a `shared/`, usa `APP_INFO["flavour"]`).
3. `shutil.which("rclone")` (PATH del sistema — modo web/cluster).

`_ensure_executable(path)` aplica `chmod +x` si hace falta. Si los tres fallan: `EnvironmentError("rclone not found. The application bundle appears to be incomplete — please reinstall BIFROST.")`.

## Subprocess

`backend._subprocess_kwargs()` devuelve flags consistentes para `subprocess.Popen`/`run`:

- Windows: `creationflags=subprocess.CREATE_NO_WINDOW` (evita ventana de consola).
- Otros: sin flags extra.

**Siempre** usar `_subprocess_kwargs()` para nuevos subprocess; no hardcodear flags.

## Depuración

### Localización de rclone

Si la app no encuentra rclone:

1. Verificar `<app>/src/assets/bin/rclone` (o `.exe`) existe y es ejecutable.
2. En build empaquetado, comprobar `FLET_ASSETS_DIR`.
3. Descomentar temporalmente prints en `get_rclone_executable()` para ver qué ruta intenta.
4. En cluster, verificar `which rclone`.

### Threading / UI

- `IndexError: list index out of range` en `object_patch.py:_compare_lists` → mutación de UI sin `ui_call` (ver `thread-safety.md`).
- `[ui_call] Skipping UI update — session disconnected` en consola → WebSocket cerrado (reconexión OOD); es esperado.

### Web (OOD)

- `BIFROST_CLUSTER=1 python src/main.py --web` reproduce el flujo de producción en local.
- `~/bifrost-logs/` contiene el log completo de cada sesión en el cluster.
- Si reconectar se cuelga → sospechar del dispatcher `_dispatch_log` (ver `web-mode.md`).

### Credenciales STS

- Si la renovación falla, verificar VPN activa y credenciales LDAP correctas.
- `get_expiration_from_session_token` muestra cuándo caducan las STS actuales.
- `obtener_ruta_rclone_conf()` devuelve la ruta al `rclone.conf` (dependiente de plataforma).

### Copia / check

- El log incluye el comando rclone completo (`🧾 Full command:`).
- `ejecutar_rclone_copy` usa `--checksum --check-first --copy-links` y excluye `.DS_Store`, `Thumbs.db`, `.snapshot`, `.Trash`, `.cache`.
- En Unix, rclone corre con `nice(10)` para no saturar el event loop de Hypercorn en web.
- `expose_proceso={"proc": Popen}` permite cancelar exponiendo el subprocess al caller.
