# Operación: variables de entorno, autoupdate y logs

## Variables de entorno

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_WEB` (modo web completo; señal de producción OOD; flujo CIFS/shares del cluster). |
| `BIFROST_NO_LDAP=1` | ambas | Salta la validación LDAP en el login. Para máquinas sin acceso a LDAP pero con acceso a MinIO (p. ej. IVIS). El usuario igualmente introduce usuario+contraseña (necesarios para STS). El badge del header muestra `DESKTOP (NO LDAP)`. En Windows se define como variable de sistema (ver abajo) para que aplique a todos los usuarios. |
| `BIFROST_LOG_LEVEL` | ambas | Nivel del log en consola (`DEBUG`, `INFO`…). Por defecto INFO en escritorio y DEBUG en web. |
| `BIFROST_SESSION_DIR` | transfer (web) | Carpeta de la sesión de Open OnDemand (la exporta `script.sh.erb`); allí se guardan los informes (`reports/`). |
| `FLET_ASSETS_DIR` | ambas | La setea Flet en runtime; el backend la usa para localizar el `rclone` empaquetado (`FLET_ASSETS_DIR/bin/`). |
| `FLET_APP_STORAGE_TEMP` | ambas | La setea Flet; usada para depurar la localización de binarios. |

```powershell
# BIFROST_NO_LDAP como variable de sistema de Windows (aplica a todos los usuarios)
setx BIFROST_NO_LDAP 1 /M
```

## Autoupdate

Cuando existe una release nueva de la app en el repositorio, la app pregunta
al usuario si quiere actualizarse y descarga el binario nuevo desde las
releases de GitHub.

- Lógica backend: `backend.check_update_version()`,
  `backend.should_check_for_updates()`, `backend.get_update_file_suffix()`,
  `backend.download_new_binary()`.
- Vista: `view_update` (`build_update_content`, en
  `shared/bifrost_frontend/views/update.py`) es la primera vista del flujo.
- `--update` pretende forzar la comprobación en desarrollo:

  ```bash
  flet run --update
  ```

  **Ahora mismo no hace nada**: la vista pasa `force_update` a
  `check_update_version()`, pero el bloque de prueba que simula la versión
  `999.999.999` está comentado. Para probar la pantalla de actualización hay
  que descomentarlo en `shared/bifrost_backend/common/updates.py` y
  reinstalar el paquete compartido.
- Versionado: `1.0.<run_number>` (ver [build-and-ci.md](build-and-ci.md)).

## Logs

Detalle y decisiones: `docs/superpowers/plans/PLAN-logging-improvements.md`.

- **Log técnico** (`shared/bifrost_backend/common/logs.py`, `setup_logging`): formato fijo
  (`fecha hora.ms NIVEL [logger] mensaje`), logger raíz `bifrost`, un logger por área: `bifrost.login`,
  `bifrost.auth` (STS, token, LDAP, renovación), `bifrost.mount`, `bifrost.netapp`, `bifrost.copy` (copy, check
  y sus navegadores), `bifrost.tags`, `bifrost.rclone` (texto de rclone), `bifrost.update`, `bifrost.session`
  (sesión web), `bifrost.transfer`, `bifrost.ui` (`issue shown`, fallos no previstos), `bifrost.shutdown`,
  `bifrost.logs`. El código no usa `print()`: lo que impriman otras librerías llega como `bifrost.print`, y
  stderr como `bifrost.stderr`. Los secretos (JWT, `password=`…) se enmascaran.
  - Escritorio: un fichero por sesión en la carpeta estándar del sistema (se conservan 30):
    `~/Library/Logs/BIFROST/<app>/` (macOS), `%LOCALAPPDATA%\IRB\BIFROST\<app>\` (Windows),
    `$XDG_STATE_HOME/bifrost/<app>/` o `~/.local/state/bifrost/<app>/` (Linux).
  - Web (Open OnDemand): solo stdout, que es el `output.log` de la carpeta de la sesión.
  - Nivel de consola: INFO en escritorio y DEBUG en web; se cambia con `BIFROST_LOG_LEVEL`.
- **Informes de copy y check** (`report_path()`, se conservan 30 por tipo): un fichero por operación
  (`copy-*.log`, `check-*.log`; "Save log" escribe `log-*.log` en web) con exactamente lo que vio el
  usuario en esa operación (origen, destino, todas las etiquetas del perfil y resumen con recuentos) y, debajo,
  `--- Files with problems ---` (`RunSummary.problem_lines()`): no copiados, carpetas ilegibles y
  sustituidos (copy); distintos e ilegibles (check), con su causa y hasta 100 en total. En escritorio, en `<carpeta de logs>/reports/`;
  en web, en `$BIFROST_SESSION_DIR/reports/` (carpeta de la sesión de OOD, la exporta `script.sh.erb`).
- **Salida de rclone** (`common/rclone_output.py`, `RunSummary`): rclone corre con `--use-json-log`; el
  panel solo recibe progreso, resumen (solo recuentos, sin nombres de ficheros: una copia masiva puede tener
  miles), tamaño copiado, duración, cómo se comparó (check: "compared by MD5 checksum") y qué hacer. El log
  técnico **no** guarda nombres de ficheros copiados ni los valores de las etiquetas (el comando aparece como
  `x-amz-tagging:<claves>`); al terminar escribe una línea con todo (`RunSummary.log_line()`):
  `copy finished: outcome=… rc=… copied=… bytes=… replaced=… unchanged=… failed=… folders=… attempts=…
  duration=…s speed=…` y `check finished: outcome=… rc=… matching=… missing=… different=… unreadable=…
  uncompared=… hash=md5|none duration=…s`. `attempts` > 1 indica reintentos de rclone; `hash=none`, que el
  check solo comparó tamaños.
- **Regla del log técnico en todas las pantallas**: lo que el usuario elige (una ruta, un bucket) y
  recuentos; nunca listados de contenido (carpetas, ficheros, buckets) ni valores de etiquetas. El navegador
  de MinIO y el Tag Manager escriben "N entries" / "N buckets match" y, al aplicar etiquetas, solo los
  nombres de los campos.
- **Dónde van los nombres de ficheros**: solo al informe de la operación (lista de ficheros con problemas,
  `MAX_REPORTED_NAMES` = 100). El panel da recuentos y dice que la lista está en el informe. El log técnico
  escribe cada tipo de error de rclone una vez, sin nombres ni rutas (`error_text`; hasta 100 textos
  distintos, `MAX_LOGGED_ERRORS`). Los que faltan en MinIO no se nombran nunca: se arreglan volviendo a copiar
  y pueden ser todos.
- **Ficheros ya idénticos**: copy usa `--match` para contar los ficheros que rclone no copió por ser
  idénticos. Son los que **no** reciben las etiquetas del formulario, y el resumen lo dice. rclone solo anota
  la decisión que ya toma: no añade lecturas ni peticiones a MinIO. Se descuentan los que rclone notificó
  como copiados (en un reintento la lista se reescribe y salen como idénticos).
- **Recuentos de check**: salen de los totales que rclone escribe al terminar ("N files missing",
  "N differences found", "N errors while checking"): exactos y sin depender del disco. Las listas
  `--missing-on-dst/--differ/--error` solo se usan si faltan esos totales.
- **Carpeta temporal de las listas** (`bifrost-copy-*`, `bifrost-check-*` en `tempfile.gettempdir()`:
  `TMPDIR`, `/tmp`, `/var/folders/…` o `%TEMP%`; permisos 0700; ~60 MB por millón de ficheros; se borra al
  terminar). Comprobado con un disco lleno: si rclone no puede **crear** una lista aborta la operación
  entera, y si el disco se llena **a mitad**, corta la lista sin avisar y termina con código 0. Por eso:
  con menos de 100 MB libres se trabaja sin listas (`_TEMP_MIN_FREE`); copy no da el número de "ya estaban"
  si al terminar el disco temporal está lleno o, sin reintentos, la lista tiene menos líneas que las
  comparaciones de rclone; y al empezar cada operación se borran las carpetas del usuario sin cambios en
  7 días (restos de una app que murió de golpe; no antes, porque otra sesión del mismo usuario en el mismo
  nodo puede estar usando la suya).
- **Opciones avanzadas**: `flags_no_permitidos()` rechaza en el campo "Additional rclone flags" las opciones
  que cambian la salida (`-v`, `--log-*`, `--stats*`, `--progress`), escriben informes propios, pueden volcar
  secretos (`--dump*`, `--header*`, nombres con secret/token/pass/key) o cambian la configuración.
- **Tag Manager**: igual que copy y check. Panel LOGS siempre visible; cada operación (guardar un fichero,
  aplicar a una carpeta) escribe su informe `reports/tags-<fecha>.log` con `write_report()` (un fichero:
  etiquetas anteriores y nuevas; una carpeta: lo del panel + hasta 100 ficheros que fallaron) y deja la ruta
  completa en LOGS. El log técnico: `tags finished: outcome=… total=… ok=… failed=… stopped=… duration=…`,
  errores una vez por tipo y sin nombres, y de las etiquetas solo los nombres de los campos.
- **Montajes** (buckets en Bifrost Mount, shares de la NetApp en OOD): mientras monta, rclone escribe solo sus
  errores, en JSON, en un fichero temporal en `rclone/` junto a `reports/` (`rclone_log_path()`:
  `mount-<perfil>-<bucket>.log`, `netapp-<share>.log`, siempre el mismo por bucket o share; en OOD, la carpeta
  de la sesión; `--use-json-log --log-level ERROR --log-file-max-size 10M --log-file-max-backups 1`). BIFROST lo
  lee para elegir el pop-up y, cuando el montaje falla o se desmonta (también un resto de una sesión anterior,
  un montaje perdido o al cerrar la app), pasa sus errores al log técnico con `[bifrost.rclone]`
  (`drain_rclone_log`: cada error distinto una vez, con el `RequestID` de la primera vez para buscarlo en el log
  de MinIO, sin nombres de ficheros, hasta 100) y lo borra. Un montaje
  normal no deja ninguna línea de rclone. Si un montaje falla, el pop-up da el código del error (ver abajo), no
  rutas. El log técnico registra `mount ok: <carpeta> (rclone pid
  N, N s)` / `mount failed: <carpeta> code=…` (debajo, los errores de rclone), `already mounted` si la carpeta ya estaba montada (no se lanza otro rclone), `no longer mounted`
  si el sistema quitó el montaje (al recargar la lista o al pulsar el bucket, que se vuelve a montar: `mounting
  again` y `stopping rclone pid N of the lost mount`, porque su rclone sigue vivo),
  `mounted from a previous session: <carpeta>` por cada bucket que la pantalla encuentra montado al abrirse y cada
  desmontaje con el PID que se para (`unmount <carpeta>: stopping rclone pid N` o, si es un resto de una
  sesión anterior, `rclone from a previous session, PIDs [N]` … `done (N s)`). Si la lista de buckets no se
  puede cargar: `bucket list failed: profile=… code=…` y, con `[bifrost.rclone]`, el texto de rclone.
- **Códigos de error** (PR 4 y PR 5): cada error que ve el usuario (pop-ups, la línea de error en lugar de una
  lista, la primera línea del resumen de copy, check y Tag Manager cuando fallan, y los mensajes de la renovación
  de credenciales) lleva un código `<pantalla><tipo>-<MMDD>-<HHMMSS>`, por ejemplo `MNT101-1103-141526`. Los
  del login también tienen el suyo, pero solo en el log técnico: en esa pantalla sería ruido. Pantalla: `LGN`
  login, `CRD` renovación de credenciales, `MNT` montar un bucket, `NET` NetApp, `CPY` copy (y "Save log" y los
  navegadores de copy), `CHK` check, `TAG` Tag Manager, `APP` actualizar BIFROST o fallo no previsto. El tipo es
  el campo `num` de cada `UserIssue` (`common/rclone_output.py`); `UserIssue.reference(screen)` crea el código.

  | Familia | Número | `code` |
  |---|---|---|
  | 1xx MinIO | 101 · 102 · 103 · 104 · 105 · 106 · 107 · 108 · 109 | `CREDENTIALS_EXPIRED` · `PROFILE_MISSING` · `MINIO_PERMISSION` · `BUCKET_NOT_FOUND` · `OBJECT_GONE` · `WORM_PROTECTED` · `INVALID_TAG` · `MINIO_BUSY` · `CLOCK_SKEW` |
  | 2xx red y límites | 201 · 202 · 203 · 204 | `NETWORK` · `TEMPORARY` · `TRANSFER_LIMIT` · `TIME_LIMIT` |
  | 3xx ficheros de origen | 301 · 302 · 303 · 304 · 305 | `SOURCE_NOT_FOUND` · `SOURCE_PERMISSION` · `SOURCE_CHANGING` · `FILE_IN_USE` · `DISK_FULL` |
  | 4xx montajes | 401 · 402 · 403 · 404 · 405 | `MOUNT_TIMEOUT` · `MOUNT_BUSY` · `MOUNT_NOT_ALLOWED` · `UNMOUNT_FAILED` · `FUSE_MISSING` |
  | 5xx NetApp | 501 · 502 · 503 | `NETAPP_LOGIN` · `NETAPP_SHARE_NOT_FOUND` · `NETAPP_PERMISSION` |
  | 6xx inicio de sesión | 601 | `INVALID_CREDENTIALS` |
  | 9xx BIFROST | 901 · 902 · 903 · 999 | `RCLONE_MISSING` · `RCLONE_OPTIONS` · `FATAL` · `UNEXPECTED` |

  Reglas: un número no se reutiliza ni cambia nunca (un código de una versión antigua sigue significando lo
  mismo); las variantes de una misma causa comparten número (`FUSE_MISSING` de macOS y de Linux, los tres
  `SOURCE_NOT_FOUND`); un error nuevo toma el siguiente número libre de su familia. Esta tabla, la de
  `docs/agent/backend.md` y la de la guía de usuario (`docs/user/troubleshooting.md`, con qué hacer) se
  actualizan en el mismo commit que añada o cambie un error del catálogo.

  En el log técnico, para buscar por código:
  - `issue shown: ref=MNT101-1103-141526 code=CREDENTIALS_EXPIRED screen=mount` (logger `bifrost.ui`) cada vez
    que se muestra un error, sin el contexto (en el Tag Manager es el nombre del fichero). Buscar `issue shown`
    da todos los errores que ha visto el usuario, también los del login.
  - `copy finished: … ref=CPY103-…`, `check finished: … ref=CHK…`, `tags finished: … ref=TAG…` cuando la
    operación acaba con errores: copy y check `failed` o `partial`, check con ficheros que no pudo leer, Tag
    Manager `stopped` o `partial`. Lo que el check encuentra distinto o que falta en MinIO es un resultado, no
    un error: sin código. El tipo es el del error que explica el resultado (en un parcial, la causa más
    frecuente).
  - `unexpected error ref=APP999-…` con la traza (`safe_thread`) y `update failed ref=APP…` con la suya.
- **Inicio de sesión y credenciales** (PR 5), una línea por evento:
  - `LOGIN attempt/success/failed — user: … — reason: …` (`bifrost.login`); `ldap: user found dn=…` (DEBUG).
  - Al elegir el servidor, `server selected: minio (https://…)` y la decisión de renovar
    (`hay_que_renovar_credenciales`): `credentials: profile=… token_user=… login_user=… expiry=6d 20h → valid`
    (o `→ renewal needed`).
  - Al renovar: `credentials: renewing profile=… days=7 current=…` y `credentials: renewed profile=… expiry=…`;
    si MinIO no las da, `sts: request failed: http=… code=… message=… request_id=…` (o
    `sts: unexpected response: … body=…`, en una línea y hasta 300 caracteres).
- **Otras líneas** (PR 5): `update check: current=… latest=… → up to date` (o `→ update available`; WARNING si
  falla), `web session saved/cleared for …` (DEBUG), `APP shutdown requested (reason=window|SIGTERM|SIGINT)` y,
  al cerrar la NetApp, `unmount <carpeta>: done` / `still mounted (<causa>)` por share.
- **"Export logs…"** (escritorio, en la cabecera de todas las pantallas; en OOD no existe: la pista pide el
  `output.log` de la sesión): tras una confirmación, `export_logs_zip()` guarda en `~/Downloads`
  `BIFROST-<app>-logs-<fecha>.zip` (permisos 0600) con los logs de las 5 últimas sesiones (`EXPORTED_SESSIONS`)
  y los informes de copy, check y Tag Manager desde el inicio de la más antigua; `rclone/` no entra. Antes de
  comprimir escribe `exporting logs to <zip>: sessions=N reports=M`, así que el log de la sesión actual dice
  hasta dónde llega.
- Logs antiguos que ya no se escriben: `~/bifrost-mount-logs/`, `~/rclone-combined-check.txt` y
  `~/bifrost-logs/` (también los `bifrost-tags-*.log` del Tag Manager). Pendiente de decidir si se borran.

## Seguridad

- La contraseña LDAP **nunca** se persiste en el modo web (`_WEB_SESSIONS`
  guarda estado de sesión pero no credenciales).
- Los perfiles rclone SFTP efímeros (`sftp-src-*`) almacenan la contraseña
  ofuscada con `rclone obscure` y se eliminan al final de la sesión y en cada
  login (ver [frontend.md](frontend.md)).
- No incluir valores sensibles (credenciales, tokens, connection strings) en
  documentación, commits ni artefactos; usar marcadores.

## Zona legacy

`old/` contiene `backend-old.py` y `minio-sts-credentials-request.py`:
scripts legacy, fuera de uso. No importar de ahí ni documentarlos como
activos.
