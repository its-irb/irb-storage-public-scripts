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
  (`fecha hora.ms NIVEL [logger] mensaje`), logger raíz `bifrost`, un logger por módulo
  (`bifrost.login`, `bifrost.mount`, `bifrost.copy`, `bifrost.rclone`…). Los `print()` se redirigen a
  `bifrost.print` y stderr a `bifrost.stderr`; los secretos (JWT, `password=`…) se enmascaran.
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
  normal no deja ninguna línea de rclone. Si un montaje falla, el pop-up da la ruta del log técnico de la
  sesión (`current_log_file()`; en OOD, `output.log`). El log técnico registra `mount ok: <carpeta> (rclone pid
  N, N s)` / `mount failed: <carpeta> code=…` (debajo, los errores de rclone), `already mounted` si la carpeta ya estaba montada (no se lanza otro rclone), `no longer mounted`
  si el sistema quitó el montaje (al recargar la lista o al pulsar el bucket, que se vuelve a montar: `mounting
  again` y `stopping rclone pid N of the lost mount`, porque su rclone sigue vivo),
  `mounted from a previous session: <carpeta>` por cada bucket que la pantalla encuentra montado al abrirse y cada
  desmontaje con el PID que se para (`unmount <carpeta>: stopping rclone pid N` o, si es un resto de una
  sesión anterior, `rclone from a previous session, PIDs [N]` … `done (N s)`). Si la lista de buckets no se
  puede cargar: `bucket list failed: profile=… code=…` y, con `[bifrost.rclone]`, el texto de rclone.
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
