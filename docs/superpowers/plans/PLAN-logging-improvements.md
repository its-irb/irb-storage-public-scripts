# Plan: sistema de logs unificado (log técnico + mensajes al usuario + salida de rclone)

Rama: `refactor/unified-logging`. Última actualización: 2026-11-03.

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Verificación de formatos de rclone 1.72.1 y de Hypercorn 0.18 | Hecha (falta el punto 4: errores reales de MinIO) |
| PR 1 | Log técnico común (`common/logs.py`) en las dos apps + OOD | **Hecho** |
| PR 2 | Salida de rclone para el usuario: 2a copy / check · 2b Tag Manager | **2a hecho** (`cc17aa7`, `5d11c22`); **2b implementado** (pendiente de commit y de la prueba manual) |
| PR 3 | Montajes con rclone (MinIO y NetApp): verificación real y errores de rclone al log técnico | **Implementado** (pendiente de commit, de la prueba manual y de Windows) |
| PR 4 | Referencia en cada error y exportación de los logs | Pendiente (plan revisado el 2026-11-03) |
| PR 5 | Migración de `print` al logger y limpieza del contenido | Pendiente |
| PR 6 | Documentación (`docs-update`) | Pendiente |

## Objetivo

1. **Log técnico (desarrolladores)**: todo lo que sale por terminal en desarrollo, completo y con formato fijo
   (hora con ms, nivel, módulo), igual en las dos apps. Escritorio → carpeta estándar del SO, un fichero por
   sesión, se conservan 30. Open OnDemand → solo stdout, que es el `output.log` de la carpeta de la sesión.
2. **Mensajes al usuario (UI)**: lenguaje de un investigador de biología, en inglés (idioma de la UI), con el
   vocabulario de `docs-local.md` (MinIO, NetApp/Z, "copy") y qué puede hacer cuando hay solución.
3. **Salida de rclone integrada**: la salida cruda va al log técnico; lo que importa al usuario (progreso,
   fichero copiado o fallido, resumen, montaje correcto o fallido, diferencias del check) se traduce y se
   muestra en la UI y en los **informes de operación**.
4. **Acceso fácil a los logs**: código de referencia en cada error y, en escritorio, botón "Export logs…" (zip
   de las 5 últimas sesiones para enviar a ITS). En OOD, informes en la carpeta de la sesión, junto a
   `output.log`. (Revisado el 2026-11-03: ver el PR 4.)

Decisiones tomadas: fichero por sesión (se conservan 30); carpeta estándar del SO con helper propio, sin
dependencias nuevas; informes de OOD en la carpeta de la sesión; soporte por sistema de tickets.

## Arquitectura

```text
                 ┌──────────────── log técnico (logger "bifrost.*") ──────────────┐
print()/logger ──┤ escritorio: <carpeta SO>/<app>/bifrost-<app>-<fecha>.log        │  formato fijo
warnings ────────┤ web OOD:    stdout → ./output.log                                │  + filtro de secretos
rclone (crudo) ──┤                                                                  │
                 └──────────────────────────────────────────────────────────────────┘
rclone (JSON) ──► rclone_output.RunSummary ──► líneas para el usuario ──► panel UI + informe de operación
                                │
                                └─► UserIssue (catálogo) ──► diálogo con referencia + botones
rclone mount ──► fichero temporal rclone/<tipo>-<nombre>.log (JSON, solo errores) ──► si falla: causa → UserIssue
                                │
                                └─► al desmontar o si falla: errores sin nombres ──► log técnico [bifrost.rclone],
                                    y se borra el fichero
```

| Sistema | Log técnico | Informes (PR 2) | Ficheros temporales de los montajes (PR 3) |
|---|---|---|---|
| macOS | `~/Library/Logs/BIFROST/<app>/` | `…/<app>/reports/` | `…/<app>/rclone/` |
| Windows | `%LOCALAPPDATA%\IRB\BIFROST\<app>\` | `…\reports\` | `…\rclone\` |
| Linux escritorio | `$XDG_STATE_HOME/bifrost/<app>/` (por defecto `~/.local/state/…`) | `…/reports/` | `…/rclone/` |
| OOD (web) | stdout → `./output.log` | `$BIFROST_SESSION_DIR/reports/` | `$BIFROST_SESSION_DIR/rclone/` |

Los ficheros de `rclone/` solo existen mientras el montaje está activo: al desmontar, sus errores pasan al log
técnico y se borran (ver PR 3, decisión del 2026-11-03).

Si `BIFROST_SESSION_DIR` no está definida (web en local), se usa la carpeta del SO. Los logs antiguos
(`~/bifrost-mount-logs/`, `~/bifrost-logs/`) no se borran.

Dónde va la información útil de rclone:

| Información | Dónde la ve el usuario | Dónde queda guardada |
|---|---|---|
| Carpeta montada o no, y por qué | estado del botón + diálogo con referencia | log técnico (causa y errores de rclone, sin nombres) |
| Progreso de la copia (comparando / copiando, ficheros, tamaño, velocidad, tiempo restante) | bloque de progreso encima del log, una vez por segundo | log técnico (una línea de stats cada 60 s) |
| Fichero o carpeta que no se pudo copiar y por qué | al final, en el panel: **solo el número por causa**, sin nombres | informe: lo que mostró el panel + lista de ficheros con su causa (máx. 100) |
| Ficheros ya idénticos en MinIO (no copiados, sus etiquetas no cambian) | al final, en el panel: el número | informe (lo mismo que el panel) |
| Resumen final (copiados, fallidos, qué hacer) | bloque final del panel | informe |
| Check: idénticos / faltan en MinIO / distintos / no comparados / con error | resumen en el panel, solo números | informe: lo que mostró el panel + distintos e ilegibles con su causa (máx. 100) |
| NetApp (Z) montado o no, y por qué | estado de la fila + diálogo al pulsar "Error" | log técnico (causa y errores de rclone, sin nombres) |
| Error al listar carpetas | texto de error del navegador, traducido | log técnico |
| Etiquetas aplicadas o error de MinIO | panel LOGS del Tag Manager (recuentos) + pop-up si falla | informe `tags-<fecha>.log` (máx. 100 ficheros con problemas) |

## Fase 0 — resultados (rclone 1.72.1, Hypercorn 0.18.0)

**Qué está documentado y qué no.** Documentado (estable): los campos del log JSON (`level`, `msg`, `source`,
`time`; `object`/`objectType` si se refiere a un elemento; `size` en las copias; `stats` igual que
`core/stats`), los símbolos de `--combined` de `rclone check` y los códigos de salida
(https://rclone.org/docs/, https://rclone.org/commands/rclone_check/). **No documentado**: el texto de los
mensajes (`file not in …`, `Attempt N/M failed`, `N files missing`) y cómo rclone envuelve los errores de
MinIO (`StatusCode: 403 … api error …`, de la librería de AWS). El parser se apoya en lo documentado para
funcionar y usa los textos solo para traducir el error al usuario, con `UNEXPECTED` si no lo reconoce.
**Al actualizar rclone, repetir estas pruebas** y revisar el catálogo.

- **JSON de rclone** (`--use-json-log`): cada línea trae `time`, `level` (`info`/`notice`/`error`), `msg`,
  `source` y, si se refiere a un elemento, `object` + `objectType`. Cada fichero copiado sale como
  `Copied (new)` con `size`. Las estadísticas llegan cada segundo como línea `notice` con la clave `stats`:
  `bytes`, `totalBytes`, `transfers`, `totalTransfers`, `errors`, `speed` (float), `eta` (int **o null**),
  `elapsedTime`, `lastError`, `fatalError`, `retryError`. En `check` la línea final de stats es `info`.
- **Reintentos**: rclone repite la operación hasta `--retries` veces (3 por defecto). Cada intento vuelve a
  registrar `Failed to copy` del mismo fichero y termina con `Attempt N/M failed with K errors…` (sin
  `object`). Hay que deduplicar por fichero, y los fallidos reales son los del **último** intento.
- ~~`stats.transfers` incluye los fallidos~~ **Corregido (2026-10-21):** `transfers` cuenta solo las copias
  terminadas sin error; depende de cuándo falla el fichero. Los copiados se cuentan con las líneas `Copied (` y,
  para los ficheros grandes que rclone copia por partes, `Multi-thread Copied (` (comprobado con
  `--multi-thread-cutoff 1M --disable Copy` entre carpetas locales).
- Error de la carpeta raíz: `objectType` acaba en `.Fs` y `object` es "Local file system at …". No es un
  fichero fallido; solo se guarda como primer error.
- Origen inexistente → rc 3 (`directory not found`). Fichero ilegible con `--checksum` → `…: permission
  denied`, rc 1.
- `--combined` con `--one-way`: `=` idéntico, **`+` solo en el origen (falta en MinIO)**, `*` distinto, `!`
  error al leer; `-` (solo en el destino) no aparece. Con diferencias, rc 1.
- `rclone mount` con un error termina enseguida (rc 1) y deja en `--log-file` una línea de texto
  `YYYY/MM/DD HH:MM:SS CRITICAL: …`. Se puede detectar con `poll()` + leer el final del log.
- ~~Hypercorn 0.18 con SIGTERM: cierre ordenado y `atexit` ejecutado. En web no hace falta manejador propio.~~
  **Corregido (2026-10-19):** solo es cierto si el SIGTERM llega al proceso padre. Hypercorn ejecuta la app
  en un hijo (`spawn`) al que pasa un `shutdown_event` y **no** le instala manejador de señales
  (`asyncio/run.py`, `if shutdown_trigger is None`). `scancel` (Delete en OOD) envía SIGTERM a todos los
  procesos del job, así que el hijo muere en el acto: sin `atexit`, sin limpieza y sin `APP shutdown`
  (comprobado en OOD). Hace falta un manejador de SIGTERM a nivel de módulo también en web (añadido en
  `common/shutdown.py`; en OOD real aún no se ejecuta, ver "Añadido después del cierre de la fase 1").
- **Registros anidados en Python 3.13.5** (el del cluster): `Logger.handle()` descarta los registros que se
  crean mientras otro se procesa en el mismo hilo. Hypercorn escribe en `sys.stderr` desde su propio handler y
  el redirector creaba un registro anidado, así que se perdía `Running on`. En 3.13.15 y 3.14 no pasa
  (comprobado con una reproducción mínima en las dos versiones). Arreglado: `_StreamToLogger` entrega el
  registro directamente a los handlers de `bifrost`, sin pasar por `Logger.handle()`.
- **Punto 4, errores reales de MinIO (2026-10-21, minio-archive):**
  - Claves no válidas y token de sesión falso → `StatusCode: 403 … api error InvalidAccessKeyId: The Access
    Key Id you provided does not exist in our records.` La regla `CREDENTIALS_EXPIRED` debe ir **antes** que
    la de permisos (el mensaje también contiene 403).
  - Servidor inexistente → `dial tcp: lookup …: no such host` (`NETWORK`).
  - MinIO escribe `StatusCode: 403` (sin espacio): el patrón de permisos pasa a `status ?code: 403`.
  - Para conectar con un remote al vuelo, el endpoint con puerto va entre comillas simples:
    `":s3,provider=Minio,endpoint='https://host:9000',…:"`.
  - `rclone check` contra MinIO (solo lectura, carpeta local → ruta inexistente en `its`): mismo formato que
    en local. Cada fichero que falta llega como `level=error` con `file not in S3 bucket …` (son diferencias,
    no fallos), `--combined` marca con `+` lo que falta en MinIO, y rclone escribe además líneas `notice`
    con los totales (`N files missing`, `N differences found`, `N errors while checking`), sobre el objeto
    `*s3.Fs`. Rc 1. **Check de un solo fichero** (sin `--combined`): esas líneas `notice` dan los totales
    para el resumen.
  - **No probados** (escriben en MinIO y con WORM no se puede deshacer): sin permiso de escritura y
    sobrescribir con WORM. Se usan los códigos S3 estándar (`AccessDenied`, `ObjectLocked`/`WORM`); según la
    configuración del WORM, sobrescribir puede crear una versión nueva en lugar de dar error. Probarlos solo
    en un destino preparado por quien administra MinIO.

## PR 1 — Log técnico común (hecho)

### Qué se hizo

**Nuevo `shared/bifrost_backend/common/logs.py`** (exportado en la fachada solo `setup_logging`):

- `log_dir(app)`: carpeta estándar del SO (tabla de arriba).
- `setup_logging(app, *, is_web, version)`: idempotente; devuelve la ruta del fichero o `None` en web.
  - Logger raíz `bifrost` (nivel DEBUG, sin propagar). Formato
    `%(asctime)s.%(msecs)03d %(levelname)-7s [%(name)s] %(message)s`.
  - Consola: nivel INFO en escritorio y DEBUG en web, configurable con `BIFROST_LOG_LEVEL`.
  - Escritorio: `FileHandler` DEBUG en `bifrost-<app>-<fecha>.log`; antes borra los antiguos hasta dejar 30.
  - `sys.stdout` → logger `bifrost.print` (INFO) y `sys.stderr` → `bifrost.stderr` (WARNING), línea a línea,
    con protección contra recursión y delegación de atributos (`encoding`, `fileno`, `buffer`…) al stream
    original.
  - **Paso directo de la línea de `flet run`**: `flet run` pasa `FLET_DISPLAY_URL_PREFIX` y espera en stdout
    la línea `PAGE_URL_…` sin modificar para abrir la ventana. Esas líneas se escriben tal cual.
  - `logging.captureWarnings(True)`: cada `DeprecationWarning` es un único registro `[py.warnings]`.
  - Filtro de secretos: JWT → `<jwt>`; `password=`, `secret_access_key=`, `session_token=`… → `<redacted>`.
    También quita saltos de línea finales.
  - `sys.excepthook` y `threading.excepthook` → registro CRITICAL con traceback.
  - Cabecera de sesión: app y versión, modo (`web`/`desktop`), `no_ldap`, pid, SO, arquitectura, Python,
    Flet, `log_file` y, en web, `session_dir`. **No** incluye la versión de rclone: consultarla al arrancar
    podía guardar `unknown` en caché para siempre (se usa en el user-agent).

**bifrost-mount**

- `main.py`: `backend.setup_logging("mount", …)` tras el bloque UTF-8; logger `bifrost.mount`. Se quita
  `APP start …` (lo dice la cabecera). Cierre: `APP shutdown — cleaning up` y
  `APP shutdown requested (reason=SIGTERM|SIGINT)`, una sola vez cada uno.
- `session_log.py` **eliminado**: solo tenía una función de una línea. `views/mount.py` y `main.py` usan
  `logging.getLogger("bifrost.mount")` directamente.

**bifrost-transfer**

- `main.py`: el `_TeeStream` y su rotación (`~/bifrost-logs/bifrost-console-*.log`) se sustituyen por
  `backend.setup_logging("transfer", is_web=IS_WEB, …)`; logger `bifrost.transfer`. `_cleanup_on_exit` es
  idempotente. Manejador de SIGTERM/SIGINT solo en escritorio. `import atexit` sube a los imports.

**Compartido**

- `views/login.py`: sin parámetro `log_event`; escribe en `bifrost.login` en las dos apps.
- `views/credentials.py`: sin parámetro `write_log` (duplicaba cada línea: su `print` ya llega al log).
- `mount/s3_mount.py`: `desmontar_punto_montaje` sin el parámetro `log_fn` (nadie lo pasaba) ni su envoltorio
  `_log`; usa `print` directamente.
- Errores que solo salían en pantalla y ahora también en el log técnico: `BUCKET list failed` (mount),
  `TAGS save failed` (logger `bifrost.tags`) y `UPDATE check failed` (logger `bifrost.update`).
- Corrección de tres closures que perdían la excepción: `ui_call` programa la función con `page.run_task`,
  y cuando se ejecuta Python ya ha borrado la variable del `except` → `NameError` en lugar del mensaje.
  Corregidos con `def _err(ex_val=ex)` en `bifrost-transfer/src/main.py` (credenciales SMB),
  `bifrost-mount/src/views/mount.py` (lista de buckets) y `shared/bifrost_frontend/views/update.py`.

**OOD** (submódulo `ood-app-bifrost`, commit propio): `template/script.sh.erb` exporta
`BIFROST_SESSION_DIR="$PWD"` y `PYTHONUNBUFFERED=1` antes del `cd`.

### Diferencias respecto al diseño inicial

- Las funciones `report_path`, `rclone_log_path`, `current_log_file`, `new_ref`, `open_in_file_browser` y
  `export_logs_zip` **no** se añadieron todavía: entran en el PR que las usa (abajo, con su código).
- `current_log_file()` necesitará que `setup_logging` guarde la ruta en una variable de módulo.
- `session_log.py`, `log_event`, `write_log` y `log_fn` eliminados en lugar de mantenerse como envoltorios.

### Cómo comprobarlo

- `flet run` en cada app: se abre la ventana; la terminal muestra la cabecera con
  `log_file=~/Library/Logs/BIFROST/<app>/bifrost-<app>-<fecha>.log`; `tail -f` de ese fichero muestra lo mismo.
- Login (bien y mal), montar/desmontar, renovación de credenciales: cada línea aparece una vez.
- Sin red (sin VPN **y** sin cable, si no MinIO sigue accesible desde la red del IRB): "Error loading
  buckets: …" en pantalla y `BUCKET list failed` en el log.
- Cerrar con la X o con Ctrl+C: `APP shutdown` una sola vez.
- OOD: `output.log` con líneas formateadas, `mode=web`, `log_file=stdout` y `session_dir=<carpeta de la sesión>`.

### Añadido después del cierre de la fase 1

- **App empaquetada** (`flet build`): el arranque de Flet manda stdout/stderr a su propio `console.log`, que
  solo usa para la pantalla "Error running app". Ahí la consola recibe solo avisos y errores (`_PACKAGED`):
  el log normal no se duplica y la pantalla sigue mostrando el traceback si la app falla al arrancar.
  `_ConsoleHandler` no escribe si ese fichero ya está cerrado (el `sys.exit` de Flet lo cierra al terminar).
- **Cierre de las apps** (`common/shutdown.py`, commit `feat(shutdown)`): una sola limpieza por proceso para
  `atexit`, señales y cierre de ventana, registrada al importar. En OOD el cierre al cancelar la sesión
  **sigue sin ejecutarse** (el worker de Hypercorn no parece recibir el SIGTERM de Slurm); como no es de
  logs, se sigue fuera de esta rama, en `Bifrost/PENDIENTES.md` (fuera del repo), junto con dos
  correcciones de la revisión de `shutdown.py`.

### Observado durante las pruebas (para PR 3 y PR 5)

- La salida de `rclone mount` (`NOTICE: … Symlinks support enabled`, `short read on fuse device`,
  `umount(...): Resource busy`) sale en la terminal pero **no** en el fichero: rclone escribe directamente en
  la consola heredada. → PR 3 (`--log-file`).
- `MOUNT success` de un intento anterior aparece **después** de `UNMOUNT ALL`: el bucle de espera da el
  montaje por bueno sin comprobarlo y deja el estado de la app mal. → PR 3.
- Ruido: `repr` de la conexión LDAP, `[debug matching]` línea a línea, listas de `Popen`. → PR 5.

## PR 2 — Salida de rclone para el usuario (copy / check / etiquetas)

> **Reescrito el 2026-10-21** tras una revisión adversarial del plan anterior (5 revisores con enfoques
> distintos y 2 verificadores por hallazgo). Tal como estaba, en muchos casos la app habría dicho al usuario
> algo falso sobre sus datos. Los problemas que ya existían y que la fase 2 no introduce están en
> `Bifrost/PENDIENTES.md` (fuera del repo), puntos 10-12: permisos de `rclone.conf`, el editor de etiquetas
> que puede borrar las existentes y aplicar etiquetas que sustituye las anteriores.

### Decisiones

- **Dos commits**: **2a — copy y check** (`rclone_output.py`, `copy_check.py`, `views/copy.py`, docs) y
  **2b — Tag Manager** (`tag_manager.py`, `s3_tags.py`, `rclone_ops.py`, textos y docs).
- **Informes en OOD**: carpeta de la sesión, `$BIFROST_SESSION_DIR/reports/`. La doc da dos caminos: el
  enlace "Session ID" de la tarjeta de la sesión y, si la tarjeta ya no está, la ruta en la app Files de OOD.
- **Los textos de los diálogos y mensajes de error entran en esta rama**, aunque no sean logs: forman parte
  de cómo se comunican los errores al usuario.

### Principios (de la revisión)

1. **No afirmar nada que no se pueda demostrar.** "copied" solo si rclone confirma la copia; "identical"
   solo si se comparó el contenido; si no se sabe, se dice. Un mensaje engañoso puede llevar a borrar el
   original.
2. **Funcionar con lo documentado de rclone** (nivel, `object`/`objectType`, `stats`, ficheros de informe del
   check, códigos de salida). El texto de los mensajes solo sirve para traducir el error al usuario.
3. **Clasificar solo el texto del error, nunca la ruta.** Una carpeta `worm_project` o `refused_cells` no
   debe convertirse en "WORM" o "FUSE".
4. **Un fallo del parser nunca corta la copia.** `feed` no lanza excepciones.
5. **Mínimo de datos personales.** El log técnico no guarda la lista de ficheros copiados (solo totales y
   los ficheros con error). Los informes solo guardan los ficheros con problemas, no el inventario completo.
6. **Pistas que se puedan seguir.** Hasta el PR 4 no existen ni "ticket" ni "referencia": la pista es
   "contact ITS and send them the report". Cada pista depende de la pantalla (copy / Tag Manager) y del modo
   (escritorio / Open OnDemand). Vocabulario del proyecto: MinIO (no S3), NetApp, copy (no transfer), sin
   "rclone".

### `common/logs.py` — se añade `report_path`

```python
_state: dict = {"app": None, "is_web": False}   # lo rellena setup_logging


def _data_dir(app: str) -> Path:
    """En OOD, la carpeta de la sesión (BIFROST_SESSION_DIR); si no, la carpeta de logs del SO."""
    session_dir = os.environ.get("BIFROST_SESSION_DIR")
    return Path(session_dir) if (_state["is_web"] and session_dir) else log_dir(app)


def report_path(kind: str, ext: str = "log") -> Path:
    """Ruta nueva para un informe de operación (copy, check, tags). Conserva 30 por tipo."""
    d = _data_dir(_state["app"] or "bifrost") / "reports"
    d.mkdir(parents=True, exist_ok=True)
    _prune(d, f"{kind}-*.{ext}", KEEP_SESSIONS)
    return d / f"{kind}-{datetime.now():%Y-%m-%d_%H-%M-%S}.{ext}"
```

- `_prune` debe tolerar que un fichero desaparezca entre el `glob` y el `stat` (`OSError`).
- En OOD cada sesión tiene su carpeta, así que "30 por tipo" limita **por sesión**. La retención real
  depende de si OOD limpia las carpetas de sesión: preguntar a quien administra OOD y documentarlo.

### `common/rclone_output.py` — diseño

**`UserIssue`** (`code`, `title`, `message`, `hint`) con pistas por contexto:
`issue.hint_for(screen: "copy"|"check"|"tags", is_web: bool)`. Por ejemplo, `CREDENTIALS_EXPIRED` en el Tag
Manager dice "Go ← Back to the copy screen, click 🔑 Renew credentials and come back" (allí no hay botón), y
`NETWORK` en Open OnDemand no habla de la VPN del portátil.

**`classify(error_text)`** recibe solo el texto del error:
- `error_text(msg, obj, roots)` sustituye en el mensaje el `object`, la raíz del origen y la del destino por
  marcadores y se queda con la parte final ("…: permission denied").
- Patrones con límite de palabra y orden de prioridad. `CREDENTIALS_EXPIRED` va antes que `MINIO_PERMISSION`
  (comprobado: `InvalidAccessKeyId` también trae `StatusCode: 403`).

**Catálogo** (títulos y pistas en inglés sencillo, sin "S3" ni "rclone"):

| Código | Reconoce | Qué ve el usuario (idea) |
|---|---|---|
| `CREDENTIALS_EXPIRED` | `ExpiredToken`, `InvalidAccessKeyId`, `InvalidTokenId`, `InvalidToken`, `SignatureDoesNotMatch` | MinIO access expired · renovar (según pantalla) |
| `MINIO_PERMISSION` | `AccessDenied`, `status ?code: 403` | No permission in this MinIO folder · pedir acceso al data manager |
| `BUCKET_NOT_FOUND` | `NoSuchBucket` | MinIO folder not found · elegirla de nuevo |
| `OBJECT_GONE` | `NoSuchKey` | The file is no longer in MinIO (Tag Manager) · recargar |
| `INVALID_TAG` | `InvalidTag`, `MalformedXML`, `InvalidArgument`, `BadRequest` | A tag value is not accepted by MinIO · acortarlo o quitar caracteres |
| `NETWORK` | `no such host`, `dial tcp`, `connection refused`, `i/o timeout`, `timed out`, `TLS handshake timeout`, `Could not connect to the endpoint`, `Connect timeout`, `Read timeout` | Connection problem (MinIO o el servidor SFTP de origen) · escritorio: VPN; OOD: reintentar más tarde y avisar a ITS |
| `CLOCK_SKEW` | `RequestTimeTooSkewed` | La fecha y hora del ordenador está mal |
| `MINIO_BUSY` | `SlowDown`, `ServiceUnavailable`, `InternalError`, `XMinioServerNotInitialized`, `status ?code: 50[234]` | MinIO is busy · reintentar en unos minutos |
| `DISK_FULL` | `no space left on device` | No hay espacio |
| `SOURCE_PERMISSION` | `permission denied`, `access is denied` (Windows) | Cannot read a file of the source |
| `FILE_IN_USE` | `being used by another process` (Windows) | Otro programa tiene el fichero abierto · cerrarlo |
| `SOURCE_CHANGING` | `corrupted on transfer`, `hashes differ` (en copy), `source file is being updated`, `size changed` | El fichero cambió mientras se copiaba · esperar a que el instrumento termine de escribir |
| `SOURCE_NOT_FOUND` | `directory not found`, `file not found`, `no such file or directory`, `cannot find the (file|path)` | El origen no existe (movido o renombrado) |
| `WORM_PROTECTED` | `ObjectLocked`, `\bWORM\b` | A file with the same name is already in this MinIO folder and cannot be replaced (sin "use a different name": la app no puede renombrar) |
| `RCLONE_OPTIONS` | rc 2 | The options in "Additional rclone flags (advanced)" are not valid · revisarlas o restaurar las de por defecto; se muestran las líneas `Error:` de rclone |
| `UNEXPECTED` | resto | Something went wrong · "Try again. If it keeps happening, contact ITS and send them the report saved at the end of this log." |

`MOUNT_BUSY` y `FUSE_MISSING` solo se usan en los montajes (PR 3), nunca al copiar.

**`issue_for_exception(ex)`** (para boto3 en el Tag Manager), que nunca lanza excepciones: lee el código de
`ex.response["Error"]["Code"]` solo si existe; si no, clasifica `str(ex)`; las clases de conexión de
botocore (`EndpointConnectionError`, `ConnectTimeoutError`, `ReadTimeoutError`, `ConnectionClosedError`,
`SSLError`) dan `NETWORK`. Si nada coincide, `UNEXPECTED`.

> El diseño de copy y check de esta sección es el original. Lo implementado y los cambios posteriores
> (recuentos en lugar de listas, informe = pantalla + ficheros con problemas, etc.) están en «Estado de 2a».

**`RunSummary` (copy)**, rediseñado:

- **Robustez**: `feed` ignora las líneas JSON que no son un objeto y envuelve todo en `try/except`; un fallo
  del parser se registra y devuelve `[]`.
- **Niveles**: `error`, `critical`, `fatal` y `emergency` cuentan como error. `critical` es lo que sale sin
  VPN o con las credenciales caducadas. Si no hay ninguno, se usan la última `notice` "Failed to …" o
  `stats.lastError`.
- **Ficheros copiados**: se cuentan con las líneas `info` cuyo `msg` empieza por `Copied (` o `Multi-thread Copied (`, por `object` y
  sin duplicar entre intentos. **No** se calcula como `transfers − fallidos`: comprobado que `transfers` no
  incluye los fallidos. `Copied (replaced existing)` se cuenta aparte con un aviso: "N file(s) replaced a
  different file with the same name in MinIO".
- **Nada que copiar**: `transfers == 0` sin errores → "✅ Nothing new to copy: the files were already in
  MinIO." (no "identical": el usuario puede haber puesto `--size-only`). Sin ficheros en el origen →
  "Nothing to copy: the folder is empty or everything was excluded."
- **Prueba (`--dry-run`/`-n`)**: si aparece en las opciones o en los mensajes ("Skipped copy as --dry-run is
  set") → "🧪 Test run: N file(s) would be copied. Nothing was copied to MinIO." Nunca "copied".
- **Carpetas ilegibles**: los errores con `objectType` que no es `*.Object` (p. ej. `string`) o con
  "failed to open directory" van a un grupo propio: "⚠️ Folder X could not be read: its files were NOT
  copied." Se muestran antes que nada. No cuentan como "1 file failed". Se añade el código de salida 6
  ("no se puede reintentar").
- **Reintentos**: durante los intentos no se pintan ❌ por fichero como si fueran definitivos. Se pinta una
  línea por intento: "⚠️ N file(s) failed in attempt 1 of 3 — trying again (files already copied are
  skipped)". La lista de fallidos se pinta **al final**, con los del último intento, como mucho 20 más "…and
  N more (full list in the report)". Si al final todo sale bien: "✅ … (some files needed another try)".
- **Cancelación**: no se deduce del código de salida. Comprobado: rclone sale con 143 en copias grandes, en
  Windows `terminate()` da 1 y solo a veces da −15. `do_cancel` pone `expose_proceso["cancelled"] = True`
  **antes** de terminar el proceso, y el resumen lo consulta primero: "⏹ Copy cancelled. Files already
  copied stay in MinIO." Se quita el "⚠️ Transfer cancelled by user." de `do_cancel`, que además decía
  "Transfer" también en el check.
- **Opciones no válidas (rc 2)**: se guardan las últimas líneas que no son JSON (como mucho 20, sin la
  ayuda de uso) y se enseñan las que empiezan por `Error:` junto con `RCLONE_OPTIONS`.
- **Progreso por fases**, solo con campos documentados de `stats`: mientras se compara antes de copiar
  (`--check-first`) → "⏳ Comparing with MinIO: N files checked"; al copiar → "⏳ Copying: X of Y files · …".
  Nunca "0 of 0 files". `totalChecks` crece durante la ejecución, así que en la comparación no se pone
  "de Y". Una línea cada 10 s en el panel.
- **Resultado**: `summary.outcome` ∈ `ok`, `nothing_to_copy`, `dry_run`, `partial`, `failed`, `cancelled`.
  Lo usan el resumen, el informe y el estado de la sesión web.

**Check (`RunSummary(operation="check")`)**:

- En lugar de `--combined` (que guarda también los ficheros idénticos, es decir, el inventario completo)
  se usan `--missing-on-dst`, `--differ` y `--error`, en ficheros temporales que solo contienen rutas con
  problemas. Se leen línea a línea, sin cargarlos enteros en memoria.
- Totales a partir de las `notice` de rclone: `N matching files`, `N files missing`, `N differences found`,
  `N errors while checking`, `N hashes could not be checked`. Como se solapan:
  - faltan en MinIO = `files missing`;
  - distintos = `differences found` − `files missing`;
  - errores de lectura = `errors while checking` − `differences found` (si es > 0);
  - idénticos = `matching files`.
- **Solo es una diferencia** un `level=error` sobre un fichero (`objectType` `*.Object`) cuyo texto sea de
  diferencia conocida (`file not in`, `sizes differ`, `hash… differ`). Cualquier otro error (sobre todo si
  `object` está vacío, es del `Fs` o es `critical`) significa que **el check no pudo terminar**: "❌ The check
  could not finish — {title}", sin presentar recuentos como si fueran fiables. Así se cubre que no se pueda
  listar la carpeta de MinIO, que con `--combined` marcaba todo como "missing".
- **Sin checksum común** ("No common hash found", "N hashes could not be checked"): no se dice
  "identical", sino "N file(s) have the same size but their content could not be compared".
- **Carpetas ilegibles del origen**: "Folder X could not be checked".
- **Check de un solo fichero**: los mismos totales de las `notice`.
- El código de salida no decide por sí solo: 1 con 0 faltan y 0 distintos y errores de lectura → "could
  not read the file", no "differences found".
- Texto final propio del check ("✅ Check finished: all N files are in MinIO and identical", "⚠️ Check
  finished: N missing in MinIO · N different · …", con qué hacer en cada caso). Nunca "Copy finished".
- Progreso: "⏳ Comparing files with MinIO: N checked".

### 2a — `shared/bifrost_backend/transfer/copy_check.py`

- Flags: quitar `--progress` y `--stats=1s`; añadir `--use-json-log --log-level INFO --stats 1s
  --stats-log-level NOTICE`. **Nada de esto cambia qué se copia ni cómo**: solo el formato de la salida. Se
  mantienen `--checksum --check-first --copy-links` y las exclusiones.
- **`summary` y `proceso = None` se crean antes del `try`**, y todo lo que puede fallar va dentro:
  `get_rclone_executable`, `preparar_origen_para_check` y los ficheros temporales del check. Si no se pueden
  crear los ficheros del check, se sigue sin ellos y se avisa. **`on_finish(summary)` se llama siempre**
  (desde el `finally`) y con un resumen válido. Hoy, si algo falla antes de lanzar rclone, la UI se queda en
  "running".
- El comando completo va al log técnico (INFO), con el **valor** de la cabecera `x-amz-tagging` sustituido
  por las claves de las etiquetas: los valores son metadatos personales y ya van en el informe.
- **Log técnico (principio 5)**: no se escribe una línea por fichero copiado. Solo los errores por fichero
  (necesarios para soporte), los totales y una línea de `stats` cada 60 s, no cada segundo.
- Las líneas que no son JSON van al log técnico y se guardan para el caso rc 2.

### 2a — `bifrost-transfer/src/views/copy.py`

- **Validar "Additional rclone flags (advanced)" antes de lanzar** `do_copy` o `do_check`. Se rechazan, con
  un diálogo "This option can't be used here", las opciones que controlan el log o la salida o que pueden
  volcar secretos: `-v*`, `-q`, `--verbose`, `--quiet`, `--log-*`, `--use-json-log`, `--stats*`, `-P`,
  `--progress`, `--dump*`, `--config`, `--combined`, `--missing-on-*`, `--differ`, `--match`, `--error`,
  `--header*`, y cualquier opción cuyo nombre contenga `secret`, `token`, `pass` o `key`. Las opciones
  normales (`--transfers`, `--checkers`, `--s3-no-check-bucket`…) siguen funcionando.
- **Informe por operación**: cada `do_copy`/`do_check` crea su propia lista `op_lines` y un envoltorio
  `op_log` que añade a la lista y llama a `_dispatch_log`. El informe se escribe en `on_finish`, a partir
  de una cabecera fija (origen, destino, etiquetas, inicio y fin, resultado), `op_lines` y la lista
  completa de ficheros con problemas del `RunSummary`. **No** sale del buffer web (que mezcla operaciones y
  pierde las primeras líneas al llegar a 5000) ni de los controles de la UI (en escritorio, las últimas
  líneas aún no han llegado cuando se guarda).
- `_autosave_log` también en escritorio, con `report_path("copy"|"check")`. Se borra su rotación propia (el
  `glob("bifrost-*.log")` borraba también otros logs). Al terminar, el panel muestra "📄 Report saved: <ruta>".
- **"Save log"**: en web, a `report_path()`; en escritorio, el selector de fichero de siempre.
- **Estado de la sesión web**: `copy_proceso["status"]` (compartido por referencia entre páginas; el antiguo
  `copy_status` se copiaba por valor en cada `_ws_save`) toma el `outcome` del resumen, y `_replay` tiene un texto para
  cada caso. Hoy un check con diferencias sale como "✅ Process finished" y una cancelación como "ended with
  errors". Los textos de reconexión dejan de remitir a `~/bifrost-logs/`.
- Quitar la línea duplicada `_cancelling: list = [False]`.
- Diálogo "Renew S3 Credentials" (`copy.py:118`; también `mount.py:336`) → "Renew MinIO access", por
  vocabulario.

### 2a — Documentación (en el mismo commit)

- `docs/user/transfer-data.md`: los posibles resultados de la copia (copiado, nada nuevo, con problemas,
  carpeta ilegible, cancelado, prueba) y del check (idéntico, falta en MinIO, distinto, no comparado por
  falta de checksum, no se pudo terminar), con **qué hacer** en cada caso. Dónde está el informe en cada
  sistema (`~/Library/Logs/BIFROST/transfer/reports/`, que Finder oculta; `%LOCALAPPDATA%\IRB\BIFROST\
  transfer\reports\`; `~/.local/state/bifrost/transfer/reports/`; en OOD, la carpeta de la sesión).
  "Save log" y Cancel.
- `docs/user/troubleshooting.md` ("I lost the log of a copy") y `docs/user/web-mode-ood.md` ("Logs"): los
  dos caminos en OOD (enlace "Session ID" y la ruta
  `~/ondemand/data/sys/dashboard/batch_connect/<sys|dev>/<app>/output/<session id>/reports/` en la app
  Files). Avisar de que los informes contienen nombres de ficheros.
- Doc de desarrollo y de agentes (`docs/development/operations.md`, `frontend.md`, `docs/agent/frontend.md`):
  quitar `~/bifrost-logs/` y `~/rclone-combined-check.txt` como sitios de guardado y explicar `reports/`.

### 2b — Tag Manager (`views/tag_manager.py`, `transfer/s3_tags.py`, `transfer/rclone_ops.py`, `bifrost_frontend/components.py`)

> Revisado el 2026-10-23 para seguir lo decidido en la 2a: en pantalla, recuentos; nombres de ficheros solo en
> el informe (máximo 100); informe = lo que mostró la pantalla + ficheros con problemas; log técnico sin
> nombres, rutas ni valores de etiquetas.

**Qué falla hoy (comprobado en el código)**

1. El panel dice "✅ N object(s) tagged successfully" aunque fallen ficheros: `apply_tags_to_prefix` cuenta los
   fallos pero no los devuelve.
2. Escribe una línea `✓ <fichero>` por cada objeto en el panel (100.000 ficheros, 100.000 líneas).
3. `_autosave_tag_log` guarda en `~/bifrost-logs/` (también en OOD) todo lo acumulado desde que se abrió la
   pantalla, no la operación; no usa `report_path`.
4. Guardar las etiquetas de un fichero no deja ningún registro y el error sale en crudo (`❌ Error: <excepción>`).
5. `list_prefix_contents` y `rclone_list_files_only` devuelven `[]` si fallan: un error parece una carpeta vacía.
6. Aplicar a una carpeta lista todos los objetos en memoria antes de empezar, no se puede parar y, sin red,
   cada objeto agota los reintentos de botocore (5 intentos, 60 s de espera) en 8 hilos: puede quedarse horas
   sin conseguir nada y sin decirlo.
7. Pendiente 11: si falla la lectura de las etiquetas de un fichero, el editor sale vacío con Save activo, y
   guardar sustituye las etiquetas que tenía (se pierden sin registro).
8. Textos en español: "Caracteres no permitidos en los tags" (dos diálogos), "Ver tags raw" y
   "📁 Bulk Prefix S3/MinIO".

**Decisiones (2026-10-23)**

- El pendiente 11 entra en la 2b, con la opción A: el editor no se abre sin haber leído las etiquetas.
- El pendiente 12 (aplicar sustituye todas las etiquetas del fichero) se queda como está, también el texto.
- Se escriben y se muestran todas las etiquetas del perfil, también las vacías, como en copy.
- Los avisos de error son pop-ups, sin listar ficheros, con un `show_issue` que se crea ya y que el PR 4
  amplía.
- El panel LOGS está siempre visible y todas las operaciones dejan rastro con la ruta completa del informe.
- Aplicar a una carpeta: botón Cancel, por páginas de 1.000 y parar ante errores generales.

**Errores (`common/rclone_output.py`)**

- `issue_for_exception(ex)`, que nunca lanza: usa `ex.response["Error"]["Code"]` si existe; las clases de
  conexión de botocore (`EndpointConnectionError`, `ConnectTimeoutError`, `ReadTimeoutError`,
  `ConnectionClosedError`, `SSLError`) dan `NETWORK`; si no, `classify(error_text(str(ex)))`; si nada,
  `UNEXPECTED`.
- Catálogo nuevo: `OBJECT_GONE` (`NoSuchKey`: "This file is no longer in MinIO") e `INVALID_TAG`
  (`InvalidTag`, `MalformedXML`, `InvalidArgument`, `BadRequest`: "A tag value is not accepted by MinIO").
- Pista según la pantalla: `hint_for(is_web, screen="copy"|"tags")`. En el Tag Manager no hay botón de
  renovar: para `CREDENTIALS_EXPIRED` y `PROFILE_MISSING` la pista es "Go ← Back, click 🔑 Renew credentials
  and open Tag Manager again."

**Pop-up: `show_issue` en `bifrost_frontend/components.py`**

- `show_issue(page, issue, *, is_web, title=None, context="", actions=None)`: título, contexto (el fichero
  seleccionado o un recuento; nunca listas), mensaje del `UserIssue`, "What you can do" y los botones que pase
  quien la llama. Se apoya en `show_dialog(actions=…)`, que ya existe.
- El PR 4 añade dentro `ref`, "Copy details" y "Open logs folder"; las llamadas del Tag Manager no cambian.

**Editor de un fichero (pendiente 11, opción A)**

- `_select_file` lee las etiquetas **antes** de abrir el editor:
  - lectura correcta → editor normal y `sel["tags_loaded"] = True`;
  - `NoSuchKey` → pop-up "This file is no longer in MinIO" con **OK**, y se recarga la lista;
  - otro error → pop-up "Could not read the tags of this file" con el fichero, el error traducido y qué hacer,
    y los botones **Cancel** y **Try again**. Try again vuelve a leer. Cancel quita la selección (el panel
    derecho vuelve a "Select a folder or a file"). El editor no se abre y "Apply tags" queda desactivado para
    ese fichero.
- `_on_save_file_tags` y `do_apply` sobre un fichero comprueban `sel["tags_loaded"]` antes de escribir.
- Se quita la línea roja del panel izquierdo (`browser_error`) para este caso.
- No se añaden reintentos: botocore ya hace 5.

**Panel LOGS siempre visible (como en la pantalla de copia)**

- Cada operación tiene su lista de líneas (como `_new_operation` en copy). Al terminar se escribe su informe y
  la línea "📄 Report saved: <ruta completa>".
- Función común `write_report(kind, lines, problems)` en `common/logs.py`, usada por copy, check y el Tag
  Manager. Sustituye `_write_report` de copy y `_autosave_tag_log`. Se quitan `_log_buffer` y
  `~/bifrost-logs/` como destino.
- En LOGS puede salir el nombre del fichero que el usuario ha seleccionado (como el origen en copy); nunca
  listas de ficheros de una carpeta.

| Operación | En LOGS | Informe `tags-<fecha>.log` | Pop-up |
|---|---|---|---|
| Guardar las etiquetas de un fichero | Resultado y ruta del informe | Fichero, etiquetas que tenía, etiquetas nuevas y resultado | Solo si falla |
| Aplicar a una carpeta | Etiquetas, recuentos y ruta del informe | Lo del panel + `--- Files with problems ---` (máximo 100, con su causa) | Si hay fallos o se para |
| No se pueden leer las etiquetas de un fichero | "⚠️ Could not read the tags of <fichero> — <título>" | No (no se ha cambiado nada) | Sí |

Ejemplo en escritorio (macOS):

```text
### Tags applied at 2026-10-23 10:20:41 ###
📄 File: test-logs/documento.txt
✅ Tags set on 1 file.
📄 Report saved: /Users/nrodriguez/Library/Logs/BIFROST/transfer/reports/tags-2026-10-23_10-20-41.log

### Tags applied at 2026-10-23 10:25:02 ###
📁 Folder in MinIO: test/test-logs/ (all files inside)
Profile: IRB Standard
Tags:
  project_name: melanoma
  compute_node:
  sample_type: tissue
  …
⚠️ Tags set on 4,980 file(s) in 2 min. 20 file(s) could not be changed: 20 × No permission in MinIO.
   What you can do: Check that you chose the right folder. If you need access, ask your group's data manager.
   The list of these files is in the report.
📄 Report saved: /Users/nrodriguez/Library/Logs/BIFROST/transfer/reports/tags-2026-10-23_10-27-15.log
```

En OOD la ruta es la de la carpeta de la sesión: `<carpeta de la sesión>/reports/tags-<fecha>.log`.

**Aplicar a una carpeta**

- `apply_tags_to_prefix` trabaja **por páginas**: lista 1.000 objetos (`list_objects_v2`), los etiqueta
  (8 hilos) y pasa a la página siguiente. Empieza al momento y usa poca memoria con cualquier tamaño de carpeta.
- Devuelve un resultado: `ok`, `failed` (fichero → issue; en memoria hasta 10.000), `stopped` (motivo) y
  `total`.
- **Progreso**: una línea que se reescribe como mucho una vez por segundo, "Setting tags: N files done so
  far". Sin total ni porcentaje: no se sabe hasta el final.
- **Cancel** junto a Apply mientras dura la operación: deja de enviar ficheros y espera a los que están en
  curso.
- **Parar ante errores generales** (`threading.Event`): `CREDENTIALS_EXPIRED`, `NETWORK` y `CLOCK_SKEW`
  siempre; `MINIO_PERMISSION` si fallan los primeros 20 ficheros seguidos.
- **Finales posibles:**

| Final | En LOGS | Pop-up |
|---|---|---|
| Todo bien | "✅ Tags set on N file(s) in X min." | No |
| Algunos ficheros fallan | "⚠️ Tags set on N file(s)… M file(s) could not be changed: <recuento por causa>." | "Tags were not set on some files" + recuento + qué hacer + ruta del informe · **Cancel** / **Try again** |
| Se para por un error general | "❌ Stopped — <título>. N files have the new tags; the rest of the folder was not changed." | "Tags could not be set" + lo mismo + qué hacer + ruta del informe · **Cancel** / **Try again** |
| El usuario pulsa Cancel | "⏹ Stopped. N files have the new tags; the rest were not changed." | No |
| La carpeta no tiene ficheros | "No files found in this folder." | No |

- **Try again**: con fallos sueltos reintenta **solo esos** (si eran más de 10.000, vuelve a aplicar la carpeta
  entera y el pop-up lo avisa); tras una parada general vuelve a aplicar la carpeta entera (los ficheros ya
  hechos quedan igual). Con "MinIO access expired", el pop-up dice que hay que renovar las credenciales antes.
  **Cancel** cierra el pop-up.
- Log técnico: `tags finished: outcome=… total=… ok=… failed=… stopped=… duration=…s`; los errores, una vez
  por tipo y sin nombres ni rutas; de las etiquetas, solo los nombres de los campos (ya hecho).

**Listar carpetas y ficheros (`rclone_ops.py`)**: `list_prefix_contents` y `rclone_list_files_only` lanzan
`RuntimeError` como `rclone_lsd`, en lugar de devolver `[]`. El Tag Manager muestra el error traducido en el
navegador en lugar de "(empty content)". El hilo de `_async_load` pasa a `safe_thread`.

**Textos**: los dos "Caracteres no permitidos en los tags" → "Invalid characters in tags" (como en copy);
"Ver tags raw" → "Show raw tags"; "📁 Bulk Prefix S3/MinIO: …" → "📁 Folder in MinIO: {bucket}/{prefix} (all
files inside)".

**Docs**: `docs/user/tag-manager.md` (panel LOGS, informes, pop-ups, Cancel, Try again, qué hacer si sale
"MinIO access expired"; quitar "The app renews its MinIO access automatically", que solo pasa al iniciar
sesión), la sección de etiquetas de `troubleshooting.md`, `docs/development/operations.md` y `frontend.md`.

**Verificación de la 2b** (S3 simulado con moto o el Stubber de botocore, solo en el entorno de pruebas; nunca
escribir en MinIO WORM):

| Caso | Resultado esperado |
|---|---|
| Leer etiquetas falla (red, `AccessDenied`) | Pop-up con Cancel / Try again; el editor no se abre; guardar está bloqueado |
| El fichero ya no existe (`NoSuchKey`) | Pop-up "no longer in MinIO" y la lista se recarga |
| Guardar un fichero | Línea en LOGS con la ruta completa; informe con etiquetas anteriores y nuevas |
| Carpeta vacía | "No files found in this folder." |
| Carpeta de 2.500 ficheros (3 páginas) | "Tags set on 2,500 file(s)"; progreso "done so far" |
| Fallos parciales | Recuentos por causa; informe con máximo 100; Try again solo con los fallidos |
| Credenciales caducadas a mitad | Se para enseguida; pop-up con la pista de renovar |
| Cancel a mitad | "⏹ Stopped…", sin pop-up |
| Error al listar | Error traducido en el navegador, no "(empty content)" |
| Log técnico | Una línea final; sin nombres, rutas ni valores de etiquetas |

Al final, prueba manual de la usuaria en el bucket `test` (sin WORM).

### Estado de 2b (2026-10-23)

Implementado según la sección 2b. Diferencias y detalles respecto al diseño:
- `INVALID_TAG` solo reconoce `InvalidTag`: `InvalidArgument`, `BadRequest` y `MalformedXML` también salen en
  copy por otros motivos y el mensaje ("a tag value is not accepted") sería falso.
- `list_prefix_contents` pasa a `list_prefix_folders` y devuelve solo las subcarpetas (antes devolvía
  `(carpetas, [])`).
- Un fichero y una carpeta usan el mismo formato: cabecera "### Tags applied at …", "New tags:", resultado
  con el verbo "set" ("✅ Tags set on 1 file." / "✅ Tags set on N file(s) in …", "❌ Tags not set — …") y
  pop-up "Tags could not be set". Los botones siguen siendo "Save tags" (fichero) y "Apply tags →" (carpeta).
- Añadido a petición de la usuaria: debajo del nombre del fichero, "Uploaded to MinIO: <fecha>" (el
  `LastModified` del objeto, en hora local; no cambia al tocar las etiquetas). `get_object_tags` pasa a
  `read_object_tags`, que devuelve las etiquetas y esa fecha. Se descartó guardar la fecha del último cambio
  de etiquetas como una etiqueta más: Histopathology ya usa las 10 que permite MinIO, rompería la detección
  del perfil y solo sería cierta si todo cambio pasara por BIFROST.
- Piezas comunes nuevas: `write_report()` (copy, check y tags), `show_issue()` (base del diálogo del PR 4),
  `log_text()` (color de las líneas de log en copy y Tag Manager), `by_cause()` y `duration_text()`.
- Limpieza en `tag_manager.py`: estado que solo se escribía (`right_panel`, `sel["count"]`,
  `sel["display"]`), el `profile_dd` duplicado, las referencias indirectas a botones, la rama de "aplicar a
  un fichero" de `do_apply` (el botón no se ve con un fichero seleccionado) y los `print`, que pasan al logger
  `bifrost.tags`.

Probado sin MinIO real: lógica de `s3_tags` con un cliente S3 simulado y las excepciones reales de botocore
(24 casos: páginas, fallos parciales, paradas por credenciales, red y permiso, Cancel, listado que falla,
carpeta vacía, progreso, traducción de errores, log sin nombres) y la pantalla con una página Flet simulada
(21 casos: pop-ups, editor bloqueado sin lectura, Try again, informes, LOGS, Cancel). Copy y check siguen
igual (30 salidas reales de rclone) y las dos apps arrancan. Falta la prueba manual en el bucket `test`.

### Estado de 2a (2026-10-21)

Implementado según el diseño de arriba y probado con rclone 1.72.1 en local (todos los casos de la tabla de
verificación salvo los de MinIO real y el Tag Manager). Una revisión independiente del código encontró y se
corrigió:
- **Cancelar y volver a copiar enseguida mezclaba las dos operaciones**: Copy/Check siguen desactivados hasta
  que la operación termina de verdad, y el proceso solo se libera del estado compartido si es el suyo.
- **En web, el resultado podía quedar en un diccionario de sesión antiguo** (`copy_status` se copiaba por
  valor en cada `_ws_save`): ahora vive en `copy_proceso["status"]`, compartido por referencia.
- `--syslog`, `-i`/`--interactive` y opciones cortas agrupadas (`-vP`) bloqueadas; rclone se lanza con
  `stdin` cerrado; sin ninguna salida de rclone el resultado es "failed", nunca ✅.
- Códigos de salida 8 y 10 (límites) con mensaje propio y 9 (`--error-on-no-transfer`) como "nada nuevo".
- Check sin nada que comparar: no dice "all 0 files identical".

Cambios del 2026-10-22, tras las pruebas en `minio:test`:
- **El log no afirma etiquetas que no se han puesto.** Al repetir una copia con otros metadatos, los
  ficheros idénticos se saltan y conservan sus etiquetas, pero el panel mostraba `### Metadata ###` con los
  valores nuevos. Ahora el bloque se titula "Tags for the files copied in this run" y el resumen dice cuántos
  ficheros ya estaban y no cambiaron. El dato sale de `rclone copy --match` (rclone anota la decisión que ya
  toma; sin lecturas ni peticiones extra). Se descuentan los copiados en un intento anterior.
- **Nombres de ficheros solo en el informe**: con copias masivas las listas podían tener miles de líneas. El
  panel da recuentos por causa y dice que la lista está en el informe; el informe guarda lo que mostró el
  panel y, debajo, los ficheros con problemas (no copiados, carpetas ilegibles, sustituidos, distintos,
  ilegibles) con su causa, hasta 100; el log técnico escribe cada tipo de error sin nombres ni rutas. Los que
  faltan en MinIO no se nombran nunca. Copy muestra origen y destino como check y todas las etiquetas del perfil (también las vacías, que
  también se escriben en cada fichero). Check no guarda listas en memoria.
- **Tamaño, duración y método**: el resumen dice cuántos ficheros y cuántos datos se copiaron, en cuánto
  tiempo y a qué velocidad media; check dice cómo comparó ("compared by MD5 checksum"); tras una copia
  correcta se sugiere "✓ Check data". El log técnico termina con una línea completa (`log_line()`): bytes,
  intentos, duración, velocidad y huella usada. Todo sale de la salida de rclone, sin coste extra.
- **Listas por fichero y disco temporal** (comprobado con un disco de 1 MB): si rclone no puede crear la
  lista aborta la operación, y si se llena a mitad la corta sin avisar. Con menos de 100 MB libres se
  trabaja sin listas; los recuentos de check salen de los totales de rclone; copy solo da el número de
  "ya estaban" si es fiable; se borran restos de más de 7 días.
- **Log técnico en el navegador y el Tag Manager**: dejan de escribir listados de buckets, carpetas y
  ficheros (solo recuentos) y los valores de las etiquetas aplicadas (solo los nombres de los campos).
- **Mensaje de los ya idénticos**: el número va en "Files in this copy: N copied · M already in MinIO" (o en
  "Nothing new to copy: the M file(s)…") y debajo "⚠️ Files already in MinIO were not copied again, so their
  tags were NOT updated: if their tags in MinIO are different from the ones above, they still have the old
  ones. To change them, use Tag Manager." No se afirma que las etiquetas sean distintas: rclone no las mira y
  comprobarlas costaría una petición por fichero. Si no se sabe si había alguno (reintentos sin lista
  fiable), el aviso empieza por "If some files were already in MinIO…".

### Para el PR 4 (anotado aquí para no perderlo)


- ~~`export_logs_zip` no debe incluir por defecto los informes~~ **Decidido el 2026-11-03 (PR 4):** el zip
  lleva las 5 últimas sesiones y, en transfer, los informes de copy, check y Tag Manager de esas sesiones; una
  confirmación antes de exportar dice qué contiene (nombres de ficheros y valores de etiquetas). Zip con
  permisos 0600.

### Pendiente de decidir

- **Ficheros antiguos**: `~/rclone-combined-check.txt` (inventario completo del último check, nombre fijo
  que solo escribía la app) y `~/bifrost-logs/`. ¿Se borran al arrancar, se dejan o se documentan?

### Verificación de 2a y 2b

Cada caso se reproduce en local con el rclone 1.72.1 del repo (carpetas temporales y `:memory:`; nunca
escribir en MinIO) y se pasa por el parser real:

| Caso | Resultado esperado |
|---|---|
| Copia correcta | "✅ Copy finished: N copied" con N = líneas "Copied (" |
| Repetir una copia ya hecha | "Nothing new to copy…", no "0 copied" |
| Un fichero ilegible (`chmod 000`), con reintentos 1 y 3 | recuento correcto; un solo ❌ al final; ninguno durante los intentos |
| Fichero que falla en el intento 1 y luego funciona | sin ❌ en el panel; "(some files needed another try)" |
| Subcarpeta ilegible | "Folder X could not be read…", no "1 failed" |
| Origen inexistente | "The copy could not finish — Source not found" |
| Cancelar una copia grande (multi-thread) y una pequeña | "⏹ Copy cancelled…" en los dos (rc 143 y −15) |
| `--dry-run` en las opciones | "🧪 Test run…", nunca "copied" |
| `--bogus`, `-v`, `--dump headers` en las opciones | diálogo de opción no permitida; rclone no se lanza |
| Carpeta llamada `worm_project` o `refused_cells` con un fichero ilegible | "Cannot read a file", no WORM ni FUSE |
| Destino con mismo nombre y otro contenido | aviso de "replaced" |
| Check idéntico / con un fichero que falta / con uno distinto / un solo fichero | totales correctos y textos de check |
| Check con el destino ilegible | "The check could not finish", no "N missing" |
| Check sin checksum común (`:chunker,hash_type=none:`) | "content could not be compared", no "identical" |
| Copia y check con `level=critical` (remote mal configurado) | error clasificado, no "Something went wrong" |
| Línea JSON que no es un objeto (`[]`, `null`) | ignorada, la copia sigue |
| Dos operaciones seguidas | dos informes separados, cada uno solo con lo suyo |
| `report_path` sin permiso de escritura | la operación termina y avisa; la UI no se queda en "running" |
| Web: cerrar la pestaña en medio y volver (copia, check con diferencias, cancelación) | texto de reconexión correcto para cada resultado |
| Tag Manager: claves falsas, sin red, 0 ficheros, fallos parciales | resumen real; se para ante errores generales; sin inundar el panel |
| Contra MinIO (solo lectura, como en la fase 0) | check de una carpeta local contra una ruta existente e inexistente |

Al final, prueba manual de la usuaria en la app con una carpeta pequeña en un destino de pruebas que elija.

**Hallazgos de la revisión que no se llegaron a verificar dos veces** (la revisión se paró a mitad):
carpeta ilegible del origen en el check, check sin hash común, solapamiento de totales del check, textos de
Windows, JSON que no es objeto, "replaced existing" y lectura del `--combined` en memoria. Están
incorporados arriba, y la tabla de verificación los comprueba al programar.

## PR 3 — Montajes con rclone (MinIO y NetApp)

> Revisado el 2026-10-23 contra el código y lo decidido en la 2a y la 2b (errores traducidos con
> `UserIssue`/`issue_for_exception`, pop-ups con `show_issue`, log técnico sin nombres de ficheros).

**Dónde se monta**

- **Buckets de MinIO**: Bifrost Mount, en escritorio (macOS con fuse-t, Windows con WinFsp, Linux con FUSE).
- **Shares de la NetApp**: Bifrost Transfer **solo en modo web** (OOD, Linux): el botón "⊞ Mount NetApp" solo
  aparece con `IS_WEB` (`views/copy.py`). El código de Windows para la NetApp (letras de unidad, `--volname`,
  `taskkill`) no se usa en la práctica; no se toca en este PR.

**Qué falla hoy (comprobado en el código)**

1. **Bifrost Mount dice "✅ Mounted!" aunque el montaje falle.** La espera de `do_mount` comprueba
   `os.listdir(carpeta)`, pero en macOS/Linux la carpeta se crea vacía *antes* de montar, así que pasa al
   instante; y si pasan los 30 s sin éxito lo da por montado igualmente y abre Finder. Con las credenciales
   caducadas, el usuario ve "Mounted!" y una carpeta vacía.
2. Cualquier `EnvironmentError` sale con el título "FUSE / WinFSP not detected" (también "No folder selected"
   o "Mount point already exists"); el resto, en crudo (`str(ex)`).
3. La carpeta de montaje se calcula dos veces con reglas distintas (`mount_rclone_S3_prefix_to_folder` quita
   las barras finales; `resolver_mount_point_destino` no). La función de montar no devuelve nada.
4. **Pendiente 4**: después de "Unmount all", el estado de los montajes queda desfasado (un montaje que
   "termina" tarde vuelve a marcarse como montado).
5. La salida de `rclone mount` va a la consola heredada (terminal o `console.log` de Flet), no a un fichero.
6. **NetApp**: el share se apunta en `mounts_activos` *antes* de saber si se montó; si falla, copy y check
   siguen traduciendo rutas con un montaje que no existe.
7. **NetApp**: la salida de rclone va a `DEVNULL` (no se sabe por qué falla) y siempre espera 30 s aunque rclone
   haya terminado al primer segundo (contraseña mal, sin red): no mira si el proceso sigue vivo.
8. **NetApp**: la fila del share solo dice "Error".
9. **Windows, Bifrost Mount**: en "Unmount all", si un desmontaje lanza un error, el último recurso es
   `taskkill /F /IM rclone.exe`, que cierra **todos** los rclone del usuario (también una copia de Bifrost
   Transfer). En la práctica casi nunca se ejecuta: el desmontaje ya captura casi todos los errores.
10. **Windows, Bifrost Mount**: un bucket que quedó montado de una sesión anterior cerrada de golpe se detecta
    al arrancar como "mounted", pero su proceso no está en `_s3_mount_processes`; al desmontar, en Windows no
    se hace nada y sigue montado aunque la pantalla diga que no.
11. Navegador de MinIO (`rclone_browser.py`) y lista de buckets de Bifrost Mount: "Error: <excepción>" y
    "Error loading buckets: <excepción>" en crudo.

**Decisiones (2026-10-23)**

- El pendiente 4 entra en este PR.
- Bifrost Mount sigue sin panel de log: los errores se muestran en pop-ups (`show_issue`) con la ruta del log
  técnico de la sesión ("Details:"; el PR 4 lo quita y pone la referencia: los pop-ups no dan rutas).
- Un único `MountError(issue)`; `WinFspMissingError` se mantiene porque abre el instalador.
- **Errores de rclone al log técnico, sin ficheros de log por montaje (decisión del 2026-11-03, sustituye a
  la del 2026-10-23: un `--log-file` en INFO por montaje, en `rclone/`, con su ruta en el pop-up).** En las
  pruebas manuales ese fichero no aportó nada: un montaje normal deja siempre las mismas 5 líneas, que el log
  técnico ya cuenta con más datos (PID, tiempos); en un corte de VPN rclone reintenta en silencio y tras 9
  minutos no había escrito nada; un fallo de credenciales repite el mismo error 9 veces (17 al abrir un
  fichero) y las líneas nombran carpetas y ficheros. Ahora:
  - rclone sigue escribiendo en un fichero mientras monta: es otro proceso, que puede sobrevivir a la app (si
    escribiera a BIFROST por una tubería, al morir la app rclone moriría o se bloquearía). Pero es temporal y
    solo con errores: `--use-json-log --log-level ERROR --log-file-max-size 10M --log-file-max-backups 1`. En
    JSON el nombre del fichero o carpeta llega en un campo aparte (`object`) y se quita entero, como en copy
    (con el texto de antes, `error_text` dejaba pasar la primera carpeta: `informes<path>`).
  - BIFROST lo sigue leyendo para elegir el pop-up (credenciales, permiso…).
  - Si el montaje falla, y al desmontar (también un resto de una sesión anterior, un montaje perdido o al
    cerrar la app), sus errores pasan al log técnico con el logger `bifrost.rclone` (el de copy): cada texto
    distinto una vez, sin nombres, hasta 100 (`MAX_LOGGED_ERRORS`); después se borra.
  - Nombre fijo por bucket o share (`mount-<perfil>-<bucket>.log`, `netapp-<share>.log`): así se encuentra el
    de un resto de una sesión anterior. Si queda uno de un montaje que murió sin desmontar, se borra antes de
    volver a montar (si no, su causa se confundiría con la del montaje nuevo).
  - INFO y NOTICE no se guardan: son las 5 líneas de siempre (`poll-interval…`, `Symlinks…`, `Signal
    received`, `Unmounted`, `Exiting`).
  - Se pierde: los nombres de ficheros en los errores (para desarrollo basta la causa; son datos del usuario)
    y el texto de más de 100 errores distintos.
- Una sola espera de montaje para MinIO y NetApp. A cambio, cada cambio en ella se prueba en las dos apps y
  en los tres sistemas (la tabla de verificación lo cubre); el margen de 30 s es un parámetro por si algún
  montaje necesita más.
- Windows: nunca `taskkill /IM rclone.exe`. Se cierran solo los procesos que ha montado la app y, para los
  restos de sesiones anteriores, el `rclone.exe` cuya línea de comandos contiene esa carpeta. Hay que probarlo
  en un Windows real (`Bifrost/PENDIENTES.md`).

**`common/logs.py`**

- `rclone_log_path(kind, name)`: el fichero temporal de un montaje (`mount-<perfil>-<bucket>.log`,
  `netapp-<share>.log`), siempre el mismo para el mismo bucket o share, en `rclone/` junto a `reports/` (en OOD,
  la carpeta de la sesión). `report_path` y `rclone_log_path` comparten la elección de carpeta base.
- `current_log_file()` (se adelanta del PR 4): el log técnico de la sesión; en OOD, `output.log` de la
  carpeta de la sesión. Es la ruta que dan los pop-ups de montaje.

**`common/rclone_mount.py` (nuevo, lo usan `mount/s3_mount.py` y `transfer/smb.py`)**

- `MountError(Exception)` con `.issue: UserIssue`.
- `drain_rclone_log(log_path, label)`: pasa los errores del fichero al log técnico (`bifrost.rclone`, sin
  nombres, cada texto una vez) y lo borra. La usan el fallo de un montaje y todos los desmontajes.
- `mount_and_wait(comando, mount_point, log_path, *, env=None, timeout=30) -> Popen`: añade las opciones de
  log, lanza rclone y cada 0,2 s comprueba:
  - si rclone ha terminado → `MountError` con `classify(últimos errores del fichero de rclone)` o `UNEXPECTED`;
  - si la carpeta está montada de verdad (macOS/Linux: `os.path.ismount` + `os.listdir`; Windows, donde la
    carpeta no existe hasta que monta: existe + `os.listdir`) → devuelve el proceso;
  - si pasan 30 s → termina rclone y `MountError(MOUNT_TIMEOUT)`.
- Log técnico: una línea por montaje (`mount ok: … (rclone pid N, N s)` / `mount failed: … code=…`) y, debajo, los errores de rclone; sin nombres
  de ficheros.

**Catálogo (`rclone_output.py`)**: `FUSE_MISSING` (pista por sistema), `MOUNT_TIMEOUT` ("The folder did not
respond"), `MOUNT_BUSY` (`Resource busy`, carpeta en uso), `RCLONE_MISSING` ("rclone not found": instalación
incompleta) y, para la NetApp, contraseña no aceptada (`STATUS_LOGON_FAILURE`), share inexistente
(`STATUS_BAD_NETWORK_NAME`) y acceso denegado (`STATUS_ACCESS_DENIED`). **Los textos reales de rclone hay que
comprobarlos antes** (fase 0 del PR 3): los de MinIO en local, los de la NetApp en OOD.

**`mount/s3_mount.py`**

- `mount_rclone_S3_prefix_to_folder` usa `mount_and_wait` con `rclone_log_path("mount", …)`, guarda el proceso
  en `_s3_mount_processes` solo si monta, y devuelve la carpeta montada. FUSE ausente, carpeta vacía o
  carpeta ocupada → `MountError`. Una sola función calcula la carpeta de montaje (la usan montar, desmontar y
  la detección al arrancar).
- Desmontar en Windows: si el proceso está en la lista, `taskkill /PID … /T /F` (como ahora); si no (resto de
  una sesión anterior), buscar el `rclone.exe` cuya línea de comandos contiene esa carpeta
  (`Get-CimInstance Win32_Process -Filter "Name='rclone.exe'"`) y cerrarlo por PID. Nunca por nombre.

**`bifrost-mount/src/views/mount.py`**

- `do_mount`: "✅ Mounted!" y abrir el explorador solo si `mount_and_wait` monta; `mounted_state` se actualiza
  solo entonces. Errores: `WinFspMissingError` → instalador (como ahora); `MountError` → `show_issue` con el
  bucket y la ruta del log técnico; otro error → `issue_for_exception`.
- **Pendiente 4**: mientras un bucket se está montando, "Unmount all" y "Mount" quedan desactivados; al
  terminar "Unmount all" se vuelve a comprobar qué sigue montado de verdad, y los que no se pudieron desmontar
  se avisan con un pop-up en lugar de darlos por desmontados.
- "Unmount all" ya no usa `taskkill /IM rclone.exe` (ver `s3_mount.py`).
- Lista de buckets: error traducido (`issue_for_exception`) en lugar de "Error loading buckets: <excepción>".
- Diálogos de WinFsp: `show_dialog` en lugar de `page.overlay` + `dlg.open` (la misma API que el resto).

**`transfer/smb.py` + `views/shares.py` (NetApp, OOD)**

- `montar_share_rclone` usa `mount_and_wait` con `rclone_log_path("netapp", share)` en lugar de `DEVNULL`;
  añade a `mounts_activos` **solo si monta**; devuelve el `MountError` o `None`.
- `montar_shares_seleccionados` devuelve `dict[nombre, MountError]`; la fila dice "Error" y al pulsarla abre
  `show_issue` con qué pasó, qué hacer y la ruta del log técnico (`output.log` de la sesión).

**`views/rclone_browser.py`**: error traducido (`issue_for_exception` + pista), como en el Tag Manager; el
texto original, al log técnico.

**Verificación del PR 3**

| Dónde | Caso | Resultado esperado |
|---|---|---|
| Local (macOS + fuse-t + `rclone serve s3`, sin MinIO real) | Montaje correcto | "✅ Mounted!" cuando la carpeta responde, no antes |
| Local | Claves no válidas / bucket inexistente | Pop-up traducido en segundos, con la ruta del log técnico; no "Mounted!"; los errores de rclone, en el log técnico |
| Local | Carpeta ocupada / rclone muere a mitad | `MOUNT_BUSY` / estado correcto tras "Unmount all" |
| Local | "Unmount all" con un montaje en curso | Botones desactivados; el estado final es el real (pendiente 4) |
| OOD | Share correcto / contraseña mal / share inexistente | Montado / pop-up con la causa en 1-2 s, sin esperar 30 s |
| OOD | Share que falla | No aparece en `mounts_activos`; copy no traduce rutas a él |
| Windows (se implementa en el PR 3; la prueba queda en `PENDIENTES.md`, entrada 17) | Resto de una sesión anterior + "Unmount all" | Se desmonta; ningún otro `rclone.exe` se cierra |

### Estado del PR 3 (2026-10-23)

**Fase 0 (rclone 1.72.1, fuse-t, MinIO simulado con `rclone serve s3`):**
- `rclone mount` monta en 0,3 s **aunque** las claves no valgan, el bucket no exista o el servidor no responda;
  solo termina enseguida si el perfil no existe (`CRITICAL … didn't find section`) o la carpeta ya está
  montada (`fuse: mount failed`, `ERROR : … Mount failed`). Por eso el montaje se comprueba listando la
  carpeta, y la causa sale del log de rclone (`InvalidAccessKeyId` aparece en cuanto el sistema lee la
  carpeta).
- Con un servidor que no responde, rclone tarda ~4 minutos en rendirse (10 intentos): la lectura de prueba
  va en un hilo para no bloquear la espera de 30 s.
- En macOS, si rclone muere, fuse-t desmonta la carpeta solo. Un resto de una sesión anterior (la app murió y
  rclone siguió vivo) se desmonta con `umount`. (2026-10-27: ahora se para su rclone, como en Windows; ver
  abajo.)
- Desde la terminal de las pruebas, macOS no deja leer un volumen de red ("Operation not permitted"): ese
  caso es `MOUNT_NOT_ALLOWED` (con la pista de dar permiso en Privacidad y seguridad). Por eso el montaje
  correcto completo no se pudo probar aquí. (2026-10-26: con acceso total al disco para VS Code sí se pudo,
  contra un S3 falso local: montaje, segundo montaje del mismo bucket, desmontaje y resto de una sesión
  anterior.)

**Implementado según la sección anterior, con estos detalles:**
- `common/rclone_mount.py`: `mount_and_wait`, `MountError`, `is_mounted`, `stop_process`.
- Catálogo: `MOUNT_BUSY`, `RCLONE_MISSING`, `NETAPP_LOGIN`, `NETAPP_SHARE_NOT_FOUND`, `NETAPP_PERMISSION` (por
  patrón) y `FUSE_MISSING_MACOS/LINUX`, `MOUNT_TIMEOUT`, `MOUNT_NOT_ALLOWED`, `UNMOUNT_FAILED` (constantes).
  `ISSUES_BY_CODE` para usar los del catálogo por código.
- `logs.rclone_log_path()` comparte con `report_path()` la elección de carpeta (`_new_file`).
  `logs.open_in_file_browser()` se adelanta del PR 4: Bifrost Mount la usa para abrir la carpeta montada.
- macOS/Linux: si la carpeta de montaje ya existe con contenido, se monta encima (`--allow-non-empty`) en
  lugar de fallar.
- `views/rclone_browser.py` recibe `IS_WEB` de `main.py` como las demás vistas (la pista de OOD es otra).
- Limpieza: `print`/f-strings del logger en `s3_mount.py`, `preflight.py` y `mount.py`; imports sin usar en
  `smb.py` y `preflight.py`; el `taskkill /IM rclone.exe` de "Unmount all".
- Un bucket ya montado no se vuelve a montar (encontrado en la prueba manual del 2026-10-26; ya pasaba antes
  del PR 3, pero no se veía porque el segundo rclone no tenía log). El segundo `rclone mount` se quedaba
  esperando a que la carpeta quedara libre, la comprobación veía el montaje del primero ("mount ok" falso) y,
  al desmontar, solo se paraba el primero. Ahora la pantalla abre la carpeta si el bucket está montado y el
  backend devuelve la carpeta sin lanzar rclone si ya está montada y responde (como ya hacía la NetApp);
  `mount_and_wait` da `MOUNT_BUSY` sin lanzar rclone si la carpeta ya está montada.
  Logs: PID de rclone al montar y al desmontar, "forcing" antes de forzar un desmontaje y la duración al
  terminar; sin `bucket selected` en cada clic.
- Restos de una sesión anterior (prueba manual del 2026-10-27): en macOS/Linux se esperaban 3 s inútiles por
  bucket y luego `umount -f` quitaba la carpeta por debajo de rclone, que acababa con `ERROR : Mount failed` /
  `CRITICAL` en su log. Ahora, en todos los sistemas, se busca el `rclone mount` cuya línea de comandos tiene
  exactamente esa carpeta (`ps` en macOS/Linux, PowerShell en Windows) y se para (SIGTERM / taskkill): rclone
  desmonta y sale limpio en ~0,2 s. Solo se fuerza si la carpeta sigue montada (sin esperar si no se encontró
  rclone). La búsqueda ignora los rclone que no son `mount`: una copia que lea de la carpeta montada no se
  para (en Windows también podía pasar antes). La pantalla ya marcaba como montados los restos al cargar los
  buckets, pero sin dejarlo en el log: ahora escribe `mounted from a previous session: <carpeta>` por cada uno.
- Montaje perdido (prueba manual del 2026-11-03): sin VPN, macOS acaba mostrando "Se han interrumpido las
  conexiones con el servidor" y, al pulsar "Desconectar", quita el montaje; su rclone sigue vivo y la pantalla lo
  seguía dando por montado (abría una carpeta vacía). Ahora, al pulsar un bucket marcado como montado, se
  comprueba que lo siga estando; si no, se monta de nuevo (`no longer mounted, mounting again`) y el backend
  para antes el rclone huérfano de esa carpeta (`stopping rclone pid N of the lost mount`; si no, al desmontar
  pararía el viejo y tendría que forzar el nuevo). Cada recarga de la lista también deja de marcar los que el
  sistema ha quitado (`mount: <bucket> is no longer mounted`): con dos buckets montados al cortar la VPN, el
  otro seguía marcado. Su rclone se para al volver a montarlo o al cerrar la app. Si falla, la lista deja de marcarlo aunque no se pueda recargar (sin VPN, la lista anterior se
  vuelve a pintar con los montajes al día, junto al aviso de error). Probado con rclone y fuse-t reales contra
  el S3 falso.
- Botón ⟳ junto al título de la lista para recargarla (siempre visible; desactivado mientras se monta o
  desmonta; log `bucket list: reload`): sin VPN la lista decía "try again" pero no había cómo recargarla.
  Las cargas de la lista no se solapan: si se pide otra durante una (⟳, recarga tras montar), se hace una más
  al terminar (seis clics seguidos = dos cargas; conectar la VPN y pulsar ⟳ mientras carga acaba bien).

- Logs de rclone de los montajes (2026-11-03, ver la decisión en "Decisiones"): fichero temporal de solo
  errores en JSON, con nombre fijo por bucket o share; `drain_rclone_log` pasa sus errores al log técnico
  (`[bifrost.rclone]`, sin nombres, cada texto una vez) al fallar el montaje y en todos los desmontajes, y lo
  borra; antes de montar se borra el que quedara de un montaje muerto. `MountError` ya no lleva ruta; los pop-ups
  dan la del log técnico (`logs.current_log_file()`, adelantada del PR 4). La lista de buckets separa
  `bucket list failed: … code=…` del texto de rclone (`[bifrost.rclone] lsd …`). Probado con rclone y fuse-t
  reales contra el S3 falso (19 casos): credenciales malas (2 líneas en vez de 9, fichero borrado), montaje
  normal (ninguna línea), errores con el bucket montado (sin nombres al desmontar), resto de una sesión
  anterior, fichero de un montaje muerto, perfil inexistente (CRITICAL), fichero rotado por rclone
  (`<nombre>-2026-11-03T13-44-04.778.log`, comprobado) sin tocar el de otro bucket, límite de 100, NetApp y
  `current_log_file` en escritorio y OOD. La pantalla (19 casos) da "Details:" con el log de la sesión.
  Prueba manual con MinIO de verdad: salían las 17 líneas porque cada respuesta trae otro `RequestID` y
  `HostID`. Se agrupa por `error_key` (el texto sin esos identificadores) y se escribe la primera vez con los
  suyos, para poder buscar esa petición en el log de MinIO. Arregla también la agrupación de errores de copy,
  que tenía el mismo fallo (el S3 falso los deja vacíos y no se veía).

**Probado:** `mount_and_wait` con rclone real (perfil inexistente, carpeta ocupada, lectura bloqueada) y
simulado (credenciales, bucket, servidor colgado, permiso, error desconocido): 13 casos. Backend de montaje y
NetApp: 14 (desmontar de esta sesión y restos sin tocar otro rclone, cierre de la app, búsqueda de Windows con
salida de PowerShell simulada, `mounts_activos` solo si monta). Pantallas: 15 en Bifrost Mount (botones
ocupados, pop-ups, WinFsp, "Unmount all" parcial, error de lista, bucket ya montado, restos de una sesión
anterior) y 4 en la NetApp. Copy, check y Tag Manager
siguen igual y las dos apps arrancan.

**Falta:**
- Prueba manual en Bifrost Mount con un bucket real: montaje correcto y "Unmount all" hechos el 2026-10-26;
  doble clic sobre un bucket ya montado y restos de una sesión anterior repetidos el 2026-10-27 tras los
  arreglos (PIDs correctos, ~0,1 s, logs de rclone limpios).
- Los textos reales de la NetApp en OOD (contraseña mal, share inexistente, sin permiso) para confirmar el
  catálogo.
- Windows: `Bifrost/PENDIENTES.md`, entrada 17.

## PR 4 — Referencia en cada error y exportación de los logs

> Revisado el 2026-11-03 con lo que dejó el PR 3 y las decisiones de esa fecha.

**Objetivo.** Cuando algo falla, el usuario sabe qué hacer y cómo hacérselo llegar a ITS, e ITS encuentra el
error en los logs: cada error que se muestra lleva una **referencia** (`MNT101-1103-141526`) que también está en el log
técnico, y en escritorio un botón **"Export logs…"** junta en un zip lo que ITS necesita.

### Decisiones (2026-11-03)

1. **Referencia en todos los errores que ve el usuario**: en los pop-ups (`show_issue`) y, cuando una operación
   de copy, check o Tag Manager falla, en el bloque final del panel y por tanto en su informe. Copy y check no
   abren pop-up al fallar: sin esto, lo más usado sería lo único sin referencia.
2. **Los pop-ups no dan rutas de logs.** Se quita el "Details: <log de la sesión>" que el PR 3 puso en los
   pop-ups de montaje (era provisional). El log técnico sí lleva rutas (carpetas de montaje, informes). El
   usuario llega a la carpeta de los logs con "Export logs…" o con la guía de usuario, que explica dónde está.
3. **Pop-up = título, "Error MNT101-1103-141526" justo debajo (como en las webs), qué ha pasado, qué hacer y OK** (más los
   botones propios de cada pantalla, como ahora). Sin "Copy details" ni "Open logs folder", que el diseño anterior ponía en cada
   pop-up: la referencia se puede seleccionar, la hora y la versión van en el log exportado y la carpeta la abre
   "Export logs…".
8. **El panel de copy sigue diciendo "📄 Report saved: <ruta>"** al terminar cada operación: no es un pop-up y
   sirve para que el usuario abra el informe.
4. **Soporte: "contact ITS"**, sin URL ni correo.
5. **"Export logs…" en la cabecera de todas las pantallas de escritorio** de las dos apps. En OOD no existe: la
   pista pide el `output.log` de la carpeta de la sesión.
6. **Contenido del zip: las 5 últimas sesiones**, para que ITS tenga contexto, y en Bifrost Transfer los
   informes de copy, check y Tag Manager de esas sesiones. Antes de exportar, un pop-up de confirmación dice qué se exporta.
   El log de la sesión actual no está terminado, pero se escribe línea a línea: lleva todo hasta el momento de
   exportar (y el error ya ha ocurrido). Incluir las anteriores cubre el caso habitual de exportar después de
   reiniciar la app.
7. **Diálogos que hoy enseñan la excepción en bruto** pasan a `show_issue` con referencia (detalle abajo). Los
   avisos sobre lo que escribe el usuario ("Select a bucket first", "Source and destination are required",
   "Invalid characters in tags", "Option not allowed") no son errores del programa: se quedan como están, sin
   referencia.

### Referencia (código del error)

Formato `<pantalla><tipo>-<MMDD>-<HHMMSS>`, por ejemplo **`MNT101-1103-141526`**: dónde pasó, qué pasó (siempre
el mismo número para la misma causa) y cuándo (3 de noviembre, 14:15:26). Decidido el 2026-11-03: une el código
del tipo de error, que se puede buscar en el código y en la guía sin abrir el log, con el momento, que distingue
cada vez que ocurre aunque se repita (el zip lleva 5 sesiones, de días distintos).

- **Pantalla:** `MNT` montar un bucket, `NET` NetApp, `CPY` copy (y "Save log"), `CHK` check, `TAG` Tag Manager,
  `APP` actualizar BIFROST o fallo no previsto.
- **Tipo:** un número de 3 cifras en cada `UserIssue` del catálogo (`rclone_output.py`, campo nuevo `num`); la
  primera cifra es la familia. Reglas: un número no se reutiliza ni cambia nunca (un código de una versión
  antigua sigue significando lo mismo); las variantes de una misma causa comparten número (`FUSE_MISSING` de
  macOS y de Linux, los tres `SOURCE_NOT_FOUND`); cada familia deja huecos para errores nuevos.

  | Familia | Número | Error |
  |---|---|---|
  | 1xx MinIO | 101 | `CREDENTIALS_EXPIRED` |
  | | 102 | `PROFILE_MISSING` |
  | | 103 | `MINIO_PERMISSION` |
  | | 104 | `BUCKET_NOT_FOUND` |
  | | 105 | `OBJECT_GONE` |
  | | 106 | `WORM_PROTECTED` |
  | | 107 | `INVALID_TAG` |
  | | 108 | `MINIO_BUSY` |
  | | 109 | `CLOCK_SKEW` |
  | 2xx red y límites | 201 | `NETWORK` |
  | | 202 | `TEMPORARY` |
  | | 203 | `TRANSFER_LIMIT` |
  | | 204 | `TIME_LIMIT` |
  | 3xx ficheros de origen | 301 | `SOURCE_NOT_FOUND` |
  | | 302 | `SOURCE_PERMISSION` |
  | | 303 | `SOURCE_CHANGING` |
  | | 304 | `FILE_IN_USE` |
  | | 305 | `DISK_FULL` |
  | 4xx montajes | 401 | `MOUNT_TIMEOUT` |
  | | 402 | `MOUNT_BUSY` |
  | | 403 | `MOUNT_NOT_ALLOWED` |
  | | 404 | `UNMOUNT_FAILED` |
  | | 405 | `FUSE_MISSING` |
  | 5xx NetApp | 501 | `NETAPP_LOGIN` |
  | | 502 | `NETAPP_SHARE_NOT_FOUND` |
  | | 503 | `NETAPP_PERMISSION` |
  | 9xx BIFROST | 901 | `RCLONE_MISSING` |
  | | 902 | `RCLONE_OPTIONS` |
  | | 903 | `FATAL` |
  | | 999 | `UNEXPECTED` |

- **Momento:** mes, día y hora con segundos del momento en que se muestra el error. Dos códigos iguales
  necesitarían el mismo error en la misma pantalla en el mismo segundo.
- `logs.new_ref(screen_prefix, issue) -> str`. Una referencia por error mostrado, no por sesión.
- **Línea en el log técnico**, que es lo que ITS busca: `issue shown: ref=MNT101-1103-141526
  code=CREDENTIALS_EXPIRED screen=mount`, logger `bifrost.ui`, nivel WARNING. **Sin `context`** (en el Tag
  Manager es el nombre del fichero) ni el mensaje: el código basta y las líneas de justo encima ya cuentan el
  detalle (`mount failed: … code=…` y los errores de rclone; `copy finished: …`).
- **Operaciones** (copy, check, Tag Manager) que fallan: la pantalla pide la referencia al terminar, la añade a
  su línea de resultado (`copy finished: outcome=failed … ref=CPY101-1103-141526`, `tags finished: …
  ref=TAG…`) y a la primera línea del resumen del panel, la que dice que ha fallado ("❌ The copy could not
  finish — MinIO access expired. (Error CPY101-1103-141526)"), que es también lo que guarda el informe. Llevan
  referencia: copy y check con `FAILED` o `PARTIAL`; Tag Manager con `stopped` o `partial` (su pop-up muestra la
  misma). No la llevan `OK`, `NOTHING_NEW`, `EMPTY`, `DRY_RUN`, `CANCELLED` ni `DIFFERENCES` del check (es un
  resultado, no un fallo del programa).
- **Documentación:** la tabla de tipos va en la de usuario y en la de desarrollo (ver "Documentación").

### Pistas "contact ITS" según el modo

Hoy `_CONTACT_ITS` dice "contact ITS and send them the report saved at the end of this log", y sale también en
pop-ups de montaje (por ejemplo `MOUNT_TIMEOUT` en OOD o `UNEXPECTED`), donde no hay ni panel ni informe:
`hint_for` solo distingue `copy` y `tags`, y los montajes usan `copy`. Pasa a depender solo del modo, con la
referencia:
- Escritorio: "If it keeps happening, click “Export logs…” at the top and send the file to ITS with the error
  code."
- OOD: "If it keeps happening, contact ITS with the error code and the output.log file of your session folder."
Los `UserIssue` que usan `_CONTACT_ITS` reciben la versión de OOD en `web_hint`.

### `common/logs.py`

```python
def new_ref(screen_prefix: str, issue: UserIssue) -> str:
    """Código del error que ve el usuario y que va al log técnico: pantalla + tipo + momento (MNT101-1103-141526)."""


def export_logs_zip(app: str, sessions: int = 5) -> tuple[Path, int, int]:
    """Zip en Descargas (o en la carpeta personal) con los logs de las `sessions` últimas sesiones y, en transfer,
    los informes de copy y check de esas sesiones. Devuelve (zip, sesiones, informes). Puede lanzar OSError."""
```

- Sesiones: los `bifrost-<app>-<fecha>.log` más recientes (ya pasados por el filtro de secretos al escribirse).
  Informes: `reports/copy-*.log`, `reports/check-*.log` y `reports/tags-*.log` desde el inicio de la más antigua
  de esas sesiones (la fecha está en el nombre). No entra `rclone/` (temporales: sus errores ya están en el log).
- Antes de comprimir escribe `logs exported: <zip> sessions=N reports=M`, para que en la sesión actual se vea
  hasta dónde llega. Permisos 0600. Nombre `BIFROST-<app>-logs-<fecha>.zip`.
- Hechas en el PR 3: `current_log_file()` y `open_in_file_browser()`.

### `bifrost_frontend/components.py`

- `show_issue(page, issue, *, is_web, title=None, context="", screen="copy", buttons=None, color=C_ERROR)`:
  genera la referencia con el prefijo de `screen` (pantallas nuevas: `mount`, `netapp`, `app`), escribe la línea
  `issue shown`, pone "Error MNT101-1103-141526" debajo del título (pequeño, gris, seleccionable) y la devuelve:

  ```
  ❌ Could not mount the bucket
  Error MNT101-1103-141526
  test
  MinIO access expired: Your temporary MinIO access pass is no longer valid.
  What you can do: Click “🔑 Renew credentials” and try again.
  ```
 Las llamadas
  actuales no cambian, salvo las de montaje, que pasan `screen` y dejan de construir "Details:".
- `build_header(subtitle, IS_WEB, no_ldap, page=None)`: con `page` y en escritorio, botón "Export logs…" a la
  derecha. Al pulsarlo, confirmación:
  - Título "Export logs". Texto: "BIFROST will save the logs of your last 5 sessions to your Downloads folder
    so you can send them to ITS." En Bifrost Transfer, además: "It also includes the copy, check and Tag Manager
    reports of those sessions, which contain file names and tag values."
  - Botones Cancel / Export. Al exportar: `export_logs_zip`, `open_in_file_browser(zip, select=True)` y aviso
    "Saved to Downloads. Send this file to ITS with the error code." Si falla, `show_issue` con
    referencia `APP`.
  - Todas las llamadas a `build_header` pasan `page`.

### Diálogos con la excepción en bruto (decisión 7)

| Dónde | Hoy | Con el PR 4 |
|---|---|---|
| `safe_thread` (fallo no previsto, las dos apps) | "Unexpected error" + `TipoError: mensaje` + "Check console or contact ITS."; la traza va al log como `print` | `show_issue(UNEXPECTED, title="Something went wrong", screen="app")`; la traza con `log.exception` y la misma referencia |
| Actualizar la app ("Update failed", `views/update.py`) | El texto de la excepción | `show_issue(issue_for_exception(ex), title="Could not update BIFROST", screen="app")` |
| "Save log" de copy (escritorio y web) | "Error" + `[Errno 13] Permission denied: '<ruta>'` | `show_issue(issue_for_exception(ex), title="Could not save the log", screen="copy")` |
| NetApp con privilegios de ITS sin credenciales de administrador (`main.py` de transfer) | "Error" + "Missing admin credentials for ITS privileges." | No es un fallo del programa: `show_dialog` con título "ITS privileges", sin referencia |

### Documentación (en el mismo commit, como en el PR 3)

- **Tabla de códigos de error en toda la documentación**, de usuario y de desarrollo:
  - Usuario: `docs/user/troubleshooting.md` con la tabla completa (código, qué significa y qué hacer) y cómo se
    lee un código (`MNT101-1103-141526`: pantalla, tipo, mes y día, hora); `mount-buckets.md`,
    `transfer-data.md`, `tag-manager.md` y `web-mode-ood.md` enlazan a ella desde sus tablas de problemas.
  - Desarrollo: `docs/development/operations.md` y `docs/agent/backend.md` con la tabla (número, `code` del
    catálogo y familia), las reglas de numeración (no reutilizar ni cambiar números, variantes con el mismo
    número, huecos por familia) y dónde se define (`num` en `rclone_output.py`). `docs/development/backend.md`
    describe `new_ref`, `export_logs_zip` y el campo `num`.
  - La tabla se escribe una vez por idioma de la documentación y se actualiza en el mismo commit que añada o
    cambie un error del catálogo.
- Guías de usuario: "Export logs…" (qué contiene y que hay que enviarlo a ITS con el código del error), dónde está
  la carpeta de los logs en cada sistema y, en OOD, el `output.log` de la carpeta de la sesión. Se quita
  "Details: …" de las tablas de problemas.
- `operations.md`: la línea `issue shown`, `ref=` en las líneas de resultado y `logs exported`.

### Verificación del PR 4

| Caso | Resultado esperado |
|---|---|
| Montaje con credenciales malas (Bifrost Mount) | Pop-up sin rutas, con "Error MNT101-…" bajo el título; en el log, `issue shown: ref=MNT101-… code=CREDENTIALS_EXPIRED screen=mount` después de `mount failed` |
| Copy que falla / check con errores | Primera línea del resumen del panel e informe con "(Error CPY…-…)" / "(Error CHK…-…)"; `copy finished: … ref=…` |
| Copy correcta, check con diferencias | Sin referencia |
| Tag Manager parado o parcial | Pop-up y panel con la misma referencia `TAG…-…` |
| Fallo no previsto (forzado en una prueba) | "Something went wrong" con `APP999-…`; la traza en el log con la misma referencia |
| "Export logs…" (macOS y Windows) | Confirmación con el texto de cada app; zip en Descargas con 5 sesiones (y, en transfer, sus informes de copy, check y Tag Manager), 0600, Finder/Explorador con el zip seleccionado; `logs exported` en el log |
| OOD | Sin botón; la pista pide `output.log`; la referencia también sale |
| Pistas | Ningún pop-up de montaje habla de "the report saved at the end of this log" |

## PR 5 — Migración de `print` al logger y limpieza del contenido

Por módulo (`log = logging.getLogger("bifrost.<área>")`), del más ruidoso al menos:
`views/rclone_browser.py`, `views/tag_manager.py`, `common/auth.py`, `transfer/smb.py`,
`bifrost-transfer/src/main.py`, `common/updates.py` y el resto.

- El prefijo `[algo]` pasa a ser el nombre del logger; `[debug]` → `log.debug`; errores → `log.error` /
  `log.exception`.
- Sin emojis ni mezcla de idiomas (inglés); una línea por evento con `clave=valor`; `%s` en lugar de
  f-strings en las llamadas al logger.
- Volcados grandes a DEBUG y resumidos: lista de buckets → `folders=28`; conexión LDAP → solo el DN;
  `[debug matching]` → una línea por proceso.
- `transfer/smb.py`, `desmontar_todos_los_shares` (cierre de la NetApp): hoy solo deja un `print` al final ("All SMB
  shares have been unmounted.") y otro por share que falla. Pasar a una línea por share, como Bifrost Mount
  (`unmount <carpeta>: done` / `still mounted`). Revisar a la vez, probándolo en OOD, el `umount -f` (en Linux
  quizá no funciona sin ser root con FUSE) y el `taskkill /IM rclone.exe` de Windows.
- (`mount/s3_mount.py`, `mount/preflight.py` y `views/mount.py` ya no tienen `print` ni avisos de pyflakes:
  se reescribieron en el PR 3.)
- Al terminar, `_StreamToLogger` queda solo como red de seguridad.
- Pendiente de decidir: mover el bloque de SIGTERM/SIGINT, repetido en los dos `main.py`, a una función
  compartida.

## PR 6 — Documentación (`docs-update`)

- Las guías de usuario y `operations.md` se actualizaron con cada PR (2a, 2b, PR 3; el PR 4 lleva las suyas).
- Queda: quitar `session_log.py` (ya no existe), `log_event`, `write_log` y `~/bifrost-mount-logs/` de
  `README.md`, `docs/agent/architecture.md`, `docs/development/architecture.md`, `docs/agent/frontend.md`,
  `docs/development/frontend.md` y `docs/agent/conventions-gotchas.md`, y repasar carpetas, formato, niveles,
  `BIFROST_LOG_LEVEL` y `BIFROST_SESSION_DIR` en la documentación de desarrollo.
- Gotchas nuevos: `flet run` necesita la línea `PAGE_URL_…` sin modificar en stdout; closures dentro de
  `except` que se ejecutan con `ui_call` deben capturar la excepción como argumento por defecto.

## Verificación general

1. Fase 0, punto 4 (errores reales de MinIO) antes de cerrar el catálogo del PR 2.
2. En cada PR: pyflakes, import en frío de las dos apps y reinstalar `bifrost-shared` en los dos venv
   (`uv sync --reinstall-package bifrost-shared`; la instalación no es editable).
3. Probar siempre con `flet run` real, no solo importando o llamando a `ft.run`.
4. Cuando lleguen pytest y mypy: tests de `classify`, `explain_exit`, `RunSummary.feed`,
   el resumen del check, `issue_for_exception`, `_RedactFilter`, `_StreamToLogger` y `log_dir` (funciones
   puras); del PR 3, `error_text`/`error_key`, `_error_texts` y `drain_rclone_log`; la tabla de verificación de
   la fase 2 sirve de base (y las pruebas del PR 3 con el S3 falso, `rclone serve s3`).
