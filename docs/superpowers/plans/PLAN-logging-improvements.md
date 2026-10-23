# Plan: sistema de logs unificado (log técnico + mensajes al usuario + salida de rclone)

Rama: `refactor/unified-logging`. Última actualización: 2026-10-23.

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Verificación de formatos de rclone 1.72.1 y de Hypercorn 0.18 | Hecha (falta el punto 4: errores reales de MinIO) |
| PR 1 | Log técnico común (`common/logs.py`) en las dos apps + OOD | **Hecho** |
| PR 2 | Salida de rclone para el usuario: 2a copy / check · 2b Tag Manager | **2a hecho** (`cc17aa7`, `5d11c22`); 2b revisada, pendiente |
| PR 3 | Montajes con rclone (MinIO y NetApp): `--log-file` y verificación real | Pendiente |
| PR 4 | Diálogo de error con referencia y acceso a los logs | Pendiente |
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
4. **Acceso fácil a los logs**: código de referencia en cada error y botones "Copy details", "Open logs
   folder" y "Export logs…" (zip para adjuntar al **ticket**). En OOD, informes en la carpeta de la sesión,
   junto a `output.log`.

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
rclone mount ──► --log-file <carpeta>/rclone/mount-<bucket>-<fecha>.log ──► si falla: últimas líneas → UserIssue
```

| Sistema | Log técnico | Informes (PR 2) | Logs de rclone (PR 3) |
|---|---|---|---|
| macOS | `~/Library/Logs/BIFROST/<app>/` | `…/<app>/reports/` | `…/<app>/rclone/` |
| Windows | `%LOCALAPPDATA%\IRB\BIFROST\<app>\` | `…\reports\` | `…\rclone\` |
| Linux escritorio | `$XDG_STATE_HOME/bifrost/<app>/` (por defecto `~/.local/state/…`) | `…/reports/` | `…/rclone/` |
| OOD (web) | stdout → `./output.log` | `$BIFROST_SESSION_DIR/reports/` | `$BIFROST_SESSION_DIR/rclone/` |

Si `BIFROST_SESSION_DIR` no está definida (web en local), se usa la carpeta del SO. Los logs antiguos
(`~/bifrost-mount-logs/`, `~/bifrost-logs/`) no se borran.

Dónde va la información útil de rclone:

| Información | Dónde la ve el usuario | Dónde queda guardada |
|---|---|---|
| Carpeta montada o no, y por qué | estado del botón + diálogo con referencia | log técnico + `rclone/mount-*.log` |
| Progreso de la copia (comparando / copiando, ficheros, tamaño, velocidad, tiempo restante) | bloque de progreso encima del log, una vez por segundo | log técnico (una línea de stats cada 60 s) |
| Fichero o carpeta que no se pudo copiar y por qué | al final, en el panel: **solo el número por causa**, sin nombres | informe: lo que mostró el panel + lista de ficheros con su causa (máx. 100) |
| Ficheros ya idénticos en MinIO (no copiados, sus etiquetas no cambian) | al final, en el panel: el número | informe (lo mismo que el panel) |
| Resumen final (copiados, fallidos, qué hacer) | bloque final del panel | informe |
| Check: idénticos / faltan en MinIO / distintos / no comparados / con error | resumen en el panel, solo números | informe: lo que mostró el panel + distintos e ilegibles con su causa (máx. 100) |
| NetApp (Z) montado o no, y por qué | estado de la fila + diálogo al pulsar "Error" | log técnico + `rclone/netapp-*.log` |
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
### Tags saved at 2026-10-23 10:20:41 ###
📄 File: test-logs/documento.txt
✅ Tags saved.
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
| Se para por un error general | "❌ Stopped — <título>. N files have the new tags; the rest of the folder was not changed." | "Tags could not be applied" + lo mismo + qué hacer + ruta del informe · **Cancel** / **Try again** |
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


- `export_logs_zip` no debe incluir por defecto los informes (`reports/`): tienen nombres de ficheros y
  valores de etiquetas. Solo los logs técnicos, pasados por el filtro de secretos, y los informes que el
  usuario marque. Zip con permisos 0600. Avisar en el diálogo y en la doc de qué contiene.

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

### Función que se añade a `common/logs.py`

```python
def rclone_log_path(kind: str, name: str) -> Path:
    """Ruta nueva para el --log-file de un proceso rclone (mount, netapp). Conserva 30 por tipo."""
    d = _data_dir(_state["app"] or "bifrost") / "rclone"
    d.mkdir(parents=True, exist_ok=True)
    _prune(d, f"{kind}-*.log", KEEP_SESSIONS)
    safe = re.sub(r"[^\w.-]+", "_", name).strip("_")[:60] or "x"
    return d / f"{kind}-{safe}-{datetime.now():%Y-%m-%d_%H-%M-%S}.log"
```

### Cambios

- **Excepciones tipadas** (`mount/preflight.py`, `common/rclone.py`): `RcloneMissingError(EnvironmentError)`
  (la lanza `get_rclone_executable`), `FuseMissingError(EnvironmentError)` (macOS sin fuse-t, Linux sin
  FUSE), `MountFailedError(Exception)` con `.issue: UserIssue` y `.detail: str` (últimas líneas del log de
  rclone). `WinFspMissingError` no cambia.
- **`mount/s3_mount.py`**: `mount_rclone_S3_prefix_to_folder` añade
  `--log-file <rclone_log_path("mount", f"{perfil}-{prefix}")> --log-level INFO`, devuelve
  `(proceso, mount_point, log_path)` y lanza `FuseMissingError`. Nueva
  `wait_until_mounted(proceso, mount_point, log_path, timeout=30)`: cada 0,2 s comprueba `proceso.poll()` (si
  rclone terminó → `MountFailedError`) y que el punto de montaje responda (`os.listdir` + `os.path.ismount`
  en macOS/Linux); al agotar el tiempo → `MountFailedError`. `issue` = `classify(últimas 20 líneas)` o
  `UNEXPECTED`.
- **`bifrost-mount/src/views/mount.py`** (`do_mount`): el bucle de espera propio pasa a
  `backend.wait_until_mounted(...)`; "✅ Mounted!" solo si no lanza. Así se corrige el `MOUNT success` tardío
  observado después de `UNMOUNT ALL`. Excepciones: `WinFspMissingError` (igual) → `MountFailedError` /
  `FuseMissingError` / `RcloneMissingError` → `show_issue` con título concreto → `Exception` → `UNEXPECTED`.
  El texto de "Error loading buckets" se traduce con `classify`.
- **`transfer/smb.py` + `views/shares.py`**: `montar_share_rclone` usa
  `--log-file <rclone_log_path("netapp", share)>` en vez de `DEVNULL` y, si falla, devuelve el `UserIssue`.
  `montar_shares_seleccionados` devuelve `dict[nombre, UserIssue]`; la fila muestra "Error" y al pulsarla
  abre `show_issue`.
- **`views/rclone_browser.py`**: `f"Error: {ex_val}"` → título + pista de `classify` (o `UNEXPECTED`); el
  crudo al log técnico.

## PR 4 — Diálogo de error con referencia y acceso a los logs

### Funciones que se añaden a `common/logs.py`

```python
def current_log_file() -> Path | None:
    return _state["file"]


def new_ref(prefix: str) -> str:
    """Código corto que aparece en el diálogo y en la línea del log (p. ej. MNT-7F3A)."""
    return f"{prefix}-{secrets.token_hex(2).upper()}"


def open_in_file_browser(path: Path, select: bool = False) -> None:
    """Abre la carpeta (o la muestra con el fichero seleccionado) en Finder / Explorador / gestor Linux."""
    system = platform.system()
    if system == "Darwin":
        subprocess.Popen(["open", "-R", str(path)] if select else ["open", str(path)])
    elif system == "Windows":
        subprocess.Popen(["explorer", f"/select,{path}"] if select else ["explorer", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path.parent if select else path)])


def export_logs_zip(app: str, sessions: int = 5) -> Path:
    """Comprime las últimas sesiones, los logs de rclone y los informes en Descargas (para el ticket)."""
    d = log_dir(app)
    target_dir = Path.home() / "Downloads"
    if not target_dir.is_dir():
        target_dir = Path.home()
    zip_path = target_dir / f"BIFROST-{app}-logs-{datetime.now():%Y-%m-%d_%H-%M}.zip"
    files = sorted(d.glob(f"bifrost-{app}-*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:sessions]
    files += [p for sub in ("rclone", "reports") for p in (d / sub).glob("*") if p.is_file()]
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, f.relative_to(d))
    return zip_path
```

### `shared/bifrost_frontend/components.py`

- `show_dialog` gana un parámetro opcional `content: ft.Control | None` (sustituye al texto si se pasa).
  Ningún uso actual cambia.
- `show_issue` se crea en la 2b (título, contexto, mensaje, qué hacer y botones que pase quien llama). El PR 4
  le añade `ref`, "Copy details" y "Open logs folder", sin cambiar las llamadas. Diseño completo:
  `show_issue(page, issue, *, ref, is_web=False)`: título del `UserIssue`, mensaje, "What you can do:
  …" y "Reference: MNT-7F3A" seleccionable. Botones: **Copy details** (`await page.clipboard.set(...)` con
  referencia, código, hora, app, versión y ruta del log), **Open logs folder** (solo escritorio) y **OK**. En
  web, el texto pide adjuntar `output.log` de la carpeta de la sesión de Open OnDemand.
- `build_header(...)`: parámetro opcional `on_export_logs` → botón "Export logs…" (solo escritorio):
  `export_logs_zip`, `open_in_file_browser(zip, select=True)` y aviso "Saved to Downloads. Attach it to your
  support ticket.".
- Cada `show_issue` va acompañado de `log.error("%s ref=%s detail=%s", issue.code, ref, …)`.

## PR 5 — Migración de `print` al logger y limpieza del contenido

Por módulo (`log = logging.getLogger("bifrost.<área>")`), del más ruidoso al menos:
`views/rclone_browser.py`, `views/tag_manager.py`, `mount/s3_mount.py`, `common/auth.py`, `transfer/smb.py`,
`bifrost-transfer/src/main.py`, `common/updates.py` y el resto.

- El prefijo `[algo]` pasa a ser el nombre del logger; `[debug]` → `log.debug`; errores → `log.error` /
  `log.exception`.
- Sin emojis ni mezcla de idiomas (inglés); una línea por evento con `clave=valor`; `%s` en lugar de
  f-strings en las llamadas al logger.
- Volcados grandes a DEBUG y resumidos: lista de buckets → `folders=28`; conexión LDAP → solo el DN;
  `[debug matching]` → una línea por proceso.
- De paso, avisos de pyflakes en `s3_mount.py`: `f"taskkill"` sin variables y dos `global
  _s3_mount_processes` que sobran.
- Al terminar, `_StreamToLogger` queda solo como red de seguridad.
- Pendiente de decidir: mover el bloque de SIGTERM/SIGINT, repetido en los dos `main.py`, a una función
  compartida.

## PR 6 — Documentación (`docs-update`)

- `docs/user/troubleshooting.md` y `docs/user/transfer-data.md`: dónde están los logs, "Export logs…", "Copy
  details", qué adjuntar al ticket; en OOD, `output.log` y `reports/` de la carpeta de la sesión (sustituye a
  "`~/bifrost-logs/`").
- `docs/agent/*` y `docs/development/*` (`operations.md`, `frontend.md`, `architecture.md`,
  `conventions-gotchas.md`) y `README.md`: carpetas, formato, niveles, `BIFROST_LOG_LEVEL`,
  `BIFROST_SESSION_DIR`; quitar `session_log.py`, `write_log`, `log_event`, `~/bifrost-mount-logs/` y el tee
  `bifrost-console-*`.
- Gotchas nuevos: `flet run` necesita la línea `PAGE_URL_…` sin modificar en stdout; closures dentro de
  `except` que se ejecutan con `ui_call` deben capturar la excepción como argumento por defecto.

## Verificación general

1. Fase 0, punto 4 (errores reales de MinIO) antes de cerrar el catálogo del PR 2.
2. En cada PR: pyflakes, import en frío de las dos apps y reinstalar `bifrost-shared` en los dos venv
   (`uv sync --reinstall-package bifrost-shared`; la instalación no es editable).
3. Probar siempre con `flet run` real, no solo importando o llamando a `ft.run`.
4. Cuando lleguen pytest y mypy: tests de `classify`, `explain_exit`, `RunSummary.feed`,
   el resumen del check, `issue_for_exception`, `_RedactFilter`, `_StreamToLogger` y `log_dir` (funciones
   puras); la tabla de verificación de la fase 2 sirve de base.
