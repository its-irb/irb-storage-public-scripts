# Plan: sistema de logs unificado (log técnico + mensajes al usuario + salida de rclone)

Rama: `refactor/unified-logging`. Última actualización: 2026-10-16.

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Verificación de formatos de rclone 1.72.1 y de Hypercorn 0.18 | Hecha (falta el punto 4: errores reales de MinIO) |
| PR 1 | Log técnico común (`common/logs.py`) en las dos apps + OOD | **Hecho** |
| PR 2 | Salida de rclone para el usuario: copy / check / etiquetas | Pendiente |
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
| Progreso de la copia (ficheros, tamaño, velocidad, tiempo restante) | una línea cada 10 s en el panel | log técnico (cada 1 s, DEBUG) |
| Fichero que no se pudo copiar y por qué | línea en el panel (máx. 20 + "…") | informe (lista completa) + log técnico |
| Resumen final (copiados, fallidos, qué hacer) | bloque final del panel | informe |
| Check: idénticos / faltan en MinIO / distintos / con error | resumen en el panel + hasta 20 ficheros | informe + fichero `--combined` de esa ejecución |
| NetApp (Z) montado o no, y por qué | estado de la fila + diálogo al pulsar "Error" | log técnico + `rclone/netapp-*.log` |
| Error al listar carpetas | texto de error del navegador, traducido | log técnico |
| Etiquetas aplicadas o error de MinIO | panel del Tag Manager, traducido | informe de etiquetas |

## Fase 0 — resultados (rclone 1.72.1, Hypercorn 0.18.0)

- **JSON de rclone** (`--use-json-log`): cada línea trae `time`, `level` (`info`/`notice`/`error`), `msg`,
  `source` y, si se refiere a un elemento, `object` + `objectType`. Cada fichero copiado sale como
  `Copied (new)` con `size`. Las estadísticas llegan cada segundo como línea `notice` con la clave `stats`:
  `bytes`, `totalBytes`, `transfers`, `totalTransfers`, `errors`, `speed` (float), `eta` (int **o null**),
  `elapsedTime`, `lastError`, `fatalError`, `retryError`. En `check` la línea final de stats es `info`.
- **Reintentos**: rclone repite la operación hasta `--retries` veces (3 por defecto). Cada intento vuelve a
  registrar `Failed to copy` del mismo fichero y termina con `Attempt N/M failed with K errors…` (sin
  `object`). Hay que deduplicar por fichero, y los fallidos reales son los del **último** intento.
- `stats.transfers` incluye los fallidos: copiados = `transfers − fallidos finales`.
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
  (comprobado en OOD). Hace falta un manejador de SIGTERM a nivel de módulo también en web.
- **Registros anidados en Python 3.13.5** (el del cluster): `Logger.handle()` descarta los registros que se
  crean mientras otro se procesa en el mismo hilo. Hypercorn escribe en `sys.stderr` desde su propio handler y
  el redirector creaba un registro anidado, así que se perdía `Running on`. En 3.13.15 y 3.14 no pasa
  (comprobado con una reproducción mínima en las dos versiones). Arreglado: `_StreamToLogger` entrega el
  registro directamente a los handlers de `bifrost`, sin pasar por `Logger.handle()`.
- **Pendiente (punto 4)**: errores reales de MinIO (sin permiso, token caducado, WORM) para afinar los
  patrones del catálogo. Necesita credenciales de prueba (bucket `test-policies`).

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

### Pendiente dentro de la fase 1

- **Cierre en web**: registrar el `atexit` de limpieza una sola vez a nivel de módulo (hoy se registra en
  `main()`, una vez por cada conexión del navegador, y se acumula con cada reconexión) y un manejador de
  SIGTERM también en web, para el proceso hijo de Hypercorn. Prueba: Delete en OOD → `APP shutdown` en
  `output.log`.

### Observado durante las pruebas (para PR 3 y PR 5)

- La salida de `rclone mount` (`NOTICE: … Symlinks support enabled`, `short read on fuse device`,
  `umount(...): Resource busy`) sale en la terminal pero **no** en el fichero: rclone escribe directamente en
  la consola heredada. → PR 3 (`--log-file`).
- `MOUNT success` de un intento anterior aparece **después** de `UNMOUNT ALL`: el bucle de espera da el
  montaje por bueno sin comprobarlo y deja el estado de la app mal. → PR 3.
- Ruido: `repr` de la conexión LDAP, `[debug matching]` línea a línea, listas de `Popen`. → PR 5.

## PR 2 — Salida de rclone para el usuario (copy / check / etiquetas)

### Funciones que se añaden a `common/logs.py`

```python
_state: dict = {"app": None, "is_web": False, "file": None}   # lo rellena setup_logging


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

### Nuevo `shared/bifrost_backend/common/rclone_output.py`

Código validado contra la salida real de la fase 0 (copia con un fichero ilegible, origen inexistente y
check con diferencias).

```python
"""Interpretación de la salida de rclone: crudo → log técnico; eventos útiles → texto para el usuario."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("bifrost.rclone")


@dataclass(frozen=True)
class UserIssue:
    code: str            # estable; aparece en el log técnico
    title: str           # título corto (diálogo / panel)
    message: str         # qué ha pasado, en lenguaje sencillo
    hint: str = ""       # qué puede hacer el usuario ("" si no puede hacer nada)


# Orden = prioridad. Patrones de MinIO pendientes de confirmar (fase 0, punto 4).
_CATALOG: list[tuple[re.Pattern, UserIssue]] = [
    (re.compile(r"ExpiredToken|InvalidAccessKeyId|SignatureDoesNotMatch|token.*expired", re.I),
     UserIssue("CREDENTIALS_EXPIRED", "MinIO access expired",
               "Your temporary MinIO access pass is no longer valid.",
               "Click “🔑 Renew credentials” and try again.")),
    (re.compile(r"WORM|ObjectLocked|object lock", re.I),
     UserIssue("WORM_PROTECTED", "File already in MinIO",
               "This folder is write-once: a file with the same name is already there and cannot be replaced.",
               "Copy it to another folder or with a different name.")),
    (re.compile(r"AccessDenied|403 Forbidden|status code: 403", re.I),
     UserIssue("MINIO_PERMISSION", "No permission in MinIO",
               "You do not have permission to read or write in this MinIO folder.",
               "Check that you chose the right folder. If you need access, ask your group's data manager.")),
    (re.compile(r"NoSuchBucket", re.I),
     UserIssue("BUCKET_NOT_FOUND", "MinIO folder not found",
               "The MinIO folder does not exist or you cannot see it.",
               "Choose the folder again from the list.")),
    (re.compile(r"no such host|dial tcp|connection refused|i/o timeout|context deadline exceeded|"
                r"network is unreachable|TLS handshake timeout|timed out", re.I),
     UserIssue("NETWORK", "Cannot reach MinIO",
               "BIFROST cannot connect to the MinIO server.",
               "Check that the Nexica VPN is on and try again.")),
    (re.compile(r"RequestTimeTooSkewed", re.I),
     UserIssue("CLOCK_SKEW", "Your computer's clock is wrong",
               "MinIO rejected the request because your computer's date or time is not correct.",
               "Set the date and time to automatic and try again.")),
    (re.compile(r"SlowDown|status code: 503", re.I),
     UserIssue("MINIO_BUSY", "MinIO is busy",
               "The MinIO server is overloaded right now.", "Wait a few minutes and try again.")),
    (re.compile(r"no space left on device", re.I),
     UserIssue("DISK_FULL", "Not enough space",
               "There is no free space left where the data is being written.", "Free some space and try again.")),
    (re.compile(r"permission denied", re.I),
     UserIssue("SOURCE_PERMISSION", "Cannot read a file",
               "BIFROST cannot read a file or folder of the source.",
               "Check that you have permission to open it.")),
    (re.compile(r"directory not found|file not found|no such file or directory", re.I),
     UserIssue("SOURCE_NOT_FOUND", "Source not found",
               "The source file or folder does not exist (it may have been moved or renamed).",
               "Check the source path and try again.")),
    (re.compile(r"mountpoint .* is not empty|already mounted|device or resource busy|resource busy", re.I),
     UserIssue("MOUNT_BUSY", "Folder already in use",
               "The place where the folder is opened is already in use.",
               "Close any Finder or Explorer window showing it, unmount all and try again.")),
    (re.compile(r"fuse|cgofuse|WinFsp|winfsp", re.I),
     UserIssue("FUSE_MISSING", "Folder driver not working",
               "The component that lets your computer open MinIO folders is missing or not working.",
               "Reinstall BIFROST. If it keeps happening, open a ticket.")),
]

UNEXPECTED = UserIssue("UNEXPECTED", "Something went wrong",
                       "BIFROST could not finish the operation.",
                       "Try again. If it keeps happening, open a ticket and include the reference below.")


def classify(text: str) -> UserIssue | None:
    for rx, issue in _CATALOG:
        if rx.search(text or ""):
            return issue
    return None


# https://rclone.org/docs/#exit-code
_EXIT = {
    2: UserIssue("RCLONE_USAGE", "Internal problem", "BIFROST started rclone with wrong options.",
                 "Open a ticket and include the reference below."),
    3: UserIssue("DIR_NOT_FOUND", "Folder not found", "The source or destination folder does not exist.",
                 "Check both paths and try again."),
    4: UserIssue("FILE_NOT_FOUND", "File not found", "The source file does not exist.",
                 "Check the source path and try again."),
    5: UserIssue("TEMPORARY", "Temporary problem", "Some files failed because of a temporary problem.",
                 "Start the operation again: files already copied are skipped."),
    7: UserIssue("FATAL", "Operation stopped", "rclone stopped because of a problem that retrying will not fix.",
                 "Open a ticket and include the reference below."),
}


def explain_exit(rc: int, first_error: str = "") -> UserIssue:
    return classify(first_error) or _EXIT.get(rc, UNEXPECTED)


_ATTEMPT = re.compile(r"^Attempt (\d+)/(\d+) failed")


@dataclass
class RunSummary:
    """Acumula la salida JSON de una ejecución y produce las líneas que ve el usuario."""
    operation: str                       # "copy" | "check"
    stats: dict = field(default_factory=dict)
    first_error: str = ""
    _current: dict[str, tuple[UserIssue, str]] = field(default_factory=dict)   # fichero → (issue, crudo)
    _last_attempt: tuple[int, int, dict] | None = None                         # (n, total, fallidos)
    _shown: set[str] = field(default_factory=set)
    _last_progress: float = 0.0

    MAX_LISTED = 20

    def feed(self, raw: str, now: float) -> list[str]:
        """Procesa una línea de rclone; registra el crudo y devuelve 0..n líneas para el usuario."""
        raw = raw.rstrip("\n")
        if not raw.strip():
            return []
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            log.info("%s: %s", self.operation, raw)
            return []
        level, msg = ev.get("level", ""), (ev.get("msg") or "").strip()
        obj, obj_type = ev.get("object", ""), ev.get("objectType", "")
        out: list[str] = []
        if "stats" in ev:
            self.stats = ev["stats"]
            log.debug("%s stats %s", self.operation, {k: self.stats.get(k) for k in
                      ("bytes", "totalBytes", "transfers", "totalTransfers", "errors", "eta")})
            if now - self._last_progress >= 10:
                self._last_progress = now
                out.append(f"⏳ {self.progress_text()}\n")
            return out
        log.log(logging.ERROR if level == "error" else logging.DEBUG, "%s %s %s", self.operation, obj, msg)
        if level != "error":
            return out
        self.first_error = self.first_error or msg
        if m := _ATTEMPT.match(msg):                          # fin de un intento con errores
            n, total = int(m[1]), int(m[2])
            self._last_attempt = (n, total, self._current)
            self._current = {}
            if n < total:
                out.append(f"🔁 Retrying the files that failed (attempt {n + 1} of {total})…\n")
        elif obj and not obj_type.endswith(".Fs"):            # error de un fichero (no de la carpeta raíz)
            issue = classify(msg) or UNEXPECTED
            self._current[obj] = (issue, msg)
            if obj not in self._shown and len(self._shown) < self.MAX_LISTED:
                self._shown.add(obj)
                out.append(f"❌ {obj}: {issue.title}\n")
        return out

    def failed(self, rc: int) -> dict[str, tuple[UserIssue, str]]:
        """Ficheros que siguen fallando al terminar (los del último intento)."""
        if rc == 0:
            return {}
        if self._last_attempt and self._last_attempt[0] == self._last_attempt[1]:
            return self._last_attempt[2]
        return self._current

    def progress_text(self) -> str:
        s = self.stats
        done, total = s.get("transfers", 0), s.get("totalTransfers", 0)
        text = f"{done} of {total} files · {_size(s.get('bytes', 0))} of {_size(s.get('totalBytes', 0))}"
        if s.get("speed"):
            text += f" · {_size(s['speed'])}/s"
        if s.get("eta"):
            text += f" · about {_duration(s['eta'])} left"
        return text

    def final_lines(self, rc: int) -> list[str]:
        failed = self.failed(rc)
        copied = max(self.stats.get("transfers", 0) - len(failed), 0)
        if rc == 0:
            return [f"\n✅ Copy finished: {copied} file(s) copied.\n"]
        if not failed:                                    # falló la operación entera, no un fichero
            issue = explain_exit(rc, self.first_error)
            return [f"\n❌ The copy could not finish — {issue.title}: {issue.message}\n",
                    *([f"   What you can do: {issue.hint}\n"] if issue.hint else [])]
        lines = [f"\n⚠️ Copy finished with problems: {copied} file(s) copied, {len(failed)} failed.\n"]
        if len(failed) > self.MAX_LISTED:
            lines.append(f"   … and {len(failed) - self.MAX_LISTED} more (full list in the report).\n")
        issues = [i for i, _ in failed.values()] or [explain_exit(rc, self.first_error)]
        hints = list(dict.fromkeys(i.hint for i in issues if i.hint))
        lines += [f"   What you can do: {h}\n" for h in hints[:3]]
        return lines


def parse_combined_report(path: Path) -> dict[str, list[str]]:
    """Lee el --combined de rclone check: '=' idéntico, '+' falta en MinIO, '*' distinto, '!' error al leer
    ('-' = solo en MinIO; no aparece con --one-way)."""
    groups: dict[str, list[str]] = {"=": [], "-": [], "+": [], "*": [], "!": []}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if len(line) > 2 and line[0] in groups:
                groups[line[0]].append(line[2:])
    return groups


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"
```

Exportar en `backend.py`: `UserIssue`, `classify`, `explain_exit`, `UNEXPECTED`, `report_path`.

### `shared/bifrost_backend/transfer/copy_check.py`

- `ejecutar_rclone_copy` / `ejecutar_rclone_check`: quitar `--progress` y `--stats=1s`; añadir
  `--use-json-log --log-level INFO --stats 1s --stats-log-level NOTICE`.
- El comando completo deja de ir al panel ("🧾 Full command") y pasa al log técnico.
- Bucle de salida: `for out in summary.feed(linea, time.monotonic()): log_fn(out)`. Al terminar, `log_fn`
  recibe `summary.final_lines(rc)` en lugar de "✅ Copy completed successfully." / "❌ Copy error. Code: N".
  `log_fn` sigue recibiendo texto, así que el panel, el buffer web, el throttle y `_replay` no cambian.
- Parámetro opcional `report: list[str] | None`: se rellena con `summary.failed(rc)` completo para el informe.
- `ejecutar_rclone_check`: `--combined` en `report_path("check-combined", "txt")` (uno por ejecución, en lugar
  del fijo `~/rclone-combined-check.txt`); al terminar, resumen de `parse_combined_report`:
  "N identical · N missing in MinIO · N different · N with errors" + hasta 20 ficheros de cada grupo con
  problemas. rc 1 sigue siendo "differences found".

### `bifrost-transfer/src/views/copy.py`

- `_autosave_log`: quitar `if not IS_WEB: return None`; escribir en `backend.report_path("copy"|"check")`;
  añadir la lista completa de fallidos y la ruta del `--combined`; borrar su rotación propia (el
  `glob("bifrost-*.log")` actual borra también los ficheros de consola y de etiquetas).
- Llamar a `_autosave_log()` también en escritorio al terminar copy y check.
- "Save log" se mantiene.
- Quitar la línea duplicada `_cancelling: list = [False]`.

### `bifrost-transfer/src/views/tag_manager.py`

- Errores de boto3 (`ClientError`): `backend.classify(ex.response["Error"]["Code"]) or backend.UNEXPECTED` →
  "❌ {title} — {hint}" en el panel; el crudo al log técnico.
- `_autosave_tag_log` → `backend.report_path("tags")`.
- Texto en inglés: "Caracteres no permitidos en los tags" → "Characters not allowed in tags".

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
- Nuevo `show_issue(page, issue, *, ref, is_web=False)`: título del `UserIssue`, mensaje, "What you can do:
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
   `parse_combined_report`, `_RedactFilter`, `_StreamToLogger` y `log_dir` (funciones puras).
