"""Interpretación de la salida de rclone copy / check para el usuario.

RunSummary convierte los eventos de una ejecución en líneas para el panel (que también son el informe de la
operación) y un resultado final (`outcome`). El panel no nombra ficheros: una copia masiva puede tener miles.
El informe añade la lista de ficheros con problemas (distintos, ilegibles, no copiados o que sustituyeron a otro
en MinIO; hasta MAX_REPORTED_NAMES), y el log técnico, cada tipo de error sin el nombre del fichero. Nunca se nombran los
copiados, los que ya estaban ni los que faltan (se arreglan volviendo a copiar y pueden ser todos).

Se apoya en lo que rclone documenta (https://rclone.org/docs/, https://rclone.org/commands/rclone_check/):
los campos del log JSON (level, msg, object, objectType, stats), los ficheros de informe del check y el
código de salida. El texto de los mensajes no está documentado y puede cambiar entre versiones: solo se usa
para traducir errores (UserIssue) y, si no se reconoce, el usuario ve UNEXPECTED y el texto completo queda en
el log técnico. Al actualizar rclone, repetir la fase 0 del plan
(docs/superpowers/plans/PLAN-logging-improvements.md).
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("bifrost.rclone")


# ============================================================================
# ERRORES PARA EL USUARIO
# ============================================================================

@dataclass(frozen=True)
class UserIssue:
    code: str                    # estable; aparece en el log técnico
    title: str                   # título corto
    message: str                 # qué ha pasado, en lenguaje sencillo
    hint: str = ""               # qué puede hacer el usuario ("" si no puede hacer nada)
    web_hint: str | None = None  # pista en Open OnDemand, si es distinta

    def hint_for(self, is_web: bool) -> str:
        return self.web_hint if (is_web and self.web_hint is not None) else self.hint


_CONTACT_ITS = "If it keeps happening, contact ITS and send them the report saved at the end of this log."

# Orden = prioridad. CREDENTIALS_EXPIRED va antes que MINIO_PERMISSION: MinIO responde a una clave no válida
# con "StatusCode: 403 … InvalidAccessKeyId" (comprobado, fase 0).
_CATALOG: list[tuple[re.Pattern, UserIssue]] = [
    (re.compile(r"\b(ExpiredToken|InvalidAccessKeyId|InvalidTokenId|InvalidToken|SignatureDoesNotMatch)\b"),
     UserIssue("CREDENTIALS_EXPIRED", "MinIO access expired",
               "Your temporary MinIO access pass is no longer valid.",
               "Click “🔑 Renew credentials” and try again.")),
    # Sensible a mayúsculas a propósito: una carpeta "worm_project" no es un error de WORM.
    (re.compile(r"didn't find section in config file"),
     UserIssue("PROFILE_MISSING", "MinIO access not set up",
               "BIFROST cannot find your MinIO access settings on this computer.",
               "Click “🔑 Renew credentials” and try again.")),
    (re.compile(r"\bObjectLocked\b|\bWORM\b"),
     UserIssue("WORM_PROTECTED", "File already in MinIO",
               "A file with the same name is already in this MinIO folder and it cannot be replaced.",
               "The file already in MinIO is kept. If you also need this version, copy it into a new folder "
               "(for example, one named with today's date).")),
    (re.compile(r"\bAccessDenied\b|403 Forbidden|status ?code: 403", re.I),
     UserIssue("MINIO_PERMISSION", "No permission in MinIO",
               "You do not have permission to read or write in this MinIO folder.",
               "Check that you chose the right folder. If you need access, ask your group's data manager.")),
    (re.compile(r"\bNoSuchBucket\b"),
     UserIssue("BUCKET_NOT_FOUND", "MinIO folder not found",
               "The MinIO folder does not exist or you cannot see it.",
               "Choose the folder again from the list.")),
    (re.compile(r"no such host|dial tcp|connection refused|connection reset|i/o timeout|timed out|"
                r"TLS handshake timeout|network is unreachable|Could not connect to the endpoint|"
                r"Connect timeout|Read timeout|context deadline exceeded", re.I),
     UserIssue("NETWORK", "Connection problem",
               "BIFROST lost the connection to a server (MinIO, or the SFTP server if you are copying from one).",
               "Check that the Nexica VPN is on and try again.",
               web_hint="Try again in a few minutes. " + _CONTACT_ITS)),
    (re.compile(r"\bRequestTimeTooSkewed\b"),
     UserIssue("CLOCK_SKEW", "Your computer's clock is wrong",
               "MinIO rejected the request because the date or time of the computer is not correct.",
               "Set the date and time to automatic and try again.",
               web_hint="Try again in a few minutes. " + _CONTACT_ITS)),
    (re.compile(r"\b(SlowDown|ServiceUnavailable|InternalError|XMinioServerNotInitialized)\b|status ?code: 50[234]",
                re.I),
     UserIssue("MINIO_BUSY", "MinIO is busy",
               "The MinIO server could not answer right now.",
               "Wait a few minutes and try again.")),
    (re.compile(r"no space left on device", re.I),
     UserIssue("DISK_FULL", "Not enough space",
               "There is no free space left where the data is being written.",
               "Free some space and try again.")),
    (re.compile(r"being used by another process", re.I),
     UserIssue("FILE_IN_USE", "A file is open in another program",
               "Another program has a file of the source open, so it cannot be read.",
               "Close the program that is using it and copy again.")),
    (re.compile(r"corrupted on transfer|source file is being updated", re.I),
     UserIssue("SOURCE_CHANGING", "A file changed while it was being copied",
               "The file was modified during the copy, so the copy was not kept.",
               "Wait until the instrument or program has finished writing it, then copy again.")),
    (re.compile(r"permission denied|access is denied", re.I),
     UserIssue("SOURCE_PERMISSION", "Cannot open a file or folder",
               "BIFROST is not allowed to open a file or folder.",
               "Check that you have permission to open it. If not, ask the owner of the folder.")),
    (re.compile(r"directory not found|file not found|no such file or directory|cannot find the (file|path)",
                re.I),
     UserIssue("SOURCE_NOT_FOUND", "Source not found",
               "The file or folder does not exist (it may have been moved or renamed).",
               "Check the source path and try again.")),
]

UNEXPECTED = UserIssue("UNEXPECTED", "Something went wrong",
                       "BIFROST could not finish the operation.",
                       "Try again. " + _CONTACT_ITS)

# https://rclone.org/docs/#exit-code
_EXIT = {
    2: UserIssue("RCLONE_OPTIONS", "Options not valid",
                 "The options in “Additional rclone flags (advanced)” were not accepted.",
                 "Check them, or restore the default values, and try again."),
    3: UserIssue("SOURCE_NOT_FOUND", "Folder not found",
                 "The source or destination folder does not exist.",
                 "Check both paths and try again."),
    4: UserIssue("SOURCE_NOT_FOUND", "File not found",
                 "The source file does not exist.",
                 "Check the source path and try again."),
    5: UserIssue("TEMPORARY", "Temporary problem",
                 "Some files failed because of a temporary problem.",
                 "Try again: files already copied are skipped."),
    8: UserIssue("TRANSFER_LIMIT", "Transfer limit reached",
                 "The limit set in “Additional rclone flags (advanced)” (--max-transfer) was reached, so not "
                 "all files were copied.",
                 "Copy again to continue: files already copied are skipped."),
    10: UserIssue("TIME_LIMIT", "Time limit reached",
                  "The time limit set in “Additional rclone flags (advanced)” (--max-duration) was reached, so "
                  "not all files were copied.",
                  "Copy again to continue: files already copied are skipped."),
    7: UserIssue("FATAL", "The operation stopped",
                 "It stopped because of a problem that trying again will not fix.",
                 "Contact ITS and send them the report saved at the end of this log."),
}

# Rutas y textos entre comillas: se quitan antes de clasificar para que el nombre de una carpeta
# ("worm_project", "refused_cells"…) no se confunda con un error.
_PATHLIKE = re.compile(r'"[^"]*"|(?:[A-Za-z]:\\|/)[^\s"]*')


def error_text(msg: str, obj: str = "") -> str:
    """Texto del error sin el nombre del elemento ni rutas, para clasificarlo."""
    text = msg.replace(obj, "<item>") if obj else msg
    return _PATHLIKE.sub("<path>", text)


def classify(text: str) -> UserIssue | None:
    for rx, issue in _CATALOG:
        if rx.search(text or ""):
            return issue
    return None


# ============================================================================
# RESUMEN DE UNA EJECUCIÓN
# ============================================================================

@dataclass(frozen=True)
class Problem:
    issue: UserIssue
    detail: str        # mensaje original de rclone


_ERROR_LEVELS = ("error", "critical", "fatal", "emergency")
_ATTEMPT = re.compile(r"^Attempt (\d+)/(\d+) failed")
_CHECK_TOTAL = re.compile(r"^(\d+) (files missing|differences found|errors while checking|matching files|"
                          r"hashes could not be checked)$")
_HASH_USED = re.compile(r"^Using (\w+) for hash comparisons")
_MIN_FREE_TEMP = 1024 * 1024  # con menos espacio libre, la lista --match puede haber quedado cortada (rclone no avisa)
_STATS_LOG_EVERY = 60.0    # s entre líneas de estadísticas en el log técnico
MAX_PLAIN_LINES = 20       # líneas de salida no JSON que se guardan (errores de opciones de rclone)
MAX_REPORTED_NAMES = 100   # ficheros con problemas que se nombran en el informe de la operación
MAX_LOGGED_ERRORS = 100    # textos de error distintos (sin nombres) que se escriben en el log técnico
MAX_CURRENT = 3            # ficheros en curso que se muestran en la línea de progreso

# Resultados (`outcome`)
OK, NOTHING_NEW, EMPTY, DRY_RUN, PARTIAL, FAILED, CANCELLED = (
    "ok", "nothing_new", "empty", "dry_run", "partial", "failed", "cancelled")
DIFFERENCES, UNVERIFIED = "differences", "unverified"


class RunSummary:
    """Acumula la salida JSON de un rclone copy o check y produce lo que ve el usuario.

    Uso: `feed()` por cada línea de rclone (devuelve líneas para el panel), `finish()` al terminar y después
    `final_lines()` y `log_line()`. `feed()` nunca lanza excepciones: un fallo del parser no puede cortar la copia.

    Solo se guardan nombres donde hacen falta para contar bien: los copiados (para no contar como "ya estaban"
    los que se subieron en un intento anterior), los que fallan en cada intento y las carpetas o ficheros que
    no se pudieron leer (rclone puede dar varios errores del mismo). Lo demás son recuentos. Un recuento que no
    se puede asegurar queda en None y el texto no da número: nunca se muestra uno inventado.

    El progreso no va al panel de log: la pantalla llama a `progress_snapshot()` una vez por segundo desde su
    propio temporizador. Así el hilo que lee rclone solo guarda el último estado y nunca espera a la
    interfaz (si dejara de leer, la salida de rclone se llenaría y la copia se pararía).
    """

    def __init__(self, operation: str, *, is_web: bool = False, dry_run: bool = False) -> None:
        if operation not in ("copy", "check"):
            raise ValueError(operation)
        self.operation, self.is_web, self.dry_run = operation, is_web, dry_run
        self.stats: dict = {}
        self.outcome: str | None = None
        self.rc: int | None = None
        # copy
        self.copied: set[str] = set()
        self.copied_bytes = 0
        self.replaced = 0                                  # sustituyeron un fichero distinto del mismo nombre
        self._replaced_names: list[str] = []               #   los primeros (para el informe)
        self.would_copy = 0                                # --dry-run
        self.would_copy_bytes = 0
        self.unchanged: int | None = None                  # ya idénticos en MinIO, no copiados (None: no se sabe)
        self.nothing_to_transfer = False
        self._attempt_errors: dict[str, Problem] = {}      # ficheros que fallan en el intento en curso
        self._last_attempt: tuple[int, int, dict[str, Problem]] | None = None
        self.retried = False
        # copy y check
        self.folders: dict[str, Problem] = {}              # carpetas que no se pudieron leer
        self.general_errors: list[str] = []                # errores que no son de un fichero
        self.plain_lines: deque[str] = deque(maxlen=MAX_PLAIN_LINES)   # salida que no es JSON (p. ej. rc 2)
        self.internal_error: str | None = None             # BIFROST no pudo lanzar o leer rclone
        # check: los recuentos salen de los totales de rclone en finish() (respaldo: listas o mensajes)
        self.check_totals: dict[str, int] = {}
        self.missing = 0
        self.different = 0
        self.unreadable_count = 0                          # ficheros y carpetas que no se pudieron leer
        self.unreadable: dict[str, Problem] = {}           #   los ficheros, con su causa
        self._different_names: dict[str, str] = {}         # los primeros distintos (para el informe)
        self.hash: str | None = None                       # huella usada para comparar ("md5"; "none")
        self.no_common_hash = False
        self._copying = False
        self._events = 0                                   # líneas JSON recibidas
        self._last_stats_log = 0.0
        self._logged_errors: set[str] = set()              # textos de error ya escritos en el log técnico
        self._unlogged_errors = 0                          # errores no escritos por el límite

    # ── lectura ──────────────────────────────────────────────────────────

    def feed(self, raw: str, now: float) -> list[str]:
        """Procesa una línea de rclone y devuelve 0..n líneas para el panel."""
        try:
            return self._feed(raw, now)
        except Exception:
            log.exception("%s: could not interpret a line of rclone output: %r", self.operation, raw[:300])
            return []

    def _feed(self, raw: str, now: float) -> list[str]:
        line = raw.rstrip("\r\n")
        if not line.strip():
            return []
        try:
            ev = json.loads(line)
        except ValueError:
            ev = None
        if not isinstance(ev, dict):
            self.plain_lines.append(line)
            log.info("%s rclone: %s", self.operation, line)
            return []
        self._events += 1

        if "stats" in ev:
            return self._on_stats(ev["stats"], now)

        level = str(ev.get("level", ""))
        msg = str(ev.get("msg") or "").strip()
        obj = str(ev.get("object") or "")
        obj_type = str(ev.get("objectType") or "")
        is_object = obj_type.endswith("Object")

        if level in _ERROR_LEVELS:
            if obj:
                self._log_file_error(obj, msg)
            else:
                log.warning("%s: %s", self.operation, error_text(msg))   # sin rutas (pueden nombrar ficheros)
            return self._on_error(level, msg, obj, obj_type, is_object)

        if msg.startswith(("Copied (", "Multi-thread Copied (")):   # el segundo, ficheros grandes por partes
            # No se registra cada fichero copiado en el log técnico (mínimo de datos personales).
            if obj not in self.copied:
                self.copied_bytes += _size(ev)
                if "replaced existing" in msg:
                    self.replaced += 1
                    if len(self._replaced_names) < MAX_REPORTED_NAMES:
                        self._replaced_names.append(obj)
            self.copied.add(obj)
        elif msg.startswith("Skipped copy as --dry-run"):
            self.would_copy += 1
            self.would_copy_bytes += _size(ev)
        elif msg == "There was nothing to transfer":
            self.nothing_to_transfer = True
        elif msg.startswith("Checks finished"):
            self._copying = True
        elif m := _CHECK_TOTAL.match(msg):
            self.check_totals[m[2]] = int(m[1])
            log.info("%s: %s", self.operation, msg)
        elif m := _HASH_USED.match(msg):
            self.hash = m[1]
        else:
            log.debug("%s: %s", self.operation, msg)      # sin el nombre del objeto
        return []

    def _log_file_error(self, obj: str, msg: str) -> None:
        """Al log técnico, el error de un fichero sin su nombre ni rutas, una vez por texto distinto.

        Los nombres van al informe (problem_lines). Los que faltan en MinIO no se registran: pueden ser todos.
        """
        if msg.startswith("file not in"):
            return
        text = error_text(msg, obj)
        if text in self._logged_errors:
            return
        if len(self._logged_errors) < MAX_LOGGED_ERRORS:
            self._logged_errors.add(text)
            log.warning("%s: %s", self.operation, text)
        else:
            self._unlogged_errors += 1

    def _on_stats(self, stats: dict, now: float) -> list[str]:
        # Se sustituye el dict entero: progress_snapshot() lo lee desde otro hilo sin bloqueos.
        self.stats = stats if isinstance(stats, dict) else {}
        if now - self._last_stats_log >= _STATS_LOG_EVERY:
            self._last_stats_log = now
            # Solo números: los nombres de los ficheros en curso no van al log técnico.
            log.info("%s stats: %s", self.operation, {k: self.stats.get(k) for k in (
                "transfers", "totalTransfers", "bytes", "totalBytes", "checks", "totalChecks", "errors")})
        return []

    def _on_error(self, level: str, msg: str, obj: str, obj_type: str, is_object: bool) -> list[str]:
        if m := _ATTEMPT.match(msg):
            n, total = int(m[1]), int(m[2])
            failed_now = len(self._attempt_errors)
            self._last_attempt = (n, total, self._attempt_errors)
            self._attempt_errors = {}
            if n < total:
                self.retried = True
                what = f"{failed_now} file(s) failed" if failed_now else "There were errors"
                return [f"🔁 {what} in attempt {n} of {total} — trying again "
                        f"(files already copied are skipped).\n"]
            return []
        if msg.startswith("Can't retry any of the errors"):
            return []
        if is_object and obj:
            problem = Problem(classify(error_text(msg, obj)) or UNEXPECTED, msg)
            if self.operation == "copy":
                self._attempt_errors[obj] = problem
            elif msg.startswith("file not in"):
                self.missing += 1                          # solo se usan si no hay ficheros de informe
            elif msg.endswith(" differ"):                  # "sizes differ", "md5 differ"
                self.different += 1
                if len(self._different_names) < MAX_REPORTED_NAMES:
                    self._different_names.setdefault(obj, msg)
            else:
                self.unreadable.setdefault(obj, problem)
            return []
        if "failed to open directory" in msg or (obj_type == "string" and obj):
            self.folders.setdefault(obj, Problem(classify(error_text(msg, obj)) or UNEXPECTED, msg))
            return []
        if msg.startswith("No common hash found"):
            self.no_common_hash, self.hash = True, "none"
            return []
        self.general_errors.append(msg)
        return []

    # ── final ────────────────────────────────────────────────────────────

    def add_internal_error(self, text: str) -> None:
        """BIFROST no pudo lanzar rclone o leer su salida."""
        self.internal_error = text

    def finish(self, rc: int | None, cancelled: bool, reports: dict[str, Path] | None = None) -> str:
        """Fija el resultado. `reports`: listas que escribe rclone (--match en copy; --missing-on-dst, --differ
        y --error en check). Solo se cuentan sus líneas."""
        self.rc = rc
        if self.operation == "copy":
            self.unchanged = self._count_unchanged((reports or {}).get("match"))
        else:
            self._count_check_results(reports or {})
        if self._unlogged_errors:
            log.warning("%s: %d more file error(s) of other kinds not logged (limit %d)", self.operation,
                        self._unlogged_errors, MAX_LOGGED_ERRORS)
        self.outcome = self._decide_outcome(rc, cancelled)
        return self.outcome

    def _count_unchanged(self, match: Path | None) -> int | None:
        """Ficheros que ya estaban idénticos en MinIO (lista --match), o None si la lista no es fiable.

        Si el disco temporal se llena, rclone corta la lista sin avisar: con poco espacio libre, o si sin
        reintentos hay menos líneas de las que indican sus estadísticas, no se da número.
        """
        if not match or not Path(match).exists():
            return None
        # Los copiados en un intento anterior salen como idénticos en el siguiente: esos sí se subieron.
        lines = sum(1 for name in _lines(match) if name not in self.copied)
        if shutil.disk_usage(Path(match).parent).free < _MIN_FREE_TEMP:
            log.warning("copy: the list of files already in MinIO may be incomplete (temporary disk full)")
            return None
        at_least = (self.stats.get("checks") or 0) - self.replaced - len(self.failed_files())
        if not self.retried and lines < at_least:
            log.warning("copy: the list of files already in MinIO is incomplete (%d lines, at least %d expected)",
                        lines, at_least)
            return None
        return lines

    def _count_check_results(self, reports: dict[str, Path]) -> None:
        """Recuentos del check. Los totales que rclone escribe al terminar son exactos y no dependen del disco;
        si faltan (otra versión de rclone), se cuentan las listas y, sin listas, los mensajes."""
        t = self.check_totals
        if "differences found" in t:
            self.missing = t.get("files missing", 0)
            self.different = t["differences found"] - self.missing
            self.unreadable_count = max(t.get("errors while checking", 0) - t["differences found"], 0)
            return
        if reports:
            self.missing = sum(1 for _ in _lines(reports.get("missing")))
            self.different = sum(1 for _ in _lines(reports.get("differ")))
            for path in _lines(reports.get("error")):
                self.unreadable.setdefault(path, Problem(UNEXPECTED, ""))
        self.unreadable_count = len(self.unreadable) + len(self.folders)

    @property
    def attempts(self) -> int:
        """Intentos que hizo rclone (reintenta toda la operación si hubo errores)."""
        if not self._last_attempt:
            return 1
        n, total, _ = self._last_attempt
        return n if n == total else n + 1

    def log_line(self) -> str:
        """Resultado y recuentos en una línea, para el log técnico (sin nombres de ficheros)."""
        fields = {"outcome": self.outcome, "rc": self.rc}
        if self.operation == "copy":
            fields |= {"copied": len(self.copied), "bytes": self.copied_bytes, "replaced": self.replaced,
                       "unchanged": "unknown" if self.unchanged is None else self.unchanged,
                       "failed": len(self.failed_files()), "folders": len(self.folders), "attempts": self.attempts}
        else:
            t = self.check_totals
            fields |= {"matching": t.get("matching files", 0), "missing": self.missing, "different": self.different,
                       "unreadable": self.unreadable_count, "uncompared": t.get("hashes could not be checked", 0),
                       "hash": self.hash or "unknown"}
        elapsed = self.stats.get("elapsedTime") or 0
        fields["duration"] = f"{elapsed:.0f}s"
        if self.operation == "copy" and elapsed >= 1:
            fields["speed"] = f"{human_size(self.copied_bytes / elapsed)}/s".replace(" ", "")
        return " ".join(f"{k}={v}" for k, v in fields.items())

    def failed_files(self) -> dict[str, Problem]:
        """Ficheros que siguen fallando al terminar la copia (los del último intento)."""
        if self.rc == 0:
            return {}
        if self._last_attempt and self._last_attempt[0] == self._last_attempt[1]:
            return self._last_attempt[2]
        return self._attempt_errors

    def _decide_outcome(self, rc: int | None, cancelled: bool) -> str:
        if cancelled:
            return CANCELLED
        if self.internal_error or rc is None:
            return FAILED
        if not self._events:
            # rclone no ha dicho nada (p. ej. su salida se desvió a otro sitio): no se puede afirmar nada.
            return FAILED
        if self.operation == "copy":
            if rc == 9 and not (self.failed_files() or self.folders):
                return NOTHING_NEW                         # --error-on-no-transfer: no había nada nuevo
            if rc != 0 and not (self.failed_files() or self.folders):
                return FAILED
            if self.failed_files() or self.folders:
                return PARTIAL
            if self.dry_run or self.would_copy:
                return DRY_RUN
            if not self.copied:
                # "Vacío" solo si rclone lo dice (nada que transferir y ningún fichero comparado). Con un fichero
                # suelto ya idéntico en MinIO, rclone no escribe nada y tampoco cuenta comparaciones.
                if self.nothing_to_transfer and not self.stats.get("checks"):
                    return EMPTY
                return NOTHING_NEW
            return OK
        # check: si un error no es de un fichero ni de una subcarpeta (p. ej. no se pudo leer la carpeta de
        # MinIO, objeto "" o nivel critical), los recuentos no son fiables.
        if self.general_errors or "" in self.folders:
            return FAILED
        if self.missing or self.different or self.unreadable_count:
            return DIFFERENCES
        if rc != 0:
            return FAILED
        if self.no_common_hash or self.check_totals.get("hashes could not be checked"):
            return UNVERIFIED
        if not self.check_totals.get("matching files") and not self.stats.get("checks"):
            return EMPTY
        return OK

    # ── textos ───────────────────────────────────────────────────────────

    def progress_snapshot(self) -> dict:
        """Estado actual para la línea de progreso de la pantalla. Se puede llamar desde otro hilo.

        Devuelve {"text", "fraction" (0..1, o None si aún no se sabe), "current" (hasta MAX_CURRENT ficheros
        en curso: name, percentage, bytes, size) y "more" (cuántos más hay en curso)}.
        """
        s = self.stats                                     # referencia al último dict: lectura atómica
        checks = s.get("checks") or 0
        done, total = s.get("transfers") or 0, s.get("totalTransfers") or 0
        done_b, total_b = s.get("bytes") or 0, s.get("totalBytes") or 0
        fraction = None
        # Al principio rclone aún está listando MinIO y el contador vale 0: un "0 checked" parece decir que no
        # ha mirado nada, así que hasta que haya comparaciones no se da número.
        if self.operation == "check":
            text = (f"Comparing files with MinIO: {checks} compared so far" if checks
                    else "Comparing your files with MinIO…")
        elif not self._copying and not done:
            text = (f"Comparing with what is already in MinIO: {checks} file(s) compared so far" if checks
                    else "Comparing your files with what is already in MinIO…")
        elif not total:
            text = "Copying…"
        else:
            text = f"Copying: {done} of {total} files · {human_size(done_b)} of {human_size(total_b)}"
            if s.get("speed"):
                text += f" · {human_size(s['speed'])}/s"
            if s.get("eta"):
                text += f" · about {_duration(s['eta'])} left"
            if total_b:
                fraction = min(done_b / total_b, 1.0)
        current = _current_items(s)
        return {"text": text, "fraction": fraction, "current": current[:MAX_CURRENT],
                "more": max(len(current) - MAX_CURRENT, 0)}

    def main_issue(self) -> UserIssue:
        """El problema que explica un FAILED."""
        if self.rc == 2:
            return _EXIT[2]
        texts = self.general_errors + [p.detail for p in self.folders.values()]
        for text in texts:
            if issue := classify(error_text(text)):
                return issue
        if self.internal_error:
            return classify(self.internal_error) or UNEXPECTED
        return _EXIT.get(self.rc, UNEXPECTED)

    def final_lines(self) -> list[str]:
        """Resumen para el panel (y por tanto para el informe). Llamar después de finish()."""
        o = self.outcome
        if self.operation == "copy":
            lines = self._copy_lines(o)
        else:
            lines = self._check_lines(o)
        return ["\n"] + [ln if ln.endswith("\n") else ln + "\n" for ln in lines]

    def _issue_lines(self, issue: UserIssue) -> list[str]:
        out = [f"   {issue.message}"]
        if hint := issue.hint_for(self.is_web):
            out.append(f"   What you can do: {hint}")
        if issue.code == "RCLONE_OPTIONS":
            out += [f"   Details: {ln.removeprefix('Error: ')}" for ln in self.plain_lines if ln.startswith("Error:")]
        return out

    @staticmethod
    def _by_cause(problems: list[Problem]) -> str:
        """'3 × Cannot open a file or folder, 1 × A file is open in another program': recuento por causa."""
        causes = Counter(p.issue.title for p in problems)
        return ", ".join(f"{n} × {title}" for title, n in causes.most_common())

    def _hints(self, problems: list[Problem]) -> list[str]:
        hints = list(dict.fromkeys(p.issue.hint_for(self.is_web) for p in problems if p.issue.hint))
        return [f"   What you can do: {h}" for h in hints[:3]]

    def _took(self, with_speed: bool = False) -> str:
        """' in 1 h 12 min (8.3 MB/s on average)': duración según las estadísticas finales de rclone."""
        elapsed = self.stats.get("elapsedTime") or 0
        text = f" in {_duration(elapsed)}"
        if with_speed and elapsed >= 1 and self.copied_bytes:
            text += f" ({human_size(self.copied_bytes / elapsed)}/s on average)"
        return text

    def _already_in_minio(self) -> int | str | None:
        """Ficheros que ya estaban idénticos: el número, "some" si se sabe que hay alguno pero no cuántos, o None
        si no se puede saber."""
        if self.unchanged is not None:
            return self.unchanged
        if self.retried:
            return None                                    # las comparaciones se acumulan entre intentos
        # Sin lista fiable: si rclone comparó ficheros de MinIO que luego no sustituyó, alguno ya estaba.
        return "some" if (self.stats.get("checks") or 0) > self.replaced else 0

    def _copy_lines(self, o: str | None) -> list[str]:
        n, size = len(self.copied), human_size(self.copied_bytes)
        if o == CANCELLED:
            if not n:
                return ["⏹ Copy cancelled. No file had been copied yet."]
            return [f"⏹ Copy cancelled{self._took()}. {n} file(s) ({size}) had been copied; they stay in MinIO."]
        if o == FAILED:
            issue = self.main_issue()
            return [f"❌ The copy could not finish — {issue.title}."] + self._issue_lines(issue)
        if o == DRY_RUN:
            return [f"🧪 Test run (--dry-run): {self.would_copy} file(s) would be copied "
                    f"({human_size(self.would_copy_bytes)}). Nothing was copied to MinIO."]
        if o == EMPTY:
            return ["✅ Nothing to copy: the source folder is empty, or all its files are excluded."]
        already = self._already_in_minio()
        lines: list[str] = []
        if o == NOTHING_NEW:
            files = f"the {already} file(s)" if isinstance(already, int) and already else "the files"
            lines.append(f"✅ Nothing new to copy: {files} were already in MinIO with the same content.")
        elif o == OK:
            again = " (some files needed another try)" if self.retried else ""
            lines.append(f"✅ Copy finished: {n} file(s) copied to MinIO ({size}){self._took(True)}{again}.")
            if already:
                lines.append(f"   Files in this copy: {n} copied · {already} already in MinIO.")
        else:  # PARTIAL
            failed = list(self.failed_files().values())
            folders = list(self.folders.values())
            parts = [f"{n} file(s) copied ({size})"]
            if already:
                parts.append(f"{already} already in MinIO")
            if failed:
                parts.append(f"{len(failed)} file(s) not copied")
            if folders:
                parts.append(f"{len(folders)} folder(s) could not be read")
            lines.append("⚠️ Copy finished with problems: " + ", ".join(parts) + ".")
            if folders:
                lines.append(f"⚠️ Folders that could not be read (their files were NOT copied): "
                             f"{self._by_cause(folders)}.")
            if failed:
                lines.append(f"❌ Files not copied: {self._by_cause(failed)}.")
            lines += self._hints(folders + failed)
            lines.append("   The list of these files is in the report. Files already copied stay in MinIO. After "
                         "fixing the problem, copy again: files already copied are skipped.")
        if self.replaced:
            lines.append(f"⚠️ {self.replaced} file(s) replaced a different file with the same name that was "
                         "already in MinIO; their previous tags were replaced too (list in the report).")
        # rclone no mira las etiquetas que ya tienen: no se puede afirmar que sean distintas.
        tags_kept = ("their tags were NOT updated: if their tags in MinIO are different from the ones above, they "
                     "still have the old ones. To change them, use Tag Manager.")
        if already or o == NOTHING_NEW:
            lines.append(f"⚠️ Files already in MinIO were not copied again, so {tags_kept}")
        elif already is None:
            lines.append(f"⚠️ If some files were already in MinIO with the same content, they were not copied "
                         f"again and {tags_kept}")
        if o == OK:
            lines.append("   To confirm that the copy is identical to the original, click ✓ Check data.")
        return lines

    def _check_lines(self, o: str | None) -> list[str]:
        t = self.check_totals
        uncompared = t.get("hashes could not be checked", 0)
        # rclone cuenta como "matching" también los que solo pudo comparar por tamaño (sin checksum común).
        matching = max(t.get("matching files", 0) - uncompared, 0)
        if o == CANCELLED:
            return ["⏹ Check cancelled."]
        if o == FAILED:
            issue = self.main_issue()
            return [f"❌ The check could not finish — {issue.title}."] + self._issue_lines(issue)
        if o == OK:
            how = f" (compared by {self.hash.upper()} checksum)" if self.hash and self.hash != "none" else ""
            return [f"✅ Check finished{self._took()}: all {matching} file(s) are in MinIO and identical{how}."]
        if o == EMPTY:
            return ["⚠️ Check finished: there was nothing to compare (the source folder is empty, or all its "
                    "files are excluded)."]
        if o == UNVERIFIED:
            return [f"⚠️ Check finished{self._took()}: {matching} file(s) identical; {uncompared or 'some'} file(s) "
                    "are in MinIO with the same size, but their content could not be compared (no checksum "
                    "available)."]
        lines = [f"⚠️ Check finished{self._took()}: {matching} identical · {self.missing} missing in MinIO · "
                 f"{self.different} different · {self.unreadable_count} could not be read."]
        if self.missing:
            lines.append("   Missing in MinIO — what you can do: copy the folder again (files already in MinIO "
                         "are skipped).")
        if self.different:
            lines.append("   Different from the original — what you can do: do not delete the original. Contact "
                         "ITS.")
        if self.unreadable_count:
            known = list(self.unreadable.values()) + list(self.folders.values())
            unknown = [Problem(UNEXPECTED, "")] * max(self.unreadable_count - len(known), 0)
            lines.append(f"❌ Could not be read: {self._by_cause(known + unknown)}.")
            lines += self._hints(known)
        if uncompared or self.no_common_hash:
            lines.append(f"⚠️ The content of {uncompared or 'some'} file(s) could not be compared "
                         "(no checksum available); only their size was checked.")
        if self.different or self.unreadable_count:
            lines.append("   The list of the files that are different or could not be read is in the report.")
        return lines

    def problem_lines(self) -> list[str]:
        """Para el informe: ficheros con problemas y su causa, hasta MAX_REPORTED_NAMES en total."""
        if self.operation == "copy":
            failed = self.failed_files()
            groups = [("Files not copied", len(failed), [(p, x.issue.title) for p, x in failed.items()]),
                      ("Folders that could not be read (their files were NOT copied)", len(self.folders),
                       [(p, x.issue.title) for p, x in self.folders.items()]),
                      ("Files that replaced a different file with the same name in MinIO", self.replaced,
                       [(p, "replaced, with the new tags") for p in self._replaced_names])]
        else:
            different = [(p, "different size" if m.startswith("sizes") else f"different {m.split()[0].upper()} "
                          "checksum") for p, m in self._different_names.items()]
            unreadable = {**self.unreadable, **self.folders}
            groups = [("Different from the original", self.different, different),
                      ("Could not be read", self.unreadable_count,
                       [(p, x.issue.title) for p, x in unreadable.items()])]
        out: list[str] = []
        room = MAX_REPORTED_NAMES
        for label, total, items in groups:
            if not total:
                continue
            shown = items[:room]
            room -= len(shown)
            out.append(f"{label} ({total}):")
            out += [f"  {path or '(the source folder)'} — {why}" for path, why in shown]
            if total > len(shown):
                out.append(f"  … and {total - len(shown)} more not listed (the report lists up to "
                           f"{MAX_REPORTED_NAMES} files)")
        return out


def _lines(path: Path | None):
    """Líneas no vacías de una lista de rclone, de una en una (puede tener millones)."""
    if not path or not Path(path).exists():
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            if name := ln.rstrip("\n"):
                yield name


def _current_items(stats: dict) -> list[dict]:
    """Ficheros en curso según rclone (`transferring` al copiar; `checking`, si aparece, al comparar),
    los más grandes primero."""
    items = []
    for t in stats.get("transferring") or []:
        if isinstance(t, dict) and t.get("name"):
            items.append({"name": str(t["name"]), "percentage": t.get("percentage"),
                          "bytes": t.get("bytes") or 0, "size": t.get("size") or 0})
    if not items:
        for c in stats.get("checking") or []:
            name = c.get("name") if isinstance(c, dict) else c
            if name:
                items.append({"name": str(name), "percentage": None, "bytes": 0, "size": 0})
    return sorted(items, key=lambda i: i["size"], reverse=True)


def short_name(name: str, limit: int = 40) -> str:
    """Recorta por el medio una ruta larga: '…' en lugar de la parte central, conservando el final."""
    if len(name) <= limit:
        return name
    keep = limit - 1
    return name[: keep // 3] + "…" + name[-(keep - keep // 3):]


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _size(ev: dict) -> int:
    """Tamaño en bytes que rclone indica en el evento de un fichero (0 si no lo da)."""
    size = ev.get("size")
    return size if isinstance(size, int) and size > 0 else 0


def _duration(seconds: float) -> str:
    if seconds < 1:
        return "less than 1 s"
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"
