"""Interpretación de la salida de rclone copy / check para el usuario.

La salida cruda va al log técnico; RunSummary convierte los eventos de una ejecución en líneas para el panel,
un resultado final (`outcome`) y el detalle para el informe de la operación.

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
from collections import deque
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
    path: str          # fichero o carpeta, relativo al origen
    issue: UserIssue
    detail: str        # mensaje original de rclone (para el informe)


_ERROR_LEVELS = ("error", "critical", "fatal", "emergency")
_ATTEMPT = re.compile(r"^Attempt (\d+)/(\d+) failed")
_CHECK_TOTAL = re.compile(r"^(\d+) (files missing|differences found|errors while checking|matching files|"
                          r"hashes could not be checked)$")
_STATS_LOG_EVERY = 60.0    # s entre líneas de estadísticas en el log técnico
MAX_LISTED = 20            # elementos por lista en el panel; la lista completa va al informe
MAX_CURRENT = 3            # ficheros en curso que se muestran en la línea de progreso

# Resultados (`outcome`)
OK, NOTHING_NEW, EMPTY, DRY_RUN, PARTIAL, FAILED, CANCELLED = (
    "ok", "nothing_new", "empty", "dry_run", "partial", "failed", "cancelled")
DIFFERENCES, UNVERIFIED = "differences", "unverified"


class RunSummary:
    """Acumula la salida JSON de un rclone copy o check y produce lo que ve el usuario.

    Uso: `feed()` por cada línea de rclone (devuelve líneas para el panel), `finish()` al terminar y después
    `final_lines()` y `report_lines()`. `feed()` nunca lanza excepciones: un fallo del parser no puede cortar
    la copia.

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
        self.replaced: set[str] = set()
        self.would_copy: set[str] = set()                  # --dry-run
        self.nothing_to_transfer = False
        self._attempt_errors: dict[str, Problem] = {}      # errores de fichero del intento en curso
        self._last_attempt: tuple[int, int, dict[str, Problem]] | None = None
        self.retried = False
        # copy y check
        self.folders: dict[str, Problem] = {}              # carpetas que no se pudieron leer
        self.general_errors: list[str] = []                # errores que no son de un fichero
        self.plain_lines: deque[str] = deque(maxlen=MAX_LISTED)   # salida que no es JSON (p. ej. rc 2)
        self.internal_error: str | None = None             # BIFROST no pudo lanzar o leer rclone
        # check
        self.check_totals: dict[str, int] = {}
        self.object_errors: dict[str, str] = {}            # fichero → mensaje (check)
        self.no_common_hash = False
        self.missing: list[str] = []                       # se rellenan en finish() desde los ficheros
        self.different: list[str] = []                     #   de informe del check
        self.unreadable: dict[str, Problem] = {}
        self._copying = False
        self._events = 0                                   # líneas JSON recibidas
        self._last_stats_log = 0.0

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
            log.warning("%s %s: %s", self.operation, obj or "-", msg)
            return self._on_error(level, msg, obj, obj_type, is_object)

        if msg.startswith(("Copied (", "Multi-thread Copied (")):   # el segundo, ficheros grandes por partes
            # No se registra cada fichero copiado en el log técnico (mínimo de datos personales).
            self.copied.add(obj)
            if "replaced existing" in msg:
                self.replaced.add(obj)
        elif msg.startswith("Skipped copy as --dry-run"):
            self.would_copy.add(obj)
        elif msg == "There was nothing to transfer":
            self.nothing_to_transfer = True
        elif msg.startswith("Checks finished"):
            self._copying = True
        elif m := _CHECK_TOTAL.match(msg):
            self.check_totals[m[2]] = int(m[1])
            log.info("%s: %s", self.operation, msg)
        else:
            log.debug("%s %s: %s", self.operation, obj or "-", msg)
        return []

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
            if self.operation == "copy":
                issue = classify(error_text(msg, obj)) or UNEXPECTED
                self._attempt_errors[obj] = Problem(obj, issue, msg)
            else:
                self.object_errors.setdefault(obj, msg)
            return []
        if "failed to open directory" in msg or (obj_type == "string" and obj):
            issue = classify(error_text(msg, obj)) or UNEXPECTED
            self.folders.setdefault(obj, Problem(obj, issue, msg))
            return []
        if msg.startswith("No common hash found"):
            self.no_common_hash = True
            return []
        self.general_errors.append(msg)
        return []

    # ── final ────────────────────────────────────────────────────────────

    def add_internal_error(self, text: str) -> None:
        """BIFROST no pudo lanzar rclone o leer su salida."""
        self.internal_error = text

    def finish(self, rc: int | None, cancelled: bool, check_reports: dict[str, Path] | None = None) -> str:
        """Fija el resultado. `check_reports`: ficheros --missing-on-dst/--differ/--error del check."""
        self.rc = rc
        if self.operation == "check":
            if check_reports:
                self._load_check_reports(check_reports)
            else:
                self._split_check_errors_by_text()
        self.outcome = self._decide_outcome(rc, cancelled)
        return self.outcome

    def failed_files(self) -> dict[str, Problem]:
        """Ficheros que siguen fallando al terminar la copia (los del último intento)."""
        if self.rc == 0:
            return {}
        if self._last_attempt and self._last_attempt[0] == self._last_attempt[1]:
            return self._last_attempt[2]
        return self._attempt_errors

    def _load_check_reports(self, reports: dict[str, Path]) -> None:
        """Lee los ficheros de informe del check línea a línea (pueden ser muy grandes)."""
        def read(key: str) -> list[str]:
            path = reports.get(key)
            if not path or not Path(path).exists():
                return []
            with open(path, encoding="utf-8", errors="replace") as fh:
                return [ln.rstrip("\n") for ln in fh if ln.strip()]
        self.missing = read("missing")
        self.different = read("differ")
        known = set(self.missing) | set(self.different)
        error_paths = read("error")
        for path in error_paths + [p for p in self.object_errors if p not in known and p not in error_paths]:
            msg = self.object_errors.get(path, "")
            issue = classify(error_text(msg, path)) or UNEXPECTED
            self.unreadable[path] = Problem(path, issue, msg)

    def _split_check_errors_by_text(self) -> None:
        """Sin ficheros de informe (no se pudieron crear): se reparten los errores por su texto."""
        for path, msg in self.object_errors.items():
            if msg.startswith("file not in"):
                self.missing.append(path)
            elif msg.endswith(" differ"):
                self.different.append(path)
            else:
                self.unreadable[path] = Problem(path, classify(error_text(msg, path)) or UNEXPECTED, msg)

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
        if self.missing or self.different or self.unreadable or self.folders:
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
        """Resumen para el panel (y el informe). Llamar después de finish()."""
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

    def _problem_list(self, problems: list[Problem], label: str = "") -> list[str]:
        out = [f"❌ {label}{p.path}: {p.issue.title}" for p in problems[:MAX_LISTED]]
        if len(problems) > MAX_LISTED:
            out.append(f"   … and {len(problems) - MAX_LISTED} more (full list in the report).")
        return out

    def _hints(self, problems: list[Problem]) -> list[str]:
        hints = list(dict.fromkeys(p.issue.hint_for(self.is_web) for p in problems if p.issue.hint))
        return [f"   What you can do: {h}" for h in hints[:3]]

    def _copy_lines(self, o: str | None) -> list[str]:
        n = len(self.copied)
        if o == CANCELLED:
            return ["⏹ Copy cancelled. Files already copied stay in MinIO."]
        if o == FAILED:
            issue = self.main_issue()
            return [f"❌ The copy could not finish — {issue.title}."] + self._issue_lines(issue)
        if o == DRY_RUN:
            return [f"🧪 Test run (--dry-run): {len(self.would_copy)} file(s) would be copied. "
                    "Nothing was copied to MinIO."]
        if o == EMPTY:
            return ["✅ Nothing to copy: the source folder is empty, or all its files are excluded."]
        if o == NOTHING_NEW:
            return ["✅ Nothing new to copy: the files were already in MinIO."]
        lines: list[str] = []
        if o == OK:
            again = " (some files needed another try)" if self.retried else ""
            lines.append(f"✅ Copy finished: {n} file(s) copied to MinIO{again}.")
        else:  # PARTIAL
            failed = list(self.failed_files().values())
            folders = list(self.folders.values())
            parts = [f"{n} file(s) copied"]
            if failed:
                parts.append(f"{len(failed)} file(s) not copied")
            if folders:
                parts.append(f"{len(folders)} folder(s) could not be read")
            lines.append("⚠️ Copy finished with problems: " + ", ".join(parts) + ".")
            for p in folders[:MAX_LISTED]:
                lines.append(f"⚠️ Folder “{p.path}” could not be read — its files were NOT copied "
                             f"({p.issue.title}).")
            lines += self._problem_list(failed)
            lines += self._hints(folders + failed)
            lines.append("   Files already copied stay in MinIO. After fixing the problem, copy again: "
                         "files already copied are skipped.")
        if self.replaced:
            lines.append(f"⚠️ {len(self.replaced)} file(s) replaced a different file with the same name "
                         "that was already in MinIO (see the report).")
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
            return [f"✅ Check finished: all {matching} file(s) are in MinIO and identical."]
        if o == EMPTY:
            return ["⚠️ Check finished: there was nothing to compare (the source folder is empty, or all its "
                    "files are excluded)."]
        if o == UNVERIFIED:
            return [f"⚠️ Check finished: {matching} file(s) identical; {uncompared or 'some'} file(s) are in MinIO "
                    "with the same size, but their content could not be compared (no checksum available)."]
        unreadable = list(self.unreadable.values()) + list(self.folders.values())
        lines = [f"⚠️ Check finished: {matching} identical · {len(self.missing)} missing in MinIO · "
                 f"{len(self.different)} different · {len(unreadable)} could not be read."]
        if self.missing:
            lines += self._name_list(self.missing, "Missing in MinIO")
            lines.append("   What you can do: copy the folder again (files already in MinIO are skipped).")
        if self.different:
            lines += self._name_list(self.different, "Different from the original")
            lines.append("   What you can do: do not delete the original. Contact ITS and send them the report.")
        if unreadable:
            lines += self._problem_list(unreadable, "Could not be read: ")
            lines += self._hints(unreadable)
        if uncompared or self.no_common_hash:
            lines.append(f"⚠️ The content of {uncompared or 'some'} file(s) could not be compared "
                         "(no checksum available); only their size was checked.")
        return lines

    def _name_list(self, names: list[str], label: str) -> list[str]:
        out = [f"{label}:"] + [f"   • {n}" for n in names[:MAX_LISTED]]
        if len(names) > MAX_LISTED:
            out.append(f"   … and {len(names) - MAX_LISTED} more (full list in the report).")
        return out

    def report_lines(self) -> list[str]:
        """Detalle completo para el informe de la operación (solo los elementos con problemas)."""
        out = [f"Result: {self.outcome} (exit code {self.rc})"]
        if self.operation == "copy":
            out.append(f"Files copied: {len(self.copied)}")
            for title, items in (("Files not copied", list(self.failed_files().values())),
                                 ("Folders that could not be read", list(self.folders.values()))):
                if items:
                    out += [f"{title} ({len(items)}):"] + [f"  {p.path} — {p.issue.title} — {p.detail}"
                                                           for p in items]
            if self.replaced:
                out += [f"Files that replaced a different file in MinIO ({len(self.replaced)}):"]
                out += [f"  {p}" for p in sorted(self.replaced)]
        else:
            out.append("Totals reported by the check: " + ", ".join(f"{v} {k}" for k, v in self.check_totals.items()))
            for title, names in (("Missing in MinIO", self.missing), ("Different", self.different)):
                if names:
                    out += [f"{title} ({len(names)}):"] + [f"  {n}" for n in names]
            unreadable = list(self.unreadable.values()) + list(self.folders.values())
            if unreadable:
                out += [f"Could not be read ({len(unreadable)}):"]
                out += [f"  {p.path} — {p.issue.title} — {p.detail}" for p in unreadable]
        if self.general_errors:
            out += ["Other errors:"] + [f"  {e}" for e in self.general_errors[:50]]
        if self.internal_error:
            out.append(f"Internal error: {self.internal_error}")
        return out


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


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"
