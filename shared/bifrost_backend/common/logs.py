"""Logging técnico común a bifrost-mount y bifrost-transfer.

Un solo punto de configuración: consola (stdout) siempre y, en escritorio, un fichero por sesión en la
carpeta estándar del sistema operativo. Los print() existentes se redirigen al logger para que nada se pierda
mientras se migra el código.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import sys
import threading
from datetime import datetime
from importlib import metadata
from pathlib import Path

_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-7s [%(name)s] %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"
KEEP_SESSIONS = 30
# `flet run` pasa este prefijo a la app y espera una línea "PAGE_URL_…" sin modificar en stdout.
_PASSTHROUGH_PREFIX = os.environ.get("FLET_DISPLAY_URL_PREFIX")
# App empaquetada con `flet build`: su arranque (serious_python) define esta variable y manda stdout/stderr a
# un console.log propio, que se vacía en cada arranque y que su sys.exit cierra.
_PACKAGED = "FLET_PYTHON_CALLBACK_SOCKET_ADDR" in os.environ


def log_dir(app: str) -> Path:
    """Carpeta estándar de logs del SO para la app ('mount' | 'transfer')."""
    system = platform.system()
    if system == "Darwin":
        base = Path.home() / "Library" / "Logs" / "BIFROST"
    elif system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "IRB" / "BIFROST"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "bifrost"
    return base / app


def _prune(folder: Path, pattern: str, keep: int) -> None:
    files = sorted(folder.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


class _RedactFilter(logging.Filter):
    """Enmascara secretos aunque alguien los registre por error."""

    _RULES = [
        (re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"), "<jwt>"),
        (re.compile(r"(?i)\b(password|passwd|secret_access_key|secretaccesskey|session_token|sessiontoken)"
                    r"(\s*[=:]\s*)\S+"), r"\1\2<redacted>"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage().rstrip()   # sin líneas en blanco al final (p. ej. warnings)
        for rx, repl in self._RULES:
            msg = rx.sub(repl, msg)
        record.msg, record.args = msg, None
        return True


class _StreamToLogger:
    """Sustituye a sys.stdout/sys.stderr: cada línea impresa pasa a ser un registro del logger."""

    def __init__(self, logger: logging.Logger, level: int, original, handlers: list[logging.Handler]) -> None:
        self._logger, self._level, self._original = logger, level, original
        self._handlers = handlers        # los del logger "bifrost" (misma lista, no una copia)
        # Reentrante: un manejador de señal (common/shutdown.py) puede escribir mientras el hilo principal
        # está dentro de write(); con un Lock normal se bloquearía a sí mismo.
        self._buf, self._lock = "", threading.RLock()
        self._busy = threading.local()   # evita bucles si un handler falla y escribe en stderr

    def write(self, data: str) -> int:
        if getattr(self._busy, "on", False):
            try:
                self._original.write(data)
            except Exception:
                pass
            return len(data)
        with self._lock:
            self._buf += data
            lines = self._buf.split("\n")
            self._buf = lines.pop()
        self._emit(lines)
        return len(data)

    def flush(self) -> None:
        with self._lock:
            rest, self._buf = self._buf, ""
        self._emit([rest])

    def _emit(self, lines: list[str]) -> None:
        self._busy.on = True
        try:
            for line in lines:
                if _PASSTHROUGH_PREFIX and line.startswith(_PASSTHROUGH_PREFIX):
                    # Protocolo de `flet run`: lee esta línea tal cual del stdout para abrir la ventana.
                    self._original.write(line + "\n")
                    self._original.flush()
                elif line.strip():
                    self._dispatch(line.rstrip())
        finally:
            self._busy.on = False

    def _dispatch(self, msg: str) -> None:
        # Se entrega el registro a los handlers sin pasar por Logger.handle(): algunas versiones de Python
        # (p. ej. 3.13.5, la del cluster) descartan los registros creados mientras otro registro se procesa
        # en el mismo hilo, y así se perdía lo que Hypercorn escribe en stderr desde su propio handler.
        record = self._logger.makeRecord(self._logger.name, self._level, "(stream)", 0, msg, None, None)
        for handler in self._handlers:
            if record.levelno >= handler.level:
                handler.handle(record)

    def isatty(self) -> bool:
        return False                      # sin colores ANSI en el log

    def __getattr__(self, name):          # encoding, errors, fileno, buffer… del stream original
        if name.startswith("_"):
            raise AttributeError(name)    # evita recursión si _original aún no existe (copy/pickle)
        return getattr(self._original, name)


def setup_logging(app: str, *, is_web: bool, version: str) -> Path | None:
    """Configura el log técnico de la app ('mount' | 'transfer'). Idempotente.

    Devuelve la ruta del fichero de la sesión (None en web, donde solo se escribe en stdout).
    """
    root = logging.getLogger("bifrost")
    if root.handlers:
        return None
    root.setLevel(logging.DEBUG)
    root.propagate = False
    formatter, redact = logging.Formatter(_FORMAT, _DATEFMT), _RedactFilter()
    level_name = os.environ.get("BIFROST_LOG_LEVEL", "DEBUG" if is_web else "INFO").upper()

    def _add_handler(handler: logging.Handler, level: int) -> None:
        handler.setLevel(level)
        handler.setFormatter(formatter)
        handler.addFilter(redact)
        root.addHandler(handler)

    log_file, file_error = None, None
    if not is_web:
        d = log_dir(app)
        try:
            d.mkdir(parents=True, exist_ok=True)
            _prune(d, f"bifrost-{app}-*.log", KEEP_SESSIONS - 1)
            log_file = d / f"bifrost-{app}-{datetime.now():%Y-%m-%d_%H-%M-%S}.log"
            _add_handler(logging.FileHandler(log_file, encoding="utf-8"), logging.DEBUG)
        except OSError as ex:
            log_file, file_error = None, f"Cannot create log file in {d}: {ex}"

    # En la app empaquetada la consola solo duplicaría el fichero de sesión (ver _PACKAGED); se mantiene
    # si el fichero no se ha podido crear, para no quedarse sin log.
    console = sys.stdout                     # main.py ya lo ha reenvuelto en UTF-8
    if console is not None and not (_PACKAGED and log_file):
        _add_handler(logging.StreamHandler(console), getattr(logging, level_name, logging.INFO))
    if file_error:
        root.warning(file_error)

    # warnings.warn (DeprecationWarning…) → un único registro con su línea de código, no dos líneas sueltas
    logging.captureWarnings(True)
    py_warnings = logging.getLogger("py.warnings")
    py_warnings.handlers = list(root.handlers)
    py_warnings.propagate = False

    if console is not None:
        sys.stdout = _StreamToLogger(logging.getLogger("bifrost.print"), logging.INFO, console, root.handlers)
    if sys.stderr is not None:
        sys.stderr = _StreamToLogger(logging.getLogger("bifrost.stderr"), logging.WARNING, sys.stderr, root.handlers)

    def _excepthook(exc_type, exc, tb):
        root.critical("Unhandled exception", exc_info=(exc_type, exc, tb))

    def _thread_excepthook(args):
        name = args.thread.name if args.thread else "?"
        root.critical("Unhandled exception in thread %s", name,
                      exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook

    try:
        flet_version = metadata.version("flet")
    except metadata.PackageNotFoundError:
        flet_version = "?"
    root.info("==== BIFROST %s %s — session start ====", app, version)
    root.info("mode=%s no_ldap=%s pid=%s", "web" if is_web else "desktop",
              os.environ.get("BIFROST_NO_LDAP") == "1", os.getpid())
    root.info("os=%s arch=%s python=%s flet=%s", platform.platform(), platform.machine(),
              platform.python_version(), flet_version)
    root.info("log_file=%s", log_file or "stdout")
    if is_web:
        root.info("session_dir=%s", os.environ.get("BIFROST_SESSION_DIR") or "(not set)")
    return log_file
