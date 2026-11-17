"""Lanzar `rclone mount` y comprobar que el montaje funciona de verdad (buckets de MinIO y shares de la NetApp).

Comprobado en la fase 0 del PR 3 (rclone 1.72.1, fuse-t): rclone monta la carpeta al instante aunque las
credenciales, el bucket o el servidor fallen; solo termina enseguida si el perfil no existe o la carpeta ya está
montada. Por eso el montaje se da por bueno solo cuando se puede listar la carpeta, y la causa de un fallo se
lee del log de rclone. Con un servidor que no responde, rclone tarda unos 4 minutos en rendirse (10 intentos):
la lectura de prueba va en un hilo aparte para que la espera no se quede bloqueada.

El log de rclone es un fichero temporal con solo sus errores: cuando el montaje falla o se desmonta, los errores
pasan al log técnico sin nombres de ficheros (drain_rclone_log) y el fichero se borra.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import subprocess
import threading
import time
from collections import deque
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import NoReturn

from .rclone import _subprocess_kwargs
from .rclone_output import (
    ERROR_LEVELS, ISSUES_BY_CODE, MAX_LOGGED_ERRORS, MOUNT_NOT_ALLOWED, MOUNT_TIMEOUT, UNEXPECTED, UserIssue,
    classify, error_key, error_text,
)

log = logging.getLogger("bifrost.mount")
rclone_log = logging.getLogger("bifrost.rclone")

# Solo errores, en JSON (el nombre del fichero llega aparte, en "object", y se quita entero). Un montaje normal no
# escribe nada; el tope evita que uno de días con errores repetidos llene el disco (~20 MB: el fichero y uno anterior).
_LOG_OPTIONS = ["--use-json-log", "--log-level", "ERROR", "--log-file-max-size", "10M", "--log-file-max-backups", "1"]
_POLL_SECONDS = 0.2
_LOG_TAIL = 50                       # últimas líneas del log de rclone en las que se busca la causa
_ERROR_LINE = re.compile(r"\b(ERROR|CRITICAL)\s*:")
# Fecha que rclone añade al fichero anterior al rotar el log: 2026-11-03T13-44-04.778
_ROTATED_STAMP = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]-[0-9][0-9]-[0-9][0-9].[0-9][0-9][0-9]"


class MountError(Exception):
    """Un montaje que no funciona. `issue` es lo que ve el usuario."""

    def __init__(self, issue: UserIssue) -> None:
        super().__init__(issue.title)
        self.issue = issue


def is_mounted(path: str | Path) -> bool:
    """True si la carpeta está montada. En Windows (WinFsp) la carpeta solo existe mientras está montada."""
    if platform.system() == "Windows":
        return os.path.isdir(path)
    try:
        return os.path.ismount(path)
    except OSError:
        return False


def mount_and_wait(command: list[str], mount_point: Path, log_path: Path, *,
                   env: dict | None = None, timeout: float = 30.0) -> subprocess.Popen:
    """Lanza `command` (un `rclone mount …`) con su log en `log_path` y espera a que la carpeta se pueda listar.

    Devuelve el proceso de rclone. Si rclone termina, si listar la carpeta falla por una causa que rclone deja
    en su log o si pasan `timeout` segundos, termina rclone y lanza MountError con la causa traducida. Si la
    carpeta ya está montada, no lanza nada (MOUNT_BUSY): la comprobación vería ese montaje y no el nuevo.
    """
    if is_mounted(mount_point):
        log.warning("mount failed: %s is already mounted", mount_point)
        raise MountError(ISSUES_BY_CODE["MOUNT_BUSY"])
    _remove_log(log_path)            # el de un montaje que murió sin desmontar: su causa no es la de este
    start = time.monotonic()
    proc = subprocess.Popen(
        [*command, "--log-file", str(log_path), *_LOG_OPTIONS],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **_subprocess_kwargs(),
    )
    probe: dict | None = None        # lectura de prueba en curso
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            _fail(proc, mount_point, log_path, _issue_from_log(log_path) or UNEXPECTED)
        if probe is None and is_mounted(mount_point):
            probe = _list_in_background(mount_point)
        if probe and "ok" in probe:
            log.info("mount ok: %s (rclone pid %d, %.1f s)", mount_point, proc.pid, time.monotonic() - start)
            return proc
        if probe and "error" in probe:
            if issue := _issue_from_log(log_path):            # rclone ya ha dicho por qué (credenciales, bucket…)
                _fail(proc, mount_point, log_path, issue)
            if isinstance(probe["error"], PermissionError):   # el sistema no deja a BIFROST abrir la carpeta
                _fail(proc, mount_point, log_path, MOUNT_NOT_ALLOWED)
            probe = None                                       # otro intento en la siguiente vuelta
        time.sleep(_POLL_SECONDS)
    _fail(proc, mount_point, log_path, _issue_from_log(log_path) or MOUNT_TIMEOUT)


def _list_in_background(path: Path) -> dict:
    """Lista la carpeta en otro hilo; el dict recibe "ok" o "error" (la excepción) al terminar."""
    result: dict = {}

    def run() -> None:
        try:
            os.listdir(path)
            result["ok"] = True
        except OSError as ex:
            result["error"] = ex

    threading.Thread(target=run, daemon=True).start()
    return result


def _error_texts(lines: Iterable[str]) -> Iterator[str]:
    """Los errores de un log de rclone, sin nombres de ficheros ni rutas."""
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if isinstance(event, dict):
            if event.get("level") in ERROR_LEVELS:
                yield error_text(str(event.get("msg") or ""), str(event.get("object") or ""))
        elif _ERROR_LINE.search(line):         # texto suelto (p. ej. un pánico de Go)
            yield error_text(line)


def _issue_from_log(log_path: Path) -> UserIssue | None:
    """La causa que rclone dejó en sus últimos errores. UNEXPECTED si hay errores que no se reconocen; None si no
    hay ninguno (o aún no hay log)."""
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            errors = list(_error_texts(deque(fh, maxlen=_LOG_TAIL)))
    except OSError:
        return None
    for text in reversed(errors):
        if issue := classify(text):
            return issue
    return UNEXPECTED if errors else None


def drain_rclone_log(log_path: Path, label: str) -> None:
    """Pasa al log técnico los errores que rclone dejó en `log_path` y lo borra. Cada error distinto una vez
    (error_key), sin nombres de ficheros, hasta MAX_LOGGED_ERRORS. Se llama cuando el rclone del montaje ya ha
    terminado."""
    files = [*_rotated_logs(log_path), log_path]          # el anterior (si rclone lo rotó) va primero
    logged: set[str] = set()
    not_logged: set[str] = set()
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for text in _error_texts(fh):
                    key = error_key(text)
                    if key in logged or key in not_logged:
                        continue
                    if len(logged) < MAX_LOGGED_ERRORS:
                        logged.add(key)
                        rclone_log.warning("%s: %s", label, text)
                    else:
                        not_logged.add(key)
        except FileNotFoundError:
            continue
        except OSError as ex:
            log.warning("%s: could not read the rclone log %s: %s", label, path, ex)
    if not_logged:
        rclone_log.warning("%s: %d more kind(s) of error not logged (limit %d)", label, len(not_logged),
                           MAX_LOGGED_ERRORS)
    _remove_log(log_path)


def _rotated_logs(log_path: Path) -> list[Path]:
    """El fichero anterior que rclone deja al rotar el log (<nombre>-2026-11-03T13-44-04.778.log, comprobado con
    rclone 1.72.1). El patrón es completo para no confundirlo con el de otro bucket (<nombre>-2024-datos.log)."""
    return sorted(log_path.parent.glob(f"{log_path.stem}-{_ROTATED_STAMP}{log_path.suffix}"))


def _remove_log(log_path: Path) -> None:
    for path in [*_rotated_logs(log_path), log_path]:
        try:
            path.unlink(missing_ok=True)
        except OSError as ex:             # Windows: un rclone que sigue vivo lo tiene abierto
            log.warning("could not remove the rclone log %s: %s", path, ex)


def stop_process(proc: subprocess.Popen) -> None:
    """Termina rclone (al terminar, rclone desmonta su carpeta) y, si no acaba en 5 s, lo mata."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _fail(proc: subprocess.Popen, mount_point: Path, log_path: Path, issue: UserIssue) -> NoReturn:
    log.warning("mount failed: %s code=%s", mount_point, issue.code)
    stop_process(proc)
    drain_rclone_log(log_path, f"mount {mount_point}")
    raise MountError(issue)
