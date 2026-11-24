"""Los procesos `rclone mount`: encontrarlos y pararlos sin tocar otros rclone (p. ej. una copia de Bifrost Transfer)."""

from __future__ import annotations

import logging
import ntpath
import os
import platform
import re
import signal
import subprocess

from ..common.rclone import _subprocess_kwargs
from ..common.rclone_mount import stop_process
from .mount_points import normalized

log = logging.getLogger("bifrost.mount")

# El ejecutable seguido del subcomando: `rclone mount …`, no `rclone copy …`.
_MOUNT_COMMAND = re.compile(r'rclone(?:\.exe)?"?\s+mount\s')


def rclone_mount_processes() -> list[tuple[int, str]]:
    """(PID, línea de comandos) de cada `rclone mount` en marcha: no las copias de Bifrost Transfer, aunque lean de
    una carpeta montada. En Windows la línea va normalizada como `normalized` (minúsculas y "\\"); esa parte no se
    ha probado todavía en Windows (`Bifrost/PENDIENTES.md`, entrada 17)."""
    windows = platform.system() == "Windows"
    if windows:
        script = ("Get-CimInstance Win32_Process -Filter \"Name='rclone.exe'\" | "
                  "ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }")
        comando = ["powershell", "-NoProfile", "-Command", script]
    else:
        comando = ["ps", "-A", "-ww", "-o", "pid=,ucomm=,args="]     # ucomm: nombre del programa, sin ruta
    try:
        result = subprocess.run(comando, capture_output=True, text=True, timeout=15, **_subprocess_kwargs())
    except (OSError, subprocess.TimeoutExpired) as ex:
        log.warning("could not list the rclone processes: %s", ex)
        return []
    return parse_mount_processes(result.stdout, windows=windows)


def parse_mount_processes(output: str, *, windows: bool) -> list[tuple[int, str]]:
    """Los `rclone mount` de la salida de `rclone_mount_processes`: en Windows, líneas "<PID>\\t<línea de comandos>"
    de PowerShell; en macOS/Linux, "<PID> <programa> <línea de comandos>" de `ps`. Separado para probarlo sin
    lanzar procesos."""
    processes = []
    for line in output.splitlines():
        if windows:
            pid, _, command_line = line.strip().partition("\t")
            command_line = ntpath.normcase(command_line)       # = os.path.normcase en Windows: minúsculas y "\"
        else:
            parts = line.split(None, 2)
            if len(parts) < 3 or parts[1] != "rclone":
                continue
            pid, _, command_line = parts
        if pid.isdigit() and _MOUNT_COMMAND.search(command_line):
            processes.append((int(pid), command_line))
    return processes


def pids_serving(mount_point: str, processes: list[tuple[int, str]] | None = None) -> list[int]:
    """PIDs de los `rclone mount` cuya línea de comandos tiene esta carpeta (o letra de unidad) como argumento
    completo. `processes`: la lista de `rclone_mount_processes()` si ya se tiene (en Windows, leerla es lento)."""
    # La carpeta completa, entre comillas, espacios o los extremos: …/bkt no debe coincidir con …/bkt2.
    target = re.compile(r'(?:^|["\s])' + re.escape(normalized(mount_point)) + r'(?=["\s]|$)')
    if processes is None:
        processes = rclone_mount_processes()
    return [pid for pid, command_line in processes if target.search(command_line)]


def server_mount_pids(perfil: str, processes: list[tuple[int, str]] | None = None) -> list[int]:
    """PIDs de los `rclone mount` que montan el servidor `perfil` entero (`rclone mount <perfil>: …`), estén donde
    estén. No los de un bucket (`<perfil>:<bucket>`) ni los de otro servidor (`minio` no es `minio-archive`)."""
    target = re.compile(r'\smount\s+"?' + re.escape(perfil) + r':"?(?=["\s]|$)', re.IGNORECASE)
    if processes is None:
        processes = rclone_mount_processes()
    return [pid for pid, command_line in processes if target.search(command_line)]


def drive_letter_in(command_line: str, perfil: str) -> str | None:
    """Windows: la letra de unidad ("X:") de una línea de `rclone_mount_processes()` que monta el servidor `perfil`
    entero (`rclone mount <perfil>: X: …`), o None. La línea llega en minúsculas; `minio` no es `minio-archive`."""
    match = re.search(r'\smount\s+"?' + re.escape(perfil.lower()) + r':"?\s+"?([a-z]):\\?"?(?=\s|$)', command_line)
    return f"{match.group(1).upper()}:" if match else None


def stop_mount_process(proceso: subprocess.Popen) -> None:
    """En Windows, taskkill del árbol del proceso (TerminateProcess puede dejar la unidad de WinFsp colgada)."""
    if platform.system() != "Windows":
        stop_process(proceso)
        return
    _taskkill(proceso.pid)
    try:
        proceso.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proceso.kill()


def stop_pid(pid: int) -> None:
    """Termina un rclone que no lanzó esta sesión: taskkill en Windows (como `stop_mount_process`) y SIGTERM en
    macOS/Linux (como `Popen.terminate`: rclone desmonta su carpeta y sale)."""
    if platform.system() == "Windows":
        _taskkill(pid)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as ex:
        log.warning("could not stop rclone pid %d: %s", pid, ex)


def _taskkill(pid: int) -> None:
    result = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True,
                            **_subprocess_kwargs())
    if result.returncode != 0:
        log.warning("taskkill %s failed: %s", pid, (result.stderr or result.stdout).strip())
