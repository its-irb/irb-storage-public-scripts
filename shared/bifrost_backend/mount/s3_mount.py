"""Montaje y desmontaje de servidores de MinIO enteros con rclone mount (bifrost-mount).

Cada servidor (perfil de rclone: minio, minio-archive…) se monta entero, en solo lectura y con sus buckets como
carpetas: en Windows en una letra de unidad ("X:"), en macOS/Linux en <base>/<perfil>. Un solo montaje por
servidor: dos rclone del mismo servidor compartirían la caché, y la ayuda de rclone avisa de que se puede corromper.

La carpeta de montaje está en `mount_points`, los procesos de rclone en `processes` y los montajes por bucket de la
versión anterior en `legacy`; aquí se decide qué hacer.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
import time
from pathlib import Path

from ..common.logs import rclone_log_path
from ..common.rclone import get_rclone_executable
from ..common.rclone_mount import (
    MountError, drain_rclone_log, is_mounted, mount_and_wait, obtener_letra_unidad_disponible,
)
from ..common.rclone_output import NO_DRIVE_LETTER, UNMOUNT_FAILED
from . import legacy
from .mount_points import force_unmount, prepare_mount_point, profile_folder, wait_unmounted
from .preflight import fuse_env
from .processes import (
    drive_letter_in, pids_serving, rclone_mount_processes, server_mount_pids, stop_mount_process, stop_pid,
)

log = logging.getLogger("bifrost.mount")

# Opciones de todo montaje: solo lectura y las de rendimiento probadas a mano (plan 2026-11-20, fase 0).
_MOUNT_OPTIONS = [
    "--read-only", "--links",
    "--vfs-cache-mode", "full",
    "--vfs-read-chunk-size", "32M", "--vfs-read-chunk-size-limit", "32M",
    "--buffer-size", "32M",
    "--s3-no-head-object",
    "--dir-cache-time", "12h",
    "--vfs-cache-max-size", "10G",
]
# Opciones de caché que se pueden pasar al arrancar la app: van al final del comando y mandan sobre las de arriba.
_VFS_FLAGS_WITH_VALUE = {"--vfs-cache-mode", "--vfs-cache-max-size", "--cache-dir"}

_s3_mount_processes: list[subprocess.Popen] = []   # rclone de los montajes de esta sesión


class BucketMountsBusyError(MountError):
    """Quedan montajes por bucket de la versión anterior que no se han podido desmontar (un programa tiene un
    fichero abierto). `buckets`: sus nombres."""

    def __init__(self, buckets: list[str]) -> None:
        super().__init__(UNMOUNT_FAILED)
        self.buckets = buckets


# ============================================================================
# ESTADO
# ============================================================================

def active_mount_point(perfil: str, *, scan: bool = False) -> str | None:
    """Dónde está montado el servidor `perfil` ("X:" en Windows, la carpeta en macOS/Linux), o None.

    Sin `scan` solo mira los montajes de esta sesión (rápido). Con `scan` también busca el de una sesión anterior o
    de otra ventana de Bifrost mount; en Windows eso lee los procesos con PowerShell, que es lento.
    """
    proceso = _session_process(perfil)
    if proceso is not None:
        mount_point = proceso.args[3]
        return mount_point if is_mounted(mount_point) else None
    if not scan:
        return None
    if platform.system() == "Windows":
        for _pid, command_line in rclone_mount_processes():
            letter = drive_letter_in(command_line, perfil)
            if letter and is_mounted(letter):
                return letter
        return None
    folder = profile_folder(perfil)
    return str(folder) if is_mounted(folder) else None


# ============================================================================
# MONTAR
# ============================================================================

def mount_profile(perfil: str) -> str:
    """Monta el servidor `perfil` entero y devuelve dónde ("X:" o la carpeta), ya comprobado. Si ya está montado
    (por esta sesión, una anterior u otra ventana), lo devuelve sin lanzar otro rclone.

    Raises:
        WinFspMissingError: Windows sin WinFsp (la pantalla ofrece instalarlo).
        BucketMountsBusyError: quedan montajes por bucket de la versión anterior con ficheros abiertos.
        MountError: cualquier otro fallo del montaje, ya traducido para el usuario.
    """
    env = fuse_env()
    existing = active_mount_point(perfil, scan=True)
    if existing:
        log.info("mount %s: already mounted at %s", perfil, existing)
        return existing
    _stop_lost_mounts(perfil)
    _unmount_bucket_mounts(perfil)

    if platform.system() == "Windows":
        mount_point = obtener_letra_unidad_disponible()
        if mount_point is None:
            log.warning("mount %s: no free drive letter", perfil)
            raise MountError(NO_DRIVE_LETTER)
    else:
        folder = profile_folder(perfil)
        if prepare_mount_point(folder):
            log.info("mount %s: already mounted at %s", perfil, folder)
            return str(folder)
        mount_point = str(folder)
    log.info("mounting %s: at %s", perfil, mount_point)
    proceso = mount_and_wait(_mount_command(perfil, mount_point), Path(mount_point), _log_path(perfil), env=env)
    _s3_mount_processes.append(proceso)
    return mount_point


def _mount_command(perfil: str, mount_point: str) -> list[str]:
    comando = [get_rclone_executable(), "mount", f"{perfil}:", mount_point, *_MOUNT_OPTIONS]
    if platform.system() != "Windows":
        comando.append("--allow-non-empty")
    return comando + _vfs_flags_from_argv()


def _vfs_flags_from_argv() -> list[str]:
    """Opciones de caché de rclone pasadas al arrancar la app (p. ej. --vfs-cache-mode full)."""
    flags: list[str] = []
    for i, arg in enumerate(sys.argv[:-1]):
        if arg in _VFS_FLAGS_WITH_VALUE:
            flags += [arg, sys.argv[i + 1]]
    return flags


def _stop_lost_mounts(perfil: str) -> None:
    """Para los rclone del servidor que siguen vivos sin montaje: el sistema quitó el montaje (macOS, al cortarse la
    red) o lo desmontó alguien a mano, y el rclone sigue con la caché abierta. Si no, el nuevo rclone compartiría
    la caché con él."""
    perdido = _take_session_process(perfil)
    if perdido is not None:
        log.info("mount %s: stopping rclone pid %d of the lost mount", perfil, perdido.pid)
        stop_mount_process(perdido)
    pids = server_mount_pids(perfil)                 # de una sesión anterior, de otra ventana o lanzados a mano
    stopped = perdido is not None or bool(pids)
    for pid in pids:
        log.info("mount %s: stopping rclone pid %d of a lost mount from another session", perfil, pid)
        stop_pid(pid)
    end = time.monotonic() + 5
    while pids and time.monotonic() < end:           # stop_pid no espera: que suelte la caché antes de montar
        time.sleep(0.2)
        pids = server_mount_pids(perfil)
    if pids:
        log.warning("mount %s: rclone PIDs %s still running", perfil, pids)
    elif stopped:
        drain_rclone_log(_log_path(perfil), f"mount {perfil}")


def _unmount_bucket_mounts(perfil: str) -> None:
    """Desmonta los montajes por bucket que dejó la versión anterior para este servidor y borra sus carpetas.

    Raises:
        BucketMountsBusyError: alguno sigue montado; no se monta el servidor encima.
    """
    folders = legacy.bucket_mounts(perfil)
    if folders:
        log.info("mount %s: unmounting %d bucket mounts of the previous version", perfil, len(folders))
    busy = [folder.name for folder in folders if not _unmount(str(folder), _log_path(perfil, folder.name))]
    if busy:
        log.warning("mount %s: bucket mounts still in use: %s", perfil, ", ".join(busy))
        raise BucketMountsBusyError(busy)
    legacy.remove_empty_folders(perfil)


# ============================================================================
# DESMONTAR
# ============================================================================

def unmount_profile(perfil: str) -> bool:
    """Desmonta el servidor `perfil` y devuelve True si ya no está montado (también si no lo estaba).

    Para el rclone que lo sirve: el de esta sesión o, si es de una sesión anterior u otra ventana, el que lo tiene en
    su línea de comandos. Nunca cierra otros rclone (una copia de Bifrost Transfer, otros montajes).
    """
    proceso = _take_session_process(perfil)
    if proceso is not None:
        return _unmount(proceso.args[3], _log_path(perfil), proceso)
    mount_point = active_mount_point(perfil, scan=True)
    if mount_point is None:
        return True
    return _unmount(mount_point, _log_path(perfil))


def desmontar_todos_los_mounts_s3() -> None:
    """Desmonta cada servidor montado en esta sesión. Se ejecuta al cerrar la app (también con SIGTERM/SIGINT: un
    cierre abrupto de DCV/Open OnDemand no deja a rclone desmontar por sí mismo)."""
    log.info("closing %d mounts", len(_s3_mount_processes))
    for proceso in list(_s3_mount_processes):
        perfil = proceso.args[2].rstrip(":")
        try:
            _unmount(proceso.args[3], _log_path(perfil), proceso)
        except Exception as ex:
            log.warning("closing the mount of %s failed: %s", perfil, ex)
    _s3_mount_processes.clear()


def _unmount(mount_point: str, log_path: Path, proceso: subprocess.Popen | None = None) -> bool:
    """Desmonta `mount_point` y devuelve True si ya no está montado.

    Termina `proceso` (el rclone de esta sesión) o, si no hay, los `rclone mount` que tienen esa carpeta o letra en
    su línea de comandos. Al terminar, rclone desmonta. Si sigue montado (o no había rclone), en macOS/Linux se
    fuerza el desmontaje. Una vez desmontado, los errores que dejó rclone en `log_path` pasan al log técnico.
    """
    start = time.monotonic()
    if proceso is not None:
        log.info("unmount %s: stopping rclone pid %d", mount_point, proceso.pid)
        stop_mount_process(proceso)
        pids = [proceso.pid]
    else:
        pids = pids_serving(mount_point)
        log.info("unmount %s: rclone from a previous session, PIDs %s", mount_point, pids or "not found")
        for pid in pids:
            stop_pid(pid)
    if platform.system() != "Windows" and not wait_unmounted(mount_point, seconds=3.0 if pids else 0):
        log.info("unmount %s: still mounted after %.1f s, forcing", mount_point, time.monotonic() - start)
        force_unmount(Path(mount_point))
    if wait_unmounted(mount_point):
        log.info("unmount %s: done (%.1f s)", mount_point, time.monotonic() - start)
        drain_rclone_log(log_path, f"mount {mount_point}")
        return True
    log.warning("unmount %s: still mounted", mount_point)
    return False


# ============================================================================
# AUXILIARES
# ============================================================================

def _log_path(perfil: str, bucket: str | None = None) -> Path:
    """El fichero temporal de rclone de un montaje: mount-<perfil>.log, o mount-<perfil>-<bucket>.log para los
    montajes por bucket de la versión anterior. Siempre el mismo, para encontrar también el de una sesión
    anterior."""
    return rclone_log_path("mount", perfil if bucket is None else f"{perfil}-{bucket}")


def _session_process(perfil: str) -> subprocess.Popen | None:
    """El rclone de esta sesión que monta el servidor (args: rclone, "mount", "<perfil>:", destino, …)."""
    remote = f"{perfil}:"
    return next((proceso for proceso in _s3_mount_processes
                 if len(proceso.args) > 3 and proceso.args[2] == remote), None)


def _take_session_process(perfil: str) -> subprocess.Popen | None:
    """Saca de la lista el rclone de esta sesión que monta el servidor (None si no hay ninguno)."""
    proceso = _session_process(perfil)
    if proceso is not None:
        _s3_mount_processes.remove(proceso)
    return proceso
