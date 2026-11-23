"""Montaje y desmontaje de buckets (o carpetas) de MinIO con rclone mount (bifrost-mount).

La carpeta de montaje está en `mount_points` y los procesos de rclone en `processes`; aquí se decide qué hacer.
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
from ..common.rclone_mount import drain_rclone_log, mount_and_wait
from .mount_points import force_unmount, mount_base, normalized, prepare_mount_point, wait_unmounted
from .preflight import fuse_env
from .processes import pids_serving, stop_mount_process, stop_pid

log = logging.getLogger("bifrost.mount")

_s3_mount_processes: list[subprocess.Popen] = []   # rclone de los montajes de esta sesión
# Opciones de caché de rclone que se pueden pasar al arrancar la app y se reenvían a cada montaje.
_VFS_FLAGS_WITH_VALUE = {"--vfs-cache-mode", "--vfs-cache-max-size", "--cache-dir"}


def resolver_mount_point_destino(perfil_rclone: str, ruta_destino: str) -> str:
    """Carpeta local donde se monta un bucket o carpeta de MinIO. La misma al montar, desmontar y al detectar
    los montajes de una sesión anterior."""
    return str(mount_base() / perfil_rclone / ruta_destino.strip().strip("/").replace("/", "_"))


def _mount_log_path(mount_point: str | Path) -> Path:
    """El fichero temporal de rclone de un montaje (mount-<perfil>-<bucket>.log). Sale de la carpeta de montaje
    (<base>/<perfil>/<bucket>) para encontrar también el de un resto de una sesión anterior."""
    mount_point = Path(mount_point)
    return rclone_log_path("mount", f"{mount_point.parent.name}-{mount_point.name}")


# ============================================================================
# MONTAR
# ============================================================================

def mount_rclone_S3_prefix_to_folder(rclone_profile: str, s3_prefix: str) -> str:
    """Monta en solo lectura un bucket (o carpeta) de MinIO y devuelve la carpeta local, ya comprobada. Si ya está
    montada y responde, la devuelve sin lanzar otro rclone (el segundo se quedaría esperando a que la carpeta
    quede libre y la comprobación vería el montaje del primero).

    Raises:
        WinFspMissingError: Windows sin WinFsp (la pantalla ofrece instalarlo).
        MountError: cualquier otro fallo del montaje, ya traducido para el usuario.
    """
    prefix = s3_prefix.strip().strip("/")
    if not prefix:
        raise ValueError("No bucket selected to mount")      # la pantalla lo comprueba antes
    mount_point = Path(resolver_mount_point_destino(rclone_profile, prefix))
    env = fuse_env()
    if prepare_mount_point(mount_point):
        log.info("already mounted: %s", mount_point)
        return str(mount_point)
    perdido = _take_process(mount_point)
    if perdido is not None:             # el sistema quitó el montaje (macOS, al cortarse la red) y rclone sigue vivo
        log.info("mount %s: stopping rclone pid %d of the lost mount", mount_point, perdido.pid)
        stop_mount_process(perdido)
        drain_rclone_log(_mount_log_path(mount_point), f"mount {mount_point}")
    comando = [get_rclone_executable(), "mount", f"{rclone_profile}:{prefix}", str(mount_point),
               "--read-only", "--links", *_vfs_flags_from_argv()]
    if platform.system() != "Windows":
        comando.append("--allow-non-empty")
    log.info("mounting %s:%s at %s", rclone_profile, prefix, mount_point)
    proceso = mount_and_wait(comando, mount_point, _mount_log_path(mount_point), env=env)
    _s3_mount_processes.append(proceso)
    return str(mount_point)


def _vfs_flags_from_argv() -> list[str]:
    """Opciones de caché de rclone pasadas al arrancar la app (p. ej. --vfs-cache-mode full)."""
    flags: list[str] = []
    for i, arg in enumerate(sys.argv[:-1]):
        if arg in _VFS_FLAGS_WITH_VALUE:
            flags += [arg, sys.argv[i + 1]]
    return flags


# ============================================================================
# DESMONTAR
# ============================================================================

def desmontar_punto_montaje(mount_point: str) -> bool:
    """Desmonta la carpeta de un bucket y devuelve True si ya no está montada.

    Se termina el rclone que sirve la carpeta: el de esta sesión o, si es un resto de una sesión anterior (la app
    se cerró de golpe y rclone siguió vivo), el que la tiene en su línea de comandos. Al terminar, rclone desmonta
    su carpeta. Si sigue montada (o no había rclone), en macOS/Linux se fuerza el desmontaje. Nunca se cierran
    otros rclone (una copia de Bifrost Transfer, otros montajes). Una vez desmontada, los errores que dejó rclone
    pasan al log técnico.
    """
    start = time.monotonic()
    proceso = _take_process(mount_point)
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
        drain_rclone_log(_mount_log_path(mount_point), f"mount {mount_point}")
        return True
    log.warning("unmount %s: still mounted", mount_point)
    return False


def desmontar_todos_los_mounts_s3() -> None:
    """Termina el rclone de cada montaje de esta sesión y, si la carpeta sigue montada, la desmonta. Se ejecuta
    al cerrar la app (también con SIGTERM/SIGINT: un cierre abrupto de DCV/Open OnDemand no deja a rclone
    desmontar por sí mismo)."""
    log.info("closing %d mounts", len(_s3_mount_processes))
    windows = platform.system() == "Windows"
    for proceso in list(_s3_mount_processes):
        mount_point = proceso.args[3] if len(proceso.args) > 3 else None
        try:
            stop_mount_process(proceso)
            if mount_point and not windows and not wait_unmounted(mount_point):
                force_unmount(Path(mount_point))
            if mount_point:
                drain_rclone_log(_mount_log_path(mount_point), f"mount {mount_point}")
        except Exception as ex:
            log.warning("closing the mount %s failed: %s", mount_point, ex)
    _s3_mount_processes.clear()


def _take_process(mount_point: str | Path) -> subprocess.Popen | None:
    """Saca de la lista el rclone de esta sesión que sirve la carpeta (None si no hay ninguno)."""
    target = normalized(mount_point)
    for proceso in list(_s3_mount_processes):
        if len(proceso.args) > 3 and normalized(proceso.args[3]) == target:
            _s3_mount_processes.remove(proceso)
            return proceso
    return None
