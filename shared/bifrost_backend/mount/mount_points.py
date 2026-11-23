"""La carpeta de un montaje de MinIO: dónde está y en qué estado (montada, colgada, desmontada)."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

from ..common.rclone_mount import MountError, is_mounted
from ..common.rclone_output import ISSUES_BY_CODE

log = logging.getLogger("bifrost.mount")


def mount_base() -> Path:
    """Devuelve la carpeta raíz donde se crean los mount points S3."""
    if platform.system() == "Windows":
        return Path("C:/rclone-mounts")
    return Path.home() / "rclone-mounts"


def normalized(path: str | Path) -> str:
    """La carpeta escrita de una sola forma, para comparar dos rutas (en Windows, minúsculas y "\\")."""
    return os.path.normcase(os.path.normpath(str(path)))


def prepare_mount_point(mount_point: Path) -> bool:
    """Deja lista la carpeta de montaje. Devuelve True si ya está montada y responde: no hay que volver a montarla.

    En macOS/Linux se desmonta un montaje colgado de una sesión anterior y se crea la carpeta (rclone puede montar
    sobre una carpeta con contenido: --allow-non-empty). En Windows la carpeta solo existe mientras está montada:
    WinFsp la crea al montar.
    """
    if platform.system() == "Windows":
        if is_mounted(mount_point):
            return True
        if mount_point.exists():
            try:
                mount_point.rmdir()
            except OSError as ex:
                log.warning("mount point %s exists and could not be removed: %s", mount_point, ex)
                raise MountError(ISSUES_BY_CODE["MOUNT_BUSY"]) from ex
        mount_point.parent.mkdir(parents=True, exist_ok=True)
        return False
    if _is_stale(mount_point):
        log.info("stale mount point %s: forcing unmount", mount_point)
        force_unmount(mount_point)
    elif is_mounted(mount_point):
        return True
    mount_point.mkdir(parents=True, exist_ok=True)
    return False


def wait_unmounted(mount_point: str | Path, seconds: float = 3.0) -> bool:
    """True cuando la carpeta deja de estar montada (rclone desmonta al terminar, pero tarda un momento)."""
    end = time.monotonic() + seconds
    while is_mounted(mount_point):
        if time.monotonic() > end:
            return False
        time.sleep(0.1)
    return True


def force_unmount(mount_point: Path) -> None:
    """Fuerza el desmontaje (perezoso si hace falta) de un punto de montaje
    FUSE en Linux/macOS. No-op en Windows (WinFsp se libera al matar el proceso).
    """
    sistema = platform.system()
    mp = str(mount_point)
    if sistema == "Linux":
        intentos = []
        if shutil.which("fusermount"):
            intentos.append(["fusermount", "-u", "-z", mp])
        if shutil.which("fusermount3"):
            intentos.append(["fusermount3", "-u", "-z", mp])
        intentos.append(["umount", "-l", mp])
    elif sistema == "Darwin":
        intentos = [["umount", "-f", mp], ["diskutil", "unmount", "force", mp]]
    else:
        return

    for comando in intentos:
        try:
            subprocess.run(comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            log.info("forced unmount of %s with: %s", mp, " ".join(comando[:-1]))
            return
        except Exception as ex:
            log.info("forced unmount with '%s' failed: %s", " ".join(comando[:-1]), ex)


def _is_stale(mount_point: Path) -> bool:
    """Detecta si mount_point es un mountpoint FUSE colgado (el proceso rclone
    que lo servía murió sin desmontar, típico de un cierre abrupto de sesión
    DCV/Open OnDemand). Un mount colgado sigue reportando ismount()=True pero
    cualquier acceso al contenido falla con OSError (p.ej. "Transport endpoint
    is not connected").
    """
    try:
        montado = os.path.ismount(mount_point)
    except OSError:
        return True
    if not montado:
        return False
    try:
        os.listdir(mount_point)
    except OSError:
        return True
    return False
