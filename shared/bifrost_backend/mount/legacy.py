"""Los montajes por bucket de la versión anterior de Bifrost mount (<base>/<perfil>/<bucket>).

Antes se montaba cada bucket en su propia carpeta; ahora se monta el servidor entero. Antes de montar un servidor,
`s3_mount` desmonta los que queden de él. Este módulo se podrá borrar cuando ya no quede ninguno.
"""

from __future__ import annotations

import logging
import platform
from pathlib import Path

from ..common.rclone_mount import is_mounted
from .mount_points import is_stale, mount_base
from .processes import pids_serving, rclone_mount_processes

log = logging.getLogger("bifrost.mount")


def bucket_mounts(perfil: str) -> list[Path]:
    """Las carpetas de <base>/<perfil> que siguen montadas como un bucket. En macOS/Linux, las montadas o colgadas;
    en Windows, las que sirve un `rclone mount` (WinFsp crea la carpeta al montar y la quita al desmontar, así que
    una carpeta que existe no está necesariamente montada).

    En macOS/Linux <base>/<perfil> es también donde se monta el servidor entero: no llamar con el servidor montado,
    porque se listarían sus buckets.
    """
    children = _children(mount_base() / perfil)
    if platform.system() == "Windows":
        if not children:
            return []
        processes = rclone_mount_processes()          # una sola vez: en Windows es lento
        return [child for child in children if pids_serving(str(child), processes)]
    return [child for child in children if is_mounted(child) or is_stale(child)]


def remove_empty_folders(perfil: str) -> None:
    """Borra las carpetas vacías que dejaron los montajes por bucket. En macOS/Linux <base>/<perfil> se queda, porque
    es donde se monta el servidor; en Windows se borran también ella y <base>, si quedan vacías."""
    folder = mount_base() / perfil
    leftovers = _children(folder)
    if platform.system() == "Windows":
        leftovers += [folder, folder.parent]
    for path in leftovers:
        try:
            path.rmdir()                     # solo si está vacía
            log.info("removed the empty folder %s", path)
        except OSError:
            pass


def _children(folder: Path) -> list[Path]:
    try:
        return sorted(folder.iterdir())
    except OSError:                          # no existe (lo normal) o no se puede leer
        return []
