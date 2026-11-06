"""Comprobación de actualizaciones y localización de assets."""

from __future__ import annotations

import logging
import os
import platform
import requests
import sys
import tempfile
from pathlib import Path

from config import APP_INFO

from .constants import EMOJI_FONT_FILENAME, REPO, __version__

log = logging.getLogger("bifrost.update")


def _parse_version(v: str) -> tuple:
    """Convierte 'v1.10.2' o '1.10.2' en tupla de enteros para comparación semántica."""
    try:
        return tuple(int(x) for x in v.strip("v").split("."))
    except Exception:
        return (0,)


def check_update_version(force_update: bool = False) -> str | None:
    """
    Comprueba si hay una versión nueva disponible en GitHub.

    Returns:
        Tag de la versión más reciente si hay actualización, None en caso contrario.
    """
    # Por si se quiere probar el update manualmente durante el desarrollo sin necesidad de subir una nueva release:
    # if force_update:
    #     return "v999.999.999"

    try:
        response = requests.get(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=5)
        response.raise_for_status()
        latest_tag = response.json().get("tag_name", "")
    except Exception as e:                      # sin red, GitHub no responde o la respuesta no es la esperada
        log.warning("update check failed: %s", e)
        return None
    newer = bool(latest_tag) and _parse_version(latest_tag) > _parse_version(__version__)
    log.info("update check: current=%s latest=%s → %s", __version__, latest_tag.strip("v") or "?",
             "update available" if newer else "up to date")
    return latest_tag if newer else None


def should_check_for_updates() -> bool:
    """
    Determina si se debe comprobar actualizaciones en el entorno actual.
    Devuelve False en entornos HPC/cluster o cuando no se ejecuta como binario compilado,
    a menos que se pase el flag --update (útil para testing en desarrollo).
    """
    if "--update" in sys.argv:
        return True
    if not getattr(sys, 'frozen', False) and not os.environ.get('FLET_APP_STORAGE_TEMP'):
        log.debug("update check skipped: not a packaged app")
        return False
    executable_name = os.path.basename(sys.argv[0] if hasattr(sys, 'argv') else '')
    if '_linux_cluster' in executable_name or '_cluster' in executable_name:
        return False
    if os.environ.get('SLURM_JOB_ID'):
        return False
    return True


def get_update_file_suffix() -> str:
    """Devuelve el sufijo de plataforma para el binario de actualización."""
    sistema = sys.platform
    if sistema == "linux":
        return "-linux"
    elif sistema == "darwin":
        # Stopgap hasta nov-2026: los Macs Intel se actualizan al .dmg x86_64.
        # Eliminar esta rama junto con el job build-macos-intel
        # (follow-up post-nov-2026).
        return "-macos.dmg" if platform.machine() == "arm64" else "-macos-intel.dmg"
    elif sistema == "win32":
        return "-main-windows.exe"
    return ""


def download_new_binary(file_name: str) -> str:
    """
    Descarga el binario más reciente de GitHub a un fichero temporal.

    Returns:
        Ruta al fichero temporal descargado.

    Raises:
        requests.HTTPError: Si la descarga falla.
    """

    sufijo = get_update_file_suffix()
    url = f"https://github.com/{REPO}/releases/latest/download/{file_name}{sufijo}"
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp:
        tmp.write(r.content)
        return tmp.name


def get_emoji_font_asset_path() -> str | None:
    """
    Devuelve la ruta relativa al assets_dir de Flet donde encontrar la fuente
    emoji, o ``None`` si no existe.

    La fuente la descargan los scripts ``shared/*-assets-downloader.sh`` a
    ``assets/fonts/`` en cada build/ejecución, así que aquí solo la localizamos.
    """
    font_rel = f"fonts/{EMOJI_FONT_FILENAME}"

    # 1. Bundle Flet (apps empaquetadas y dev con flet run).
    flet_assets = os.environ.get("FLET_ASSETS_DIR")
    if flet_assets and (Path(flet_assets) / font_rel).exists():
        return font_rel

    # 2. Dev sin flet run: assets del repo (solo si el paquete se importa
    # desde el repo, no desde site-packages).
    pkg_root = Path(__file__).parent.parent.parent
    if pkg_root.name == "shared":
        repo_font = (
            pkg_root.parent
            / f"bifrost-{APP_INFO['flavour']}" / "src" / "assets" / font_rel
        )
        if repo_font.exists():
            return font_rel

    return None
