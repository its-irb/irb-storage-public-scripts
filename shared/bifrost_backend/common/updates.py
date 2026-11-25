"""Comprobación de actualizaciones y localización de assets."""

from __future__ import annotations

import logging
import os
import platform
import requests
import sys
import tempfile
import zipfile
from pathlib import Path


from .constants import EMOJI_FONT_FILENAME, REPO, __version__
from .rclone import app_assets_dir

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

    Nunca en Linux ni en el clúster (Open OnDemand: transfer en modo web y mount en las sesiones DCV), ni
    siquiera con --update: allí la app se ejecuta desde el código que instala ITS y las releases no traen
    binarios de Linux. El modo web tampoco muestra la pantalla de actualización (main.py de transfer).
    En el resto, False cuando no se ejecuta como binario compilado, a menos que se pase el flag --update
    (útil para testing en desarrollo).
    """
    if sys.platform.startswith("linux") or os.environ.get("BIFROST_CLUSTER") == "1":
        log.debug("update check skipped: Linux / cluster")
        return False
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
        # .zip con el instalador .exe dentro (lo crea el job release del CI). El .exe suelto
        # (-main-windows.exe) se sigue publicando para las versiones que aún lo piden.
        return "-windows.zip"
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


def extract_windows_installer(zip_path: str, dest_dir: str) -> str:
    """
    Extrae el instalador .exe del .zip de la release de Windows y devuelve su ruta.

    Raises:
        RuntimeError: Si el .zip no contiene exactamente un .exe.
    """
    with zipfile.ZipFile(zip_path) as z:
        exes = [n for n in z.namelist() if n.lower().endswith(".exe")]
        if len(exes) != 1:
            raise RuntimeError(f"Expected one .exe in the update zip, found {len(exes)}")
        return z.extract(exes[0], dest_dir)


def build_windows_update_script(exe_path: str, flavour: str) -> str:
    """
    Contenido del .bat que instala la actualización en Windows y relanza la app.

    Está separado de la vista para poder probarlo sin interfaz gráfica.
    """
    return (
        f'@echo off\n'
        # Salir del directorio de trabajo heredado de la app (...\flet\app): mientras algún proceso lo tenga
        # como directorio actual, Windows no deja borrarlo y la app relanzada falla al re-extraerlo (errno 32).
        f'cd /d "%TEMP%"\n'
        f'timeout /t 2 /nobreak >nul\n'
        # /wait: el instalador es una app gráfica y cmd no la espera por defecto;
        # sin esto la app se relanza antes de que termine la instalación.
        f'start /wait "" "{exe_path}" /SILENT /SUPPRESSMSGBOXES /NOCANCEL\n'
        f'start "" "%ProgramFiles(x86)%\\Bifrost-{flavour}\\bifrost-{flavour}.exe"\n'
    )


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

    # 2. Dev sin flet run (python src/main.py): los assets de la app, junto a su config.py; funciona
    # también con bifrost-shared instalado en site-packages.
    assets = app_assets_dir()
    if assets is not None and (assets / font_rel).exists():
        return font_rel

    return None
