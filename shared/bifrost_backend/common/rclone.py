"""Resolución del ejecutable rclone, rutas de configuración y listados básicos."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from sys import platform as sys_platform



_rclone_version_cache: str | None = None


def _get_rclone_version() -> str:
    global _rclone_version_cache
    if _rclone_version_cache is not None:
        return _rclone_version_cache
    try:
        out = subprocess.check_output(
            [get_rclone_executable(), "--version"],
            encoding="utf-8",
            errors="replace",
            **_subprocess_kwargs(),
        )
        # Primera línea: "rclone v1.72.1"
        _rclone_version_cache = out.splitlines()[0].split()[1].lstrip("v")
    except Exception:
        _rclone_version_cache = "unknown"
    return _rclone_version_cache


def _get_user_agent() -> str:
    try:
        from version import __version__ as app_version
    except Exception:
        app_version = "dev"
    return f"bifrost-transfer/{app_version} rclone/{_get_rclone_version()}"


def _ensure_executable(path: Path) -> None:
    if not os.access(path, os.X_OK):
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def app_assets_dir() -> Path | None:
    """La carpeta `assets/` de la app que se está ejecutando (`bifrost-<flavour>/src/assets`), o None.

    Es la carpeta del `config.py` de la app (módulo `config`, que cada app aporta en su `src/`). Sirve en
    desarrollo sin `flet run` (`python src/main.py`), donde no hay `FLET_ASSETS_DIR`. No se calcula subiendo
    carpetas desde este fichero: con `bifrost-shared` instalado en el venv, este fichero está en
    `site-packages`, no en el repo.
    """
    config_file = getattr(sys.modules.get("config"), "__file__", None)
    if not config_file:
        return None
    return Path(config_file).resolve().parent / "assets"


def get_rclone_executable() -> str:
    """
    Devuelve la ruta al ejecutable rclone.

    Prioridad:
      1. Bundle Flet (FLET_ASSETS_DIR/bin/rclone) — apps empaquetadas y `flet run`.
      2. assets/bin de la app (`app_assets_dir()`) — dev con `python src/main.py`, también en modo web.
      3. rclone en el PATH del sistema (modo web/cluster).
    """
    rclone_name = "rclone.exe" if sys_platform == "win32" else "rclone"

    flet_assets = os.environ.get("FLET_ASSETS_DIR")
    if flet_assets:
        bundled = Path(flet_assets) / "bin" / rclone_name
        if bundled.exists():
            _ensure_executable(bundled)
            return str(bundled)

    assets = app_assets_dir()
    dev_asset = assets / "bin" / rclone_name if assets else None
    if dev_asset is not None and dev_asset.exists():
        _ensure_executable(dev_asset)
        return str(dev_asset)

    in_path = shutil.which("rclone")
    if in_path:
        return in_path

    raise EnvironmentError(
        "rclone not found. The application bundle appears to be incomplete — "
        "please reinstall BIFROST."
    )


def _subprocess_kwargs() -> dict:
    """Suprime la ventana de consola en Windows para subprocesos."""
    if sys_platform == "win32":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


@lru_cache(maxsize=1)
def obtener_ruta_rclone_conf() -> Path:
    """Ejecuta `rclone config file` y devuelve la ruta absoluta al rclone.conf activo."""
    rclone = get_rclone_executable()
    out = subprocess.check_output(
        [rclone, "config", "file"],
        text=True,
        stderr=subprocess.STDOUT,
        **_subprocess_kwargs(),
    ).strip()

    lines = [l.strip().strip('"').strip("'") for l in out.splitlines() if l.strip()]

    for l in reversed(lines):
        if l.lower().endswith(".conf"):
            return Path(l).expanduser().resolve()

    candidates = []
    for l in lines:
        if re.search(r"[A-Za-z]:\\", l):
            candidates.append(l[l.find(re.search(r"[A-Za-z]:\\", l).group(0)):])
        if "/" in l:
            m = re.search(r"(/[^ \t\r\n]+)", l)
            if m:
                candidates.append(m.group(1))

    for c in reversed(candidates):
        c = c.strip().strip('"').strip("'")
        p = Path(c)
        if p.suffix.lower() != ".conf":
            p = p / "rclone.conf"
        return p.expanduser().resolve()

    raise RuntimeError(
        f"No pude extraer la ruta del config. Salida de `rclone config file`: {out!r}"
    )


def rclone_lsd(perfil: str, path: str = "", timeout: int = 15) -> list[str]:
    """
    Lista las subcarpetas/buckets de un path en un perfil rclone.
    
    Args:
        perfil: nombre del perfil rclone (ej. "irbminio")
        path:   path dentro del perfil. "" = raíz (lista buckets)
    
    Returns:
        Lista ordenada de nombres de carpeta.
    
    Raises:
        RuntimeError: si rclone lsd falla.
    """
    rclone = get_rclone_executable()
    target = f"{perfil}:{path}" if path else f"{perfil}:"

    result = subprocess.run(
        [rclone, "lsd", target],
        capture_output=True,
        text=True,
        timeout=timeout,
        **_subprocess_kwargs(),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"rclone lsd failed (code {result.returncode})")

    folders = []
    for line in result.stdout.splitlines():
        # formato: "          -1 2024-01-01 00:00:00        -1 folder_name"
        parts = line.strip().split(None, 4)
        if len(parts) == 5:
            folders.append(parts[4])
    return sorted(folders)
