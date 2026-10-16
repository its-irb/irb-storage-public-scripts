"""Requisitos previos de montaje: WinFsp (Windows) y FUSE (macOS/Linux)."""

from __future__ import annotations

import ctypes, ctypes.util
import os
import platform
import re
import requests
import shutil
import subprocess
import tempfile
from pathlib import Path


class WinFspMissingError(EnvironmentError):
    """Falta WinFsp en Windows. Se distingue de EnvironmentError genérico
    para que la UI pueda ofrecer auto-instalación en lugar de solo mostrar
    un link a winfsp.dev."""
    pass


def _check_winfsp_windows() -> bool:
    """Detecta WinFSP en Windows por múltiples métodos."""
    import shutil
    import winreg

    # 1. En el PATH
    if shutil.which("winfsp-ctl.exe") or shutil.which("winfsp-x64.dll"):
        return True

    # 2. Variables de entorno (cubre Program Files, Program Files (x86), y rutas custom)
    for env_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        pf = os.environ.get(env_var, "")
        if pf and (Path(pf) / "WinFsp" / "bin" / "winfsp-ctl.exe").exists():
            return True

    # 3. Registro de Windows (más fiable: el instalador siempre escribe aquí)
    for hive, key_path in (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinFsp"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\WinFsp"),
    ):
        try:
            winreg.OpenKey(hive, key_path).Close()
            return True
        except FileNotFoundError:
            continue

    return False


def _winfsp_latest_msi_url() -> tuple[str, str]:
    """Devuelve (url_descarga_msi, tag_version) de la última release de WinFsp en GitHub.

    Levanta RuntimeError si la API no responde o no hay asset .msi.
    """
    api_url = "https://api.github.com/repos/winfsp/winfsp/releases/latest"
    try:
        resp = requests.get(api_url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as ex:
        raise RuntimeError(f"No se pudo consultar la API de GitHub de WinFsp: {ex}")

    tag = data.get("tag_name", "")
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        if name.lower().endswith(".msi") and url:
            return url, tag

    raise RuntimeError("No se encontró ningún asset .msi en la última release de WinFsp.")


def _download_winfsp_msi(url: str, tag: str) -> Path:
    """Descarga el MSI de WinFsp a %TEMP%\\winfsp-<tag>.msi y devuelve el path.

    Levanta RuntimeError si la descarga falla o el fichero resultante está vacío.
    """
    safe_tag = re.sub(r"[^A-Za-z0-9._-]", "_", tag) or "latest"
    dest = Path(tempfile.gettempdir()) / f"winfsp-{safe_tag}.msi"
    try:
        with requests.get(url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        f.write(chunk)
    except Exception as ex:
        raise RuntimeError(f"No se pudo descargar WinFsp MSI: {ex}")

    if not dest.exists() or dest.stat().st_size == 0:
        raise RuntimeError(f"El MSI descargado está vacío: {dest}")

    return dest


def install_winfsp_windows(on_progress=None) -> bool:
    """Descarga e instala WinFsp en Windows.

    Args:
        on_progress: callable(str) opcional que recibe mensajes de estado en inglés
                     ("Checking...", "Downloading...", "Installing...") para mostrarlos en UI.

    Returns:
        True si WinFsp queda instalado correctamente.
        False si el usuario canceló el UAC (no es un error real).

    Raises:
        RuntimeError si falla la consulta a GitHub, la descarga o la instalación.
    """
    if platform.system() != "Windows":
        raise RuntimeError("install_winfsp_windows solo es válido en Windows")

    def _emit(msg: str) -> None:
        if on_progress is not None:
            try:
                on_progress(msg)
            except Exception:
                pass

    _emit("Checking latest WinFsp version...")
    url, tag = _winfsp_latest_msi_url()

    _emit(f"Downloading WinFsp {tag}...")
    msi_path = _download_winfsp_msi(url, tag)

    _emit(f"Installing WinFsp {tag}...")
    try:
        result = subprocess.run(
            ["msiexec", "/i", str(msi_path), "/qb", "/norestart"],
            check=False,
        )
    except FileNotFoundError as ex:
        raise RuntimeError(f"No se encontró msiexec: {ex}")

    rc = result.returncode
    if rc in (0, 3010):
        if _check_winfsp_windows():
            return True
        raise RuntimeError(
            f"msiexec terminó con código {rc} pero WinFsp sigue sin detectarse."
        )
    if rc == 1602:
        return False
    raise RuntimeError(f"msiexec falló con código de salida {rc}.")


def _macos_app_bundle_frameworks() -> Path | None:
    """
    Devuelve <App.app>/Contents/Frameworks usando NSBundle.mainBundle() vía ctypes.
    Funciona porque Flet (serious_python) embebe Python en el mismo proceso Flutter,
    por lo que mainBundle() apunta correctamente al .app en ejecución.
    Devuelve None si falla o no estamos dentro de un bundle.
    """
    try:
        objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('objc'))
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]
        objc.objc_msgSend.restype = ctypes.c_void_p
        objc.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        bundle = objc.objc_msgSend(
            objc.objc_getClass(b'NSBundle'),
            objc.sel_registerName(b'mainBundle'),
        )
        path_nsstr = objc.objc_msgSend(bundle, objc.sel_registerName(b'bundlePath'))
        objc.objc_msgSend.restype = ctypes.c_char_p
        utf8 = objc.objc_msgSend(path_nsstr, objc.sel_registerName(b'UTF8String'))
        if utf8:
            p = Path(utf8.decode()) / 'Contents' / 'Frameworks'
            print(f"[debug] NSBundle.mainBundle path: {p}")
            if p.is_dir():
                return p
    except Exception as e:
        print(f"[debug] _macos_app_bundle_frameworks failed: {e}")
    return None


def _get_fuse_macos() -> Path | None:
    """Ruta del dylib fuse-t en macOS: .app empaquetado (bundle) o dev (FLET_ASSETS_DIR). None si no existe."""

    fuse_t_path: Path | None = None

    bundle_fw = _macos_app_bundle_frameworks()
    if bundle_fw:
        fuse_t_path = bundle_fw / "fuse_t.framework" / "Versions" / "Current" / "fuse_t"
    else:
        # modo desarrollo
        flet_assets = os.environ.get("FLET_ASSETS_DIR")
        if flet_assets:
            # mirar si existe la ruta, si no existe notificar por print debug 
            fuse_t_path = Path(flet_assets).parent.parent / "frameworks" / "fuse_t.framework" / "Versions" / "Current" / "fuse_t"
            
    if fuse_t_path is not None and fuse_t_path.exists():
        print("[debug] path fuse-t:" + str(fuse_t_path))
        return fuse_t_path
    else:
        print("[debug] path fuse-t not found:" + str(fuse_t_path))
        return None


def _check_fuse_linux() -> bool:
    """Detecta FUSE en Linux."""
    import shutil
    if shutil.which("fusermount") or shutil.which("fusermount3"):
        return True
    try:
        result = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
        if "fuse" in result.stdout.lower():
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return Path("/dev/fuse").exists()
