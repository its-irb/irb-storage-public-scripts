from __future__ import annotations

"""
IRB MinIO Rclone Data Transfer Tool — BACKEND
==============================================

Contiene toda la lógica de negocio sin dependencias de GUI (tkinter).

Módulos cubiertos:
- Constantes y versión
- Comprobación de versión / actualizaciones (lógica pura)
- Utilidades del sistema (CPUs, rutas rclone)
- Autenticación STS (MinIO) y gestión de credenciales rclone
- Autenticación y grupos LDAP
- Gestión de shares SMB/CIFS
- Perfiles rclone (lectura, creación, actualización)
- Montaje/desmontaje de shares
- Ejecución de comandos rclone (copy, check)
"""

import os
import stat
import re
import sys
import json
import time
import shlex
import shutil
import platform
import subprocess
import configparser
import threading
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from sys import platform as sys_platform
import ctypes, ctypes.util
import traceback
import tempfile

import jwt
import requests
import urllib3
from ldap3 import Server, Connection, SUBTREE, SIMPLE
from xml.etree import ElementTree as etree

from bifrost_frontend.frontend import show_dialog, C_ERROR

from config import APP_INFO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_s3_mount_processes: list[subprocess.Popen] = []


# ============================================================================
# RCLONE EXECUTABLE RESOLUTION
# ============================================================================

def _ensure_executable(path: Path) -> None:
    if not os.access(path, os.X_OK):
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def get_rclone_executable() -> str:
    """
    Devuelve la ruta al ejecutable rclone.

    Prioridad:
      1. Bundle Flet (FLET_ASSETS_DIR/bin/rclone) — apps empaquetadas.
      2. assets/bin del repo (dev: `python src/main.py` sin `flet run`).
      3. rclone en el PATH del sistema (modo web/cluster).
    """
    rclone_name = "rclone.exe" if sys_platform == "win32" else "rclone"

    flet_assets = os.environ.get("FLET_ASSETS_DIR")
    if flet_assets:
        bundled = Path(flet_assets) / "bin" / rclone_name
        if bundled.exists():
            _ensure_executable(bundled)
            return str(bundled)

    dev_asset = (
        Path(__file__).parent.parent.parent
        / f"bifrost-{APP_INFO['flavour']}" / "src" / "assets" / "bin" / rclone_name
    )
    if dev_asset.exists():
        _ensure_executable(dev_asset)
        return str(dev_asset.resolve())

    in_path = shutil.which("rclone")
    if in_path:
        return in_path

    raise EnvironmentError(
        "rclone not found. The application bundle appears to be incomplete — "
        "please reinstall BIFROST."
    )


# ============================================================================
# CONSTANTES Y VERSIÓN
# ============================================================================

MINIO_SERVERS = {
    "minio-archive": {
        "IRB": {
            "profile": "minio-archive",
            "endpoint": "https://minio-archive.sc.irbbarcelona.org:9000"
        }
    },
    "irbminio": {
        "IRB": {
            "profile": "irbminio",
            "endpoint": "http://irbminio.sc.irbbarcelona.org:9000"
        }
    },
    "minio": {
        "IRB": {
            "profile": "minio",
            "endpoint": "https://minio.sc.irbbarcelona.org:9000",
            "extra_rclone_config": {
                "no_check_bucket": "true",
                "region": "eu-south-2",
            }
        }
    }
}

REPO = "its-irb/irb-storage-public-scripts"

try:
    from version import __version__
except ImportError:
    __version__ = "1.0.1"

# ============================================================================
# COMPROBACIÓN DE VERSIÓN / ACTUALIZACIONES (lógica pura, sin GUI)
# ============================================================================

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
    #     print("⚠️ Force update mode enabled (--update flag detected)")
    #     print("Simulating new version available: 999.999.999")
    #     return "v999.999.999"

    print(f"Version of this executable: {__version__}")
    try:
        url = f"https://api.github.com/repos/{REPO}/releases/latest"
        print(f"Checking the latest version of {REPO}... at url: {url}")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            latest_tag = response.json().get("tag_name", "")
            print(f"\nLatest available version: {latest_tag.strip('v')}")
            if latest_tag and _parse_version(latest_tag) > _parse_version(__version__):
                print(f"\n🚀 New version available: {latest_tag}")
                return latest_tag
            else:
                print("✅ You are using the latest version.")
        else:
            print("⚠️ Could not check the latest version.")
    except Exception as e:
        print(f"⚠️ Error verifying update: {e}")
    return None

def should_check_for_updates() -> bool:
    """
    Determina si se debe comprobar actualizaciones en el entorno actual.
    Devuelve False en entornos HPC/cluster o cuando no se ejecuta como binario compilado,
    a menos que se pase el flag --update (útil para testing en desarrollo).
    """
    if "--update" in sys.argv:
        return True
    if not getattr(sys, 'frozen', False) and not os.environ.get('FLET_APP_STORAGE_TEMP'):
        print("ℹ️ Running as Python script (not compiled). Skipping update check.")
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
        return "-macos.dmg"
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



# ============================================================================
# UTILIDADES DEL SISTEMA
# ============================================================================

def obtener_num_cpus() -> int:
    """Obtiene el número de CPUs disponibles. Prioriza SLURM_CPUS_PER_TASK."""
    cpus = os.environ.get("SLURM_CPUS_PER_TASK")
    if cpus:
        try:
            return int(cpus)
        except ValueError:
            pass
    return os.cpu_count() or 1


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


def traducir_ruta_a_remote(ruta_local: str, mounts_activos: list) -> str:
    """Convierte una ruta local a formato rclone remote:/ruta."""
    ruta_local = os.path.abspath(ruta_local)
    for mount in mounts_activos:
        mount_path = os.path.abspath(mount["mount_path"])
        if ruta_local.startswith(mount_path):
            subpath_relativa = os.path.relpath(ruta_local, mount_path)
            subpath_relativa = "" if subpath_relativa == "." else subpath_relativa
            ruta_remote = f'{mount["remote_name"]}:{mount["remote_subpath"]}'
            if subpath_relativa:
                ruta_remote = f"{ruta_remote}/{subpath_relativa}"
            return ruta_remote
    return ruta_local


def open_file(path: str) -> None:
    """Abre un directorio en el explorador de archivos del SO."""
    if sys_platform == "win32":
        import winreg
        FILEBROWSER_PATH = os.path.join(os.getenv('WINDIR'), 'explorer.exe')
        path = os.path.normpath(path + "\\")
        subprocess.run([FILEBROWSER_PATH, path])
    elif sys_platform == "darwin":
        subprocess.Popen(["open", path])


# ============================================================================
# DETECCIÓN DE FUSE / WINFSP
# ============================================================================

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


def install_winfsp_windows(page=None, on_progress=None) -> bool:
    """Descarga e instala WinFsp en Windows.

    Args:
        page: objeto Flet page (opcional, solo para tipado uniforme).
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


def _check_fuse_macos() -> bool:
    """Detecta fuse-t en macOS. Comprueba rutas del sistema y el framework bundled en el .app."""
    candidates = [
        Path("/usr/local/lib/libfuse-t.dylib"),
        Path("/Library/Filesystems/fuse-t.fs"),
        Path("/usr/local/include/fuse-t"),
        # modo desarrollo
        Path(__file__).parent.parent.parent / 'bifrost-{0:s}'.format(APP_INFO["flavour"]) / 'src' / 'frameworks' / 'fuse_t.framework' / "Versions" / "Current" / "fuse_t",
    ]
    bundle_fw = _macos_app_bundle_frameworks()
    if bundle_fw:
        candidates.append(bundle_fw / "fuse_t.framework" / "Versions" / "Current" / "fuse_t")
    return any(p.exists() for p in candidates)

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


# ============================================================================
# PARA SOLUCIONAR PROBLEMA DE VENTANA DE CONSOLA EN WINDOWS AL LANZAR SUBPROCESOS (RCLONE)
# ============================================================================
def _subprocess_kwargs() -> dict:
    """Suprime la ventana de consola en Windows para subprocesos."""
    if sys_platform == "win32":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}

# ============================================================================
# AUTENTICACIÓN STS (MinIO) Y GESTIÓN DE CREDENCIALES RCLONE
# ============================================================================


def get_credentials(endpoint: str, username: str, password: str, durationseconds: int = 86400) -> dict | None:
    """
    Obtiene credenciales STS temporales desde MinIO vía LDAP.

    Returns:
        Dict con AccessKeyId, SecretAccessKey, SessionToken o None si falla.
    """
    payload = {
        "Action": "AssumeRoleWithLDAPIdentity",
        "LDAPUsername": username,
        "LDAPPassword": password,
        "DurationSeconds": durationseconds,
        "Version": "2011-06-15",
    }
    r = requests.post(endpoint, data=payload)

    print(f"[STS] HTTP {r.status_code}")
    if r.status_code >= 400:
        print(f"[STS] Response headers: {dict(r.headers)}")
        print(f"[STS] Response body:\n{r.text}")

    try:
        root = etree.fromstring(r.content)
    except Exception as e:
        print(f"[STS] ERROR: respuesta no es XML válido: {e}")
        print(f"[STS] Raw body:\n{r.text}")
        return None

    ns = {"ns": "https://sts.amazonaws.com/doc/2011-06-15/"}

    err = root.find("ns:Error", ns) or root.find(".//ns:Error", ns)
    if err is not None:
        code  = err.findtext("ns:Code", namespaces=ns)
        msg   = err.findtext("ns:Message", namespaces=ns)
        reqid = root.findtext(".//ns:RequestId", namespaces=ns)
        print(f"[STS] Error Code={code} Message={msg} RequestId={reqid}")

    et = root.find("ns:AssumeRoleWithLDAPIdentityResult/ns:Credentials", ns)
    if et is None:
        print("[STS] No se encontró Credentials en la respuesta XML.")
        print(f"[STS] Body (XML):\n{r.text}")
        print("ERROR: Invalid LDAP credentials")
        return None

    credentials = {}
    for el in et:
        _, _, tag = el.tag.rpartition("}")
        credentials[tag] = el.text
    return credentials
    

def get_usuario_from_session_token(session_token: str) -> str | None:
    """Extrae el usuario del JWT del session_token de MinIO."""
    try:
        payload = jwt.decode(session_token, options={"verify_signature": False})
        #print(f"[token] payload keys: {list(payload.keys())}")
        usuario = payload.get("ldapUsername") or payload.get("sub")
        print(f"[token] ldapUsername={usuario!r}")
        return usuario
    except Exception as e:
        print(f"Error leyendo usuario del token: {e}")
        return None

def configure_rclone(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str,
    endpoint: str,
    profilename: str = "minio-gordo",
    extra_config: dict | None = None,
) -> None:
    """Crea o actualiza un perfil S3/MinIO en rclone.conf con las credenciales STS."""
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    if config_path.exists():
        config.read(config_path)

    if profilename in config:
        section = config[profilename]
        section["endpoint"]          = endpoint
        section["access_key_id"]     = aws_access_key_id
        section["secret_access_key"] = aws_secret_access_key
        section["session_token"]     = aws_session_token
    else:
        config[profilename] = {
            "type":              "s3",
            "provider":          "Minio",
            "endpoint":          endpoint,
            "acl":               "bucket-owner-full-control",
            "env_auth":          "false",
            "access_key_id":     aws_access_key_id,
            "secret_access_key": aws_secret_access_key,
            "session_token":     aws_session_token,
        }

    if extra_config:
        for key, value in extra_config.items():
            config[profilename][key] = str(value)

    with open(config_path, "w") as f:
        config.write(f)


def get_rclone_session_token(profile_name: str, config_path: str | None = None) -> str:
    """Lee el session_token del perfil rclone dado. Devuelve '' si no existe."""
    if not config_path:
        if sys_platform == "darwin":
            config_path = os.path.expanduser("~/.config/rclone/rclone.conf")
        elif sys_platform == "win32":
            config_path = os.path.join(
                os.path.expanduser("~"), "AppData", "Roaming", "rclone", "rclone.conf"
            )
        else:
            config_path = os.path.expanduser("~/.config/rclone/rclone.conf")

    if not os.path.isfile(config_path):
        print(f"El fichero de configuracion de rclone {config_path} no existe")
        return ""

    config = configparser.ConfigParser()
    config.read(config_path)

    if profile_name not in config:
        print(f"Perfil '{profile_name}' no encontrado en {config_path}")
        return ""

    return config[profile_name].get("session_token", "")


def get_expiration_from_session_token(session_token: str):
    """
    Decodifica el JWT del session_token y devuelve el tiempo restante hasta expiración.

    Returns:
        timedelta restante o None si no se puede leer.
    """
    try:
        payload = jwt.decode(session_token, options={"verify_signature": False})
        exp_timestamp = payload.get("exp")
        if not exp_timestamp:
            print("El token no contiene 'exp'.")
            return None
        exp_time = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = exp_time - now
        print(f"Expira en: {remaining} ({exp_time})")
        return remaining
    except Exception as e:
        print(f"Error decodificando token: {e}")
        return None


def _get_s3_mount_base() -> Path:
    """Devuelve la carpeta raíz donde se crean los mount points S3."""
    if platform.system() == "Windows":
        return Path("C:/rclone-mounts")
    return Path.home() / "rclone-mounts"



def mount_rclone_S3_prefix_to_folder(rclone_profile: str, s3_prefix: str) -> None:
    import shutil

    try:
        rclone = get_rclone_executable()
    except EnvironmentError as e:
        raise EnvironmentError(str(e))

    sistema = platform.system()
    env = {**os.environ}
    if sistema == "Darwin":
        if not _check_fuse_macos():     
            raise EnvironmentError("fuse-t not detected. Download it with macos-third-party-assets-downloader.sh")
        bundle_fw = _macos_app_bundle_frameworks()
        if bundle_fw:
            env["CGOFUSE_LIBFUSE_PATH"] = str(bundle_fw / "fuse_t.framework" / "Versions" / "Current" / "fuse_t")
        elif (Path(__file__).parent.parent.parent / 'bifrost-{0:s}'.format(APP_INFO["flavour"]) / 'src' / 'frameworks' / 'fuse_t.framework' / "Versions" / "Current" / "fuse_t").exists():
            env["CGOFUSE_LIBFUSE_PATH"] = str(Path(__file__).parent.parent.parent / 'bifrost-{0:s}'.format(APP_INFO["flavour"]) / 'src' / 'frameworks' / 'fuse_t.framework' / "Versions" / "Current" / "fuse_t")
        elif getattr(sys, "frozen", False):
            env["CGOFUSE_LIBFUSE_PATH"] = str(Path(sys.executable).parents[1] / "Frameworks" / "fuse_t.framework" / "Versions" / "Current" / "fuse_t")
        else:
            dev_path = Path(sys.executable).parent.parent.parent / 'bifrost-{0:s}'.format(APP_INFO["flavour"]) / 'src' / 'frameworks' / 'fuse_t.framework' / 'Versions' / 'Current' / 'fuse_t'
            if dev_path.exists():
                env["CGOFUSE_LIBFUSE_PATH"] = str(dev_path)
    elif sistema == "Windows":
        if not _check_winfsp_windows():
            raise WinFspMissingError("WinFsp not detected on this system.")
    elif sistema == "Linux":
        if not _check_fuse_linux():
            raise EnvironmentError(
                "FUSE not detected. Install via: sudo apt install fuse  (Debian/Ubuntu) "
                "or: sudo dnf install fuse  (Fedora/RHEL)"
            )
    else:
        raise EnvironmentError(f"Unsupported OS: {sistema}")

    mount_base = _get_s3_mount_base() / rclone_profile
    prefix_sanitizado = s3_prefix.strip("/").replace("/", "_")
    mount_point = mount_base / prefix_sanitizado

    if mount_point.exists() and not os.path.ismount(mount_point):
        try:
            mount_point.rmdir()
        except OSError as e:
            raise EnvironmentError(f"Mount point {mount_point} already exists and could not be removed: {e}") from e

    if sistema != "Windows":
        mount_point.mkdir(parents=True, exist_ok=True)
    else:
       mount_point.parent.mkdir(parents=True, exist_ok=True)

    comando = [rclone, "mount", f"{rclone_profile}:{s3_prefix}", str(mount_point), "--read-only", "--links"]
    if sistema != "Windows":
        comando.append("--allow-non-empty")

    proceso = subprocess.Popen(comando,env=env, **_subprocess_kwargs())
    _s3_mount_processes.append(proceso)

    #import time
    #for _ in range(30):
    #    time.sleep(0.5)
    #    if os.path.ismount(mount_point):
    #        break
    #else:
    #    print(f"[mount] Warning: mount point not ready after 15s: {mount_point}")

    #try:
    #    if sistema == "Windows":
    #        os.startfile(str(mount_point))
    #    else:
    #        opener = {"Darwin": ["open"], "Linux": ["xdg-open"]}
    #        subprocess.Popen(opener[sistema] + [str(mount_point)])
    #except Exception as e:
    #    print(f"Mount successful, but could not open file explorer: {e}")


# ============================================================================
# AUTENTICACIÓN Y GESTIÓN DE USUARIOS LDAP
# ============================================================================

LDAP_SERVER_URL = "ldap://irbldap3.sc.irbbarcelona.org"
LDAP_BASE_DN = "o=irbbarcelona"


def get_ldap_groups(usuario: str) -> list[str]:
    """Obtiene los grupos LDAP a los que pertenece un usuario."""
    server = Server(LDAP_SERVER_URL)
    conn = Connection(server, auto_bind=True)
    conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=f"(uid={usuario})",
        search_scope=SUBTREE,
        attributes=["groupMembership"],
    )
    cn_grupos = []
    for entrada in conn.entries:
        for dn in entrada.groupMembership.values:
            partes = dn.split(",")
            cn = next(
                (p.split("=")[1] for p in partes if p.lower().startswith("cn=")), None
            )
            if cn:
                cn_grupos.append(cn)
    return cn_grupos


def validar_credenciales_ldap(credenciales_ldap: dict | None) -> tuple[bool, str | None]:
    """Valida credenciales LDAP mediante un bind autenticado."""
    if not credenciales_ldap:
        return False
    usuario  = credenciales_ldap["usuario"]
    password = credenciales_ldap["password"]
    server = Server(LDAP_SERVER_URL)
    try:
        conn = Connection(server, auto_bind=True)
        conn.search(LDAP_BASE_DN, f"(cn={usuario})", SUBTREE, attributes=["dn"])
        print(f"[debug] - LDAP: Search for user '{usuario}' returned {len(conn.entries)} entries.")
        if not conn.entries:
            print("[debug] - LDAP: No se encontró el usuario. conn.entries")
            return False, "invalid"
        user_dn = conn.entries[0].entry_dn
        conn_auth = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
        print(f"[debug] - LDAP: Validating credentials for user: {conn_auth}")
        if conn_auth.bind():
            conn_auth.unbind()
            conn.unbind()
            return True, None
        return False, "invalid"
    except Exception as e:
        print(f"LDAP validation error: {e}")
        if "invalid server address" in str(e).lower():
            return False, "vpn"
        return False, "invalid"


def construir_credenciales_smb(
    credenciales_ldap: dict,
    usar_privilegios_its: bool,
    credenciales_admin: dict | None = None,
) -> dict:
    """Construye las credenciales SMB finales según el modo de operación."""
    if usar_privilegios_its:
        if (
            not credenciales_admin
            or not credenciales_admin["usuario"]
            or not credenciales_admin["password"]
        ):
            raise ValueError("Missing admin credentials for ITS privileges.")
        return {
            "usuario":  credenciales_admin["usuario"],
            "password": credenciales_admin["password"],
        }
    return {
        "usuario":  credenciales_ldap["usuario"],
        "password": credenciales_ldap["password"],
    }


# ============================================================================
# GESTIÓN DE SHARES SMB/CIFS
# ============================================================================

EXCEPCION_FILERS = ["filer12-svm-vm"]


def obtener_shares_accesibles(
    grupos_usuario: list[str],
    username: str,
    password: str,
    usuario_actual: str,
    excepcion_filers: list[str],
    usar_privilegios: bool = False,
) -> list[dict]:
    """Obtiene la lista de shares SMB/CIFS accesibles para el usuario."""
    URL = "https://netapp-api-proxy.sc.irbbarcelona.org/get-shares"
    try:
        respuesta = requests.post(
            URL,
            headers={"Content-Type": "application/json"},
            json={"username": username, "password": password},
            verify=False,
        )
        respuesta.raise_for_status()
        raw = respuesta.json()
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as e:
        print(f"Error getting shares from proxy: {e}")
        return []

    grupos_set = {g.strip().lower() for g in grupos_usuario}

    def normalizar_acl(principal: str) -> str:
        s = (principal or "").strip().lower()
        if s.startswith("cn="):
            return s.split(",", 1)[0].removeprefix("cn=").strip()
        if "\\" in s:
            return s.split("\\", 1)[1].strip()
        if "@" in s:
            return s.split("@", 1)[0].strip()
        return s

    resultado = []
    for share in data.get("records", []):
        if share["svm"]["name"] not in excepcion_filers:
            for acl in share.get("acls", []):
                user_or_group = acl.get("user_or_group", "")
                pnorm = normalizar_acl(user_or_group)
                tiene_acceso = (
                    pnorm == usuario_actual.lower() or pnorm in grupos_set
                )
                if usar_privilegios and "domain admins" in user_or_group.strip().lower():
                    tiene_acceso = True
                if tiene_acceso:
                    resultado.append({
                        "name": share["name"],
                        "path": share["path"],
                        "host": share["svm"]["name"].replace("-svm", "")
                               + ".sc.irbbarcelona.org",
                    })
                    break
    return resultado


# ============================================================================
# GESTIÓN DE PERFILES RCLONE
# ============================================================================

def obtener_perfiles_rclone_config(config_path=None) -> list[str]:
    """Lee el rclone.conf y devuelve los nombres de los perfiles configurados."""
    config_path = obtener_ruta_rclone_conf()
    print(f"Using rclone config path: {config_path}")
    if not os.path.exists(config_path):
        return []
    config = configparser.ConfigParser()
    config.read(config_path)
    return config.sections()


def crear_perfil_rclone_smb(
    nombre_perfil: str,
    host: str,
    path: str,
    username: str,
    password: str,
) -> None:
    """Crea (o reemplaza) un perfil SMB en rclone.conf."""
    rclone = get_rclone_executable()
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
    config[nombre_perfil] = {
        "type":   "smb",
        "domain": "IRBBARCELONA",
        "host":   host,
        "user":   username,
        "pass":   subprocess.check_output(
            [rclone, "obscure", password],
            text=True,
            **_subprocess_kwargs(),
        ).strip(),
    }
    with open(config_path, "w") as f:
        config.write(f)


def actualizar_password_perfiles_rclone(
    usuario: str,
    nueva_password: str,
    rclone_config_path: str | None = None,
) -> None:
    """Actualiza la contraseña de todos los perfiles SMB del usuario."""
    rclone = get_rclone_executable()
    print(f"Actualizando contraseña para perfiles rclone tipo '{usuario}-smbmount-*'...")
    if not rclone_config_path:
        rclone_config_path = obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(rclone_config_path)
    try:
        resultado = subprocess.run(
            [rclone, "obscure", nueva_password],
            capture_output=True, text=True, check=True,
            **_subprocess_kwargs(),
        )
        password_obscurecida = resultado.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"❌ Error obscuring password: {e.stderr}")
        return
    actualizado = False
    for section in config.sections():
        if (
            section.startswith(f"{usuario}-smbmount-")
            and config[section].get("type") == "smb"
        ):
            config[section]["pass"] = password_obscurecida
            actualizado = True
    if actualizado:
        with open(rclone_config_path, "w") as f:
            config.write(f)
        print(f"🔐 Password updated for all SMB profiles of '{usuario}'")
    else:
        print(f"⚠️ No profiles '{usuario}-smbmount-*' found in rclone.conf")


# ============================================================================
# MONTAJE / DESMONTAJE DE SHARES
# ============================================================================

def obtener_letra_unidad_disponible() -> str | None:
    """Devuelve la primera letra de unidad disponible en Windows, o None."""
    import string
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        drives_mask = ctypes.windll.kernel32.GetLogicalDrives()
        letras_en_uso = {
            f"{l}:"
            for i, l in enumerate(string.ascii_uppercase)
            if drives_mask & (1 << i)
        }
        for letra in [f"{l}:" for l in string.ascii_uppercase[3:]]:
            if letra not in letras_en_uso:
                return letra
    except Exception as e:
        print(f"Error obteniendo letras de unidad: {e}")
    return None


def generar_punto_montaje(usuario_actual: str, nombre_share: str) -> str:
    """Genera el punto de montaje según el SO."""
    if platform.system() == "Windows":
        letra = obtener_letra_unidad_disponible()
        if letra:
            return letra
        raise Exception("No hay letras de unidad disponibles en Windows")
    return os.path.expanduser(f"~/cifs-mount/{usuario_actual}/{nombre_share}")


def montar_share_rclone(
    nombre_perfil: str,
    share_path: str,
    punto_montaje: str,
    mounts_activos: list,
) -> bool:
    """Monta un share SMB con rclone."""
    rclone = get_rclone_executable()
    rclone_config_path = obtener_ruta_rclone_conf()
    sistema = platform.system()
    if sistema != "Windows":
        os.makedirs(punto_montaje, exist_ok=True)
    if os.path.ismount(punto_montaje):
        return True
    comando = [
        rclone, "mount",
        f"{nombre_perfil}:/{share_path}", str(punto_montaje),
        "--vfs-cache-mode", "off",
        "--read-only",
        "--config", str(rclone_config_path),
    ]
    if sistema == "Windows":
        comando.extend(["--volname", nombre_perfil])
    mounts_activos.append({
        "mount_path":     str(punto_montaje),
        "remote_name":    nombre_perfil,
        "remote_subpath": share_path,
    })
    print(f"Montando {comando}...")
    try:
        proceso = subprocess.Popen(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **_subprocess_kwargs())
        for _ in range(30):
            time.sleep(1)
            if os.path.ismount(punto_montaje):
                return True
        proceso.terminate()
        return False
    except Exception as e:
        print(f"Exception mounting share: {e}")
        return False


def desmontar_todos_los_shares(usuario_actual: str) -> None:
    """Desmonta todos los shares SMB del usuario (llamado en atexit)."""
    sistema = platform.system()
    if sistema == "Windows":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "rclone.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print("All SMB shares have been unmounted.")
        except Exception as e:
            print(f"Error unmounting in Windows: {e}")
    else:
        base_dir = Path.home() / "cifs-mount" / usuario_actual
        if not base_dir.exists():
            return
        for subdir in base_dir.iterdir():
            if subdir.is_dir() and os.path.ismount(subdir):
                try:
                    subprocess.run(["umount", "-f", str(subdir)], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"Error unmounting {subdir}: {e}")
        print("All SMB shares have been unmounted.")


def desmontar_punto_montaje(mount_point: str, log_fn=None) -> None:
    def _log(msg):
        print(msg)
        if log_fn:
            log_fn(msg)

    global _s3_mount_processes
    #mount_point_abs = str(Path(mount_point).resolve())
    try:
        mount_point_abs = str(Path(mount_point).resolve()).rstrip("\\").rstrip("/")
    except OSError:
        mount_point_abs = str(Path(mount_point).absolute()).rstrip("\\").rstrip("/")
    proceso_encontrado = None

    print(f"[debug] S3 processes: {_s3_mount_processes}")

    for proceso in list(_s3_mount_processes):
        print(f"[debug matching] mount_point_abs={mount_point_abs!r}")
        try:
            cmdline = proceso.args if hasattr(proceso, 'args') else []
            print(f"[debug matching] cmdline args={cmdline}")
            # Fix Bug 1: resolver cada arg individualmente, saltando los que no son paths
            matched = False
            for arg in cmdline:
                if not arg:
                    continue
                try:
                    arg_norm = os.path.normcase(os.path.normpath(arg))
                    mp_norm  = os.path.normcase(os.path.normpath(mount_point_abs))
                    print(f"[debug matching] arg_norm: {arg_norm}, mount_point_abs: {mp_norm}")
                    if arg_norm == mp_norm:
                        matched = True
                        break
                except (OSError, ValueError):
                    # args como "irbminio:bucket" no son paths válidos en Windows — ignorar
                    continue
            if matched:
                proceso_encontrado = proceso
                print(f"proceso encontrado {proceso_encontrado}")
                _s3_mount_processes.remove(proceso)
                break
        except Exception as ex:
            _log(f"[unmount] Warning checking process: {ex}")

    if proceso_encontrado is not None:
        _log(f"[unmount] Sending Ctrl-C to PID {proceso_encontrado.pid} for {mount_point}")
        sistema = platform.system()
        if sistema == "Windows":
            # GenerateConsoleCtrlEvent es el método correcto para WinFSP
            # TerminateProcess (.terminate()) puede dejar la unidad en estado colgado
            import ctypes
            try:
                #ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, proceso_encontrado.pid)  # 0 = CTRL_C_EVENT
                result = subprocess.run([f"taskkill", "/PID", str(proceso_encontrado.pid), "/F" , "/T"], check=True, capture_output=True,
                text=True, **_subprocess_kwargs())
                print(f"[taskkill] Output: {result.stdout}")
                try:
                    proceso_encontrado.wait(timeout=5)
                except Exception:
                    _log(f"[unmount] Ctrl-C timeout, forcing kill on PID {proceso_encontrado.pid}")
                    proceso_encontrado.kill()
            except Exception as e:
                _log(f"[unmount] GenerateConsoleCtrlEvent failed: {e}, falling back to kill")
                proceso_encontrado.kill()
        else:
            proceso_encontrado.terminate()
            try:
                proceso_encontrado.wait(timeout=3)
            except Exception:
                proceso_encontrado.kill()
    else:
        _log(f"[unmount] No active process found for {mount_point}, trying filesystem unmount")

    # Fallback: unmount a nivel de filesystem para mounts de sesiones anteriores
    sistema = platform.system()
    if sistema == "Windows":
        return  # WinFSP se desmonta al matar el proceso — no hay fusermount
    try:
        import time
        time.sleep(0.5)
        if not os.path.isdir(mount_point) or not os.path.ismount(mount_point):
            return
        if sistema == "Linux":
            subprocess.run(["fusermount", "-u", mount_point], check=True)
        elif sistema == "Darwin":
            subprocess.run(["umount", mount_point], check=True)
    except Exception as e:
        _log(f"\n⚠️ Could not unmount {mount_point}: {str(e)}\n")

def resolver_mount_point_destino(perfil_rclone: str, ruta_destino: str) -> str:
    """Calcula la ruta local del mount point para un prefijo S3 dado."""
    mount_base = _get_s3_mount_base()  / perfil_rclone
    prefix_sanitizado = ruta_destino.replace("/", "_")
    return str(mount_base / prefix_sanitizado)

def desmontar_todos_los_mounts_s3() -> None:
    """Mata todos los procesos rclone mount de S3 activos."""
    global _s3_mount_processes
    print(f"[atexit] Terminating {len(_s3_mount_processes)} S3 mount processes...")
    for proceso in _s3_mount_processes:
        try:
            proceso.terminate()
            proceso.wait(timeout=3)
        except Exception as e:
            print(f"[atexit] Error terminating rclone mount: {e}")
            try:
                proceso.kill()
            except Exception:
                pass
    _s3_mount_processes.clear()
    print("[atexit] All S3 mounts terminated.")

# ============================================================================
# OPERACIONES RCLONE (COPY / CHECK)
# ============================================================================

def construir_tag_string(metadatos_dict: dict) -> str:
    """Convierte el diccionario de metadatos en una cadena x-amz-tagging URL-encoded."""
    return "&".join(
        f"{k}={urllib.parse.quote(v)}" for k, v in metadatos_dict.items()
    )


def ejecutar_rclone_copy(
    origen: str,
    destino_perfil: str,
    destino_path: str,
    rclone_config_path: str,
    metadatos_dict: dict,
    flags_adicionales: list[str],
    num_cores: int,
    log_fn,
    on_success=None,
    on_finish=None,
    expose_proceso: dict | None = None,
) -> None:
    """Lanza rclone copy. Si *expose_proceso* es un dict, guarda el Popen en expose_proceso['proc']."""
    rclone = get_rclone_executable()
    tag_string   = construir_tag_string(metadatos_dict)
    header_value = f"x-amz-tagging:{tag_string}"


    comando = [
        rclone, "copy",
        origen,
        f"{destino_perfil}:/{destino_path}",
        "--config", rclone_config_path,
        "--checksum",
        "--check-first",
        "--copy-links",
        "--exclude", "**/.DS_Store",
        "--exclude", "**/*.Thumbs.db",
        "--exclude", ".snapshot/**",
        "--exclude", "**/.snapshot/**",
        "--exclude", ".snapshot/",
        "--exclude", "**/.Trash*/**",
        "--exclude", "**/.cache/**",
        "--progress",
        "--stats=1s",
        "--header-upload", header_value,
    ]
    comando.extend(flags_adicionales)

    comando_str = " ".join(shlex.quote(arg) for arg in comando)
    log_fn(f"\n🧾 Full command:\n{comando_str}\n\n")

    # Run rclone at a lower CPU priority so the Hypercorn/Python server
    # process is always schedulable even when rclone saturates all cores.
    # nice(10) means the OS will prefer processes at niceness < 10 (e.g.
    # Hypercorn at niceness 0) when CPU is contested. Linux/macOS only;
    # preexec_fn is silently ignored on Windows (but we also gate it).
    _preexec = (lambda: os.nice(10)) if sys_platform != "win32" else None

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            preexec_fn=_preexec,
            **_subprocess_kwargs(),
        )
        if expose_proceso is not None:
            expose_proceso["proc"] = proceso
        for linea in proceso.stdout:
            log_fn(linea)
        proceso.wait()
        if proceso.returncode == 0:
            log_fn("\n✅ Copy completed successfully.\n")
            if on_success:
                on_success()
        else:
            log_fn(f"\n❌ Copy error. Code: {proceso.returncode}")
    except Exception as e:
        log_fn(f"\n❌ Exception while executing rclone: {str(e)}")
    finally:
        # Guarantee the subprocess is not left running if the stdout loop raised.
        try:
            if proceso.poll() is None:
                proceso.terminate()
        except Exception:
            pass
        if expose_proceso is not None:
            expose_proceso["proc"] = None
        if on_finish:
            on_finish()


def es_directorio_rclone(ruta_rclone: str, config_path: str) -> bool:
    """Devuelve True si la ruta rclone apunta a un directorio."""
    rclone = get_rclone_executable()
    try:
        resultado = subprocess.run(
            [rclone, "lsjson", ruta_rclone, "--config", config_path],
            capture_output=True,
            check=True,
            encoding="utf-8",
            errors="replace",
            **_subprocess_kwargs(),
        )
        if not resultado.stdout:
            return False
        salida = json.loads(resultado.stdout)
        if not salida:
            return False
        if len(salida) > 1:
            return True
        return salida[0].get("IsDir", False)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return False


def traducir_a_ruta_local_montada(
    origen: str,
    mounts_activos: list,
    config_path: str,
) -> str:
    """Si 'origen' es un remote rclone con mount activo, devuelve la ruta local equivalente."""
    if ":" in origen and not origen.startswith("/"):
        try:
            remote, ruta_relativa = origen.split(":", 1)
        except ValueError:
            return origen
        ruta_relativa = ruta_relativa.lstrip("/")
        for mount in mounts_activos:
            if all(k in mount for k in ("remote_name", "mount_path", "remote_subpath")):
                if (
                    mount["remote_name"] == remote
                    and ruta_relativa.startswith(mount["remote_subpath"])
                ):
                    subruta = ruta_relativa[len(mount["remote_subpath"]):].lstrip("/")
                    return str(Path(mount["mount_path"]) / subruta)
    return origen


def preparar_origen_para_check(
    origen: str,
    mounts_activos: list,
    rclone_config_path: str,
) -> tuple[str, str | None]:
    """Analiza el origen y lo normaliza para rclone check."""
    if ":" in origen and not origen.startswith("/"):
        remote, ruta_local = origen.split(":", 1)
        ruta_local = ruta_local.lstrip("/")
        if es_directorio_rclone(origen, rclone_config_path):
            carpeta = traducir_a_ruta_local_montada(origen, mounts_activos, rclone_config_path)
            return carpeta, None
        else:
            ruta_local_path = Path(ruta_local)
            fichero = ruta_local_path.name
            carpeta_remota = f"{remote}:{str(ruta_local_path.parent)}"
            carpeta = traducir_a_ruta_local_montada(
                carpeta_remota, mounts_activos, rclone_config_path
            )
            return carpeta + f"/{fichero}", fichero
    else:
        if os.path.isfile(origen):
            ruta_local_path = Path(origen)
            fichero = ruta_local_path.name
            return str(ruta_local_path.parent) + f"/{fichero}", fichero
        return origen, None


def ejecutar_rclone_check(
    origen: str,
    destino_perfil: str,
    destino_path: str,
    rclone_config_path: str,
    flags_adicionales: list[str],
    mounts_activos: list,
    log_fn,
    on_finish=None,
    expose_proceso: dict | None = None,
) -> None:
    """Lanza rclone check. Si *expose_proceso* es un dict, guarda el Popen en expose_proceso['proc']."""
    rclone = get_rclone_executable()
    origen_ajustado, fichero = preparar_origen_para_check(
        origen, mounts_activos, rclone_config_path
    )
    combined_path = Path.home() / "rclone-combined-check.txt"
    combined_path.parent.mkdir(parents=True, exist_ok=True)

    comando = [
        rclone, "check",
        origen_ajustado,
        f"{destino_perfil}:/{destino_path}",
        "--config", rclone_config_path,
        "--progress",
        "--stats=1s",
    ]
    if fichero:
        comando += ["--one-way", "--copy-links"]
    else:
        comando += [
            "--one-way",
            "--combined", str(combined_path),
            "--copy-links",
            "--exclude", "/.DS_Store",
            "--exclude", "**/.DS_Store",
            "--exclude", "/Thumbs.db",
            "--exclude", "**/Thumbs.db",
            "--exclude", ".snapshots/**",
            "--exclude", "**/.snapshots/**",
        ]
    comando.extend(flags_adicionales)

    comando_str = " ".join(shlex.quote(arg) for arg in comando)
    log_fn(f"\n🧾 Full command:\n{comando_str}\n\n")

    _preexec = (lambda: os.nice(10)) if sys_platform != "win32" else None

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            preexec_fn=_preexec,
            **_subprocess_kwargs(),
        )
        if expose_proceso is not None:
            expose_proceso["proc"] = proceso
        for linea in proceso.stdout:
            log_fn(linea)
        proceso.wait()
        if proceso.returncode == 0:
            log_fn("\n✅ Verification OK: no differences found.\n")
        elif proceso.returncode == 1:
            # rclone check exits 1 when differences are found — expected, not a hard error.
            # Exit codes ≥2 indicate real failures (network, permissions, etc.).
            log_fn(
                "\n⚠️ Verification complete: differences found. "
                "Check the combined report for details.\n"
            )
        else:
            log_fn(
                f"\n❌ Verification failed (exit code {proceso.returncode}). "
                "Check for network or permissions issues.\n"
            )
    except Exception as e:
        log_fn(f"\n❌ Exception during verification: {str(e)}")
    finally:
        # Guarantee the subprocess is not left running if the stdout loop raised.
        try:
            if proceso.poll() is None:
                proceso.terminate()
        except Exception:
            pass
        if expose_proceso is not None:
            expose_proceso["proc"] = None
        if on_finish:
            on_finish()


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


# ============================================================================
# LÓGICA DE INICIALIZACIÓN
# ============================================================================

def configurar_perfiles_smb_si_faltan(
    shares_accesibles: list,
    credenciales_smb: dict,
    perfiles_configurados: list,
) -> list:
    """Crea los perfiles rclone SMB que falten y devuelve la lista actualizada."""
    shares_no_configurados = [
        share for share in shares_accesibles
        if f"{credenciales_smb['usuario']}-smbmount-{share['host']}"
        not in perfiles_configurados
    ]
    if not shares_no_configurados:
        return perfiles_configurados
    for share in shares_accesibles:
        nombre_perfil = f"{credenciales_smb['usuario']}-smbmount-{share['host']}"
        if nombre_perfil not in perfiles_configurados:
            crear_perfil_rclone_smb(
                nombre_perfil=nombre_perfil,
                host=share["host"],
                path=share["name"],
                username=credenciales_smb["usuario"],
                password=credenciales_smb["password"],
            )
            print(f"Rclone profile created for share {share['name']}: {nombre_perfil}")
    return obtener_perfiles_rclone_config()


def montar_shares_seleccionados(
    recursos_seleccionados: list[str],
    recursos_cifs_dict: dict,
    mounts_activos: list,
) -> list[str]:
    """Monta los shares seleccionados y devuelve lista de los que fallaron."""
    fallidos = []
    for recurso in recursos_seleccionados:
        datos = recursos_cifs_dict[recurso]
        punto_montaje = datos["punto_montaje"]
        if not os.path.ismount(punto_montaje):
            if platform.system() != "Windows":
                os.makedirs(punto_montaje, exist_ok=True)
            exito = montar_share_rclone(
                datos["nombre_perfil"],
                datos["remote_path"],
                punto_montaje,
                mounts_activos,
            )
            if not exito:
                fallidos.append(recurso)
    return fallidos


def construir_recursos_cifs_dict(shares: list, usuario_actual: str) -> dict:
    """Construye el diccionario de recursos CIFS con sus datos de montaje."""
    resultado = {}
    for share in shares:
        nombre_share = share["name"]
        remote_host  = share["host"]
        resultado[nombre_share] = {
            "nombre_perfil": f"{usuario_actual}-smbmount-{remote_host}",
            "punto_montaje":  generar_punto_montaje(usuario_actual, nombre_share),
            "remote_path":    nombre_share,
            "remote_host":    remote_host,
        }
    return resultado

# ============================================================================
# HELPER THREAD-SAFE PARA ACTUALIZAR UI
# ============================================================================

def ui_call(page: ft.Page, fn: Callable) -> None:
    # Use run_task (asyncio coroutine) instead of run_thread (ThreadPoolExecutor).
    # Flet's ObjectPatch.from_diff walks control.controls as a live list with no
    # lock; run_thread runs fn() in a thread pool *in parallel* to the asyncio
    # event loop, so concurrent .controls.clear()/.extend() from the thread pool
    # races with the diff walker → IndexError: list index out of range.
    # run_task schedules the coroutine on the same asyncio event loop; since
    # _compare_lists contains no `await`, no run_task coroutine can preempt it
    # mid-iteration, eliminating the race entirely.
    async def _wrapper():
        fn()
    page.run_task(_wrapper)


# ============================================================================
# WRAPPER SEGURO PARA HILOS — captura excepciones y las muestra en diálogo
# ============================================================================

def safe_thread(page: ft.Page, target: Callable, daemon: bool = True) -> threading.Thread:
    """
    Crea un Thread que captura cualquier excepción no controlada y la muestra
    en un diálogo de error en lugar de matar el proceso silenciosamente.
    """
    def _wrapper():
        try:
            target()
        except Exception as exc:
            tb = traceback.format_exc()
            print(f"[safe_thread] Unhandled exception:\n{tb}")
            _exc = exc  # capture before Python deletes the except-clause variable
            def _show(e=_exc):
                show_dialog(
                    page,
                    "Unexpected error",
                    f"{type(e).__name__}: {e}\n\nCheck console or contact ITS.",
                    C_ERROR,
                )
            ui_call(page, _show)

    t = threading.Thread(target=_wrapper, daemon=daemon)
    return t
