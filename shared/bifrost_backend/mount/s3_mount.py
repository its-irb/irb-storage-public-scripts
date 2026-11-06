"""Montaje y desmontaje de buckets (o carpetas) de MinIO con rclone mount (bifrost-mount)."""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from ..common.logs import rclone_log_path
from ..common.rclone import _subprocess_kwargs, get_rclone_executable
from ..common.rclone_mount import MountError, drain_rclone_log, is_mounted, mount_and_wait, stop_process
from ..common.rclone_output import FUSE_MISSING_LINUX, FUSE_MISSING_MACOS, ISSUES_BY_CODE
from .preflight import WinFspMissingError, _check_fuse_linux, _check_winfsp_windows, _get_fuse_macos

log = logging.getLogger("bifrost.mount")

_s3_mount_processes: list[subprocess.Popen] = []   # rclone de los montajes de esta sesión
# Opciones de caché de rclone que se pueden pasar al arrancar la app y se reenvían a cada montaje.
_VFS_FLAGS_WITH_VALUE = {"--vfs-cache-mode", "--vfs-cache-max-size", "--cache-dir"}


def _get_s3_mount_base() -> Path:
    """Devuelve la carpeta raíz donde se crean los mount points S3."""
    if platform.system() == "Windows":
        return Path("C:/rclone-mounts")
    return Path.home() / "rclone-mounts"


def resolver_mount_point_destino(perfil_rclone: str, ruta_destino: str) -> str:
    """Carpeta local donde se monta un bucket o carpeta de MinIO. La misma al montar, desmontar y al detectar
    los montajes de una sesión anterior."""
    return str(_get_s3_mount_base() / perfil_rclone / ruta_destino.strip().strip("/").replace("/", "_"))


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
    env = _fuse_env()
    if _prepare_mount_point(mount_point):
        log.info("already mounted: %s", mount_point)
        return str(mount_point)
    perdido = _take_process(mount_point)
    if perdido is not None:             # el sistema quitó el montaje (macOS, al cortarse la red) y rclone sigue vivo
        log.info("mount %s: stopping rclone pid %d of the lost mount", mount_point, perdido.pid)
        _stop_mount_process(perdido)
        drain_rclone_log(_mount_log_path(mount_point), f"mount {mount_point}")
    comando = [get_rclone_executable(), "mount", f"{rclone_profile}:{prefix}", str(mount_point),
               "--read-only", "--links", *_vfs_flags_from_argv()]
    if platform.system() != "Windows":
        comando.append("--allow-non-empty")
    log.info("mounting %s:%s at %s", rclone_profile, prefix, mount_point)
    proceso = mount_and_wait(comando, mount_point, _mount_log_path(mount_point), env=env)
    _s3_mount_processes.append(proceso)
    return str(mount_point)


def _fuse_env() -> dict:
    """Entorno de rclone mount con el controlador de carpetas del sistema (fuse-t, WinFsp o FUSE)."""
    sistema = platform.system()
    env = {**os.environ}
    if sistema == "Darwin":
        fuse_path = _get_fuse_macos()
        if fuse_path is None:
            log.error("fuse-t not found (if running from source: shared/macos-assets-downloader.sh)")
            raise MountError(FUSE_MISSING_MACOS)
        env["CGOFUSE_LIBFUSE_PATH"] = str(fuse_path)
    elif sistema == "Windows":
        if not _check_winfsp_windows():
            raise WinFspMissingError("WinFsp not detected on this system.")
    elif sistema == "Linux":
        if not _check_fuse_linux():
            raise MountError(FUSE_MISSING_LINUX)
    else:
        raise EnvironmentError(f"Unsupported OS: {sistema}")
    return env


def _prepare_mount_point(mount_point: Path) -> bool:
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
    if _mount_point_is_stale(mount_point):
        log.info("stale mount point %s: forcing unmount", mount_point)
        _force_unmount_path(mount_point)
    elif is_mounted(mount_point):
        return True
    mount_point.mkdir(parents=True, exist_ok=True)
    return False


def _vfs_flags_from_argv() -> list[str]:
    """Opciones de caché de rclone pasadas al arrancar la app (p. ej. --vfs-cache-mode full)."""
    flags: list[str] = []
    for i, arg in enumerate(sys.argv[:-1]):
        if arg in _VFS_FLAGS_WITH_VALUE:
            flags += [arg, sys.argv[i + 1]]
    return flags


def _mount_point_is_stale(mount_point: Path) -> bool:
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
        _stop_mount_process(proceso)
        pids = [proceso.pid]
    else:
        pids = _rclone_pids_serving(mount_point)
        log.info("unmount %s: rclone from a previous session, PIDs %s", mount_point, pids or "not found")
        for pid in pids:
            _stop_pid(pid)
    if platform.system() != "Windows" and not _wait_unmounted(mount_point, seconds=3.0 if pids else 0):
        log.info("unmount %s: still mounted after %.1f s, forcing", mount_point, time.monotonic() - start)
        _force_unmount_path(Path(mount_point))
    if _wait_unmounted(mount_point):
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
            _stop_mount_process(proceso)
            if mount_point and not windows and not _wait_unmounted(mount_point):
                _force_unmount_path(Path(mount_point))
            if mount_point:
                drain_rclone_log(_mount_log_path(mount_point), f"mount {mount_point}")
        except Exception as ex:
            log.warning("closing the mount %s failed: %s", mount_point, ex)
    _s3_mount_processes.clear()


def _take_process(mount_point: str | Path) -> subprocess.Popen | None:
    """Saca de la lista el rclone de esta sesión que sirve la carpeta (None si no hay ninguno)."""
    target = _normalized(mount_point)
    for proceso in list(_s3_mount_processes):
        if len(proceso.args) > 3 and _normalized(proceso.args[3]) == target:
            _s3_mount_processes.remove(proceso)
            return proceso
    return None


def _normalized(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _stop_mount_process(proceso: subprocess.Popen) -> None:
    """En Windows, taskkill del árbol del proceso (TerminateProcess puede dejar la unidad de WinFsp colgada)."""
    if platform.system() != "Windows":
        stop_process(proceso)
        return
    _taskkill(proceso.pid)
    try:
        proceso.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proceso.kill()


def _taskkill(pid: int) -> None:
    result = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True,
                            **_subprocess_kwargs())
    if result.returncode != 0:
        log.warning("taskkill %s failed: %s", pid, (result.stderr or result.stdout).strip())


def _stop_pid(pid: int) -> None:
    """Termina un rclone que no lanzó esta sesión: taskkill en Windows (como `_stop_mount_process`) y SIGTERM en
    macOS/Linux (como `Popen.terminate`: rclone desmonta su carpeta y sale)."""
    if platform.system() == "Windows":
        _taskkill(pid)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as ex:
        log.warning("could not stop rclone pid %d: %s", pid, ex)


def _rclone_pids_serving(mount_point: str) -> list[int]:
    """PIDs de los `rclone mount` cuya línea de comandos tiene esta carpeta como argumento completo."""
    # La carpeta completa, entre comillas, espacios o los extremos: …/bkt no debe coincidir con …/bkt2.
    target = re.compile(r'(?:^|["\s])' + re.escape(_normalized(mount_point)) + r'(?=["\s]|$)')
    return [pid for pid, command_line in _rclone_mount_processes() if target.search(command_line)]


def _rclone_mount_processes() -> list[tuple[int, str]]:
    """(PID, línea de comandos) de cada `rclone mount` en marcha: no las copias de Bifrost Transfer, aunque lean de
    una carpeta montada. En Windows la línea va normalizada como `_normalized` (minúsculas y "\\"); esa parte no se
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
    mount_command = re.compile(r'rclone(?:\.exe)?"?\s+mount\s')      # el ejecutable seguido del subcomando
    processes = []
    for line in result.stdout.splitlines():
        if windows:
            pid, _, command_line = line.strip().partition("\t")
            command_line = os.path.normcase(command_line.replace("/", "\\"))
        else:
            parts = line.split(None, 2)
            if len(parts) < 3 or parts[1] != "rclone":
                continue
            pid, _, command_line = parts
        if pid.isdigit() and mount_command.search(command_line):
            processes.append((int(pid), command_line))
    return processes


def _wait_unmounted(mount_point: str | Path, seconds: float = 3.0) -> bool:
    """True cuando la carpeta deja de estar montada (rclone desmonta al terminar, pero tarda un momento)."""
    end = time.monotonic() + seconds
    while is_mounted(mount_point):
        if time.monotonic() > end:
            return False
        time.sleep(0.1)
    return True


def _force_unmount_path(mount_point: Path) -> None:
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
