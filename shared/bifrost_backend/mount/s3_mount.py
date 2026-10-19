"""Montaje y desmontaje de prefijos S3 con rclone mount (bifrost-mount)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

from ..common.rclone import _subprocess_kwargs, get_rclone_executable
from .preflight import WinFspMissingError, _check_fuse_linux, _check_winfsp_windows, _get_fuse_macos


_s3_mount_processes: list[subprocess.Popen] = []


def _get_s3_mount_base() -> Path:
    """Devuelve la carpeta raíz donde se crean los mount points S3."""
    if platform.system() == "Windows":
        return Path("C:/rclone-mounts")
    return Path.home() / "rclone-mounts"


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
            print(f"[mount] Desmontaje forzado OK con: {' '.join(comando)}")
            return
        except Exception as e:
            print(f"[mount] Falló '{' '.join(comando)}': {e}")
            continue


def _cleanup_stale_mount_point(mount_point: Path) -> None:
    """Pre-mount cleanup: si mount_point es un mount colgado de una sesión
    anterior (cierre abrupto), lo desmonta y limpia antes de volver a montar.
    """
    if not mount_point.exists():
        return
    if not _mount_point_is_stale(mount_point):
        return

    print(f"[mount] Punto de montaje colgado detectado en {mount_point}, forzando limpieza...")
    _force_unmount_path(mount_point)

    try:
        if mount_point.exists() and not os.path.ismount(mount_point):
            mount_point.rmdir()
    except OSError as e:
        print(f"[mount] No se pudo limpiar {mount_point} tras el desmontaje forzado: {e}")


def mount_rclone_S3_prefix_to_folder(rclone_profile: str, s3_prefix: str) -> None:
    rclone = get_rclone_executable()
    sistema = platform.system()
    env = {**os.environ}

    if sistema == "Darwin":
        fuse_path = _get_fuse_macos()
        if fuse_path is None:
            print(f"[mount] fuse-t dylib not found (profile={rclone_profile!r}) — see [fuse-t] OK/MISS lines above", flush=True)
            raise EnvironmentError(
                "The folder driver (fuse-t) is missing. Reinstall BIFROST — or, if running from source, "
                "run shared/macos-assets-downloader.sh from bifrost-mount/src."
            )

        else:
            env["CGOFUSE_LIBFUSE_PATH"] = str(fuse_path)

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
    s3_prefix_limpio = s3_prefix.strip().strip("/")
    if not s3_prefix_limpio:
        print(f"[mount] Empty s3_prefix rejected (profile={rclone_profile!r}, prefix={s3_prefix!r})", flush=True)
        raise EnvironmentError("No folder selected to mount — pick a bucket or folder first.")

    prefix_sanitizado = s3_prefix_limpio.replace("/", "_")
    mount_point = mount_base / prefix_sanitizado
    print(f"[mount] Mounting {rclone_profile}:{s3_prefix} to {mount_point} ...", flush=True)

    if sistema != "Windows":
        _cleanup_stale_mount_point(mount_point)

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

    FLAGS_WITH_VALUE = {
        "--vfs-cache-mode",
        "--vfs-cache-max-size",
        "--cache-dir",
    }

    for i, arg in enumerate(sys.argv):
        if arg in FLAGS_WITH_VALUE and i + 1 < len(sys.argv):
            comando.extend([arg, sys.argv[i + 1]])
            
    if sistema != "Windows":
        comando.append("--allow-non-empty")

    proceso = subprocess.Popen(comando,env=env, **_subprocess_kwargs())
    _s3_mount_processes.append(proceso)


def desmontar_punto_montaje(mount_point: str) -> None:
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
            print(f"[unmount] Warning checking process: {ex}")

    if proceso_encontrado is not None:
        print(f"[unmount] Sending Ctrl-C to PID {proceso_encontrado.pid} for {mount_point}")
        sistema = platform.system()
        if sistema == "Windows":
            # GenerateConsoleCtrlEvent es el método correcto para WinFSP
            # TerminateProcess (.terminate()) puede dejar la unidad en estado colgado
            try:
                result = subprocess.run([f"taskkill", "/PID", str(proceso_encontrado.pid), "/F" , "/T"], check=True, capture_output=True,
                text=True, **_subprocess_kwargs())
                print(f"[taskkill] Output: {result.stdout}")
                try:
                    proceso_encontrado.wait(timeout=5)
                except Exception:
                    print(f"[unmount] Ctrl-C timeout, forcing kill on PID {proceso_encontrado.pid}")
                    proceso_encontrado.kill()
            except Exception as e:
                print(f"[unmount] GenerateConsoleCtrlEvent failed: {e}, falling back to kill")
                proceso_encontrado.kill()
        else:
            proceso_encontrado.terminate()
            try:
                proceso_encontrado.wait(timeout=3)
            except Exception:
                proceso_encontrado.kill()
    else:
        print(f"[unmount] No active process found for {mount_point}, trying filesystem unmount")

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
        print(f"\n⚠️ Could not unmount {mount_point}: {str(e)}\n")


def resolver_mount_point_destino(perfil_rclone: str, ruta_destino: str) -> str:
    """Calcula la ruta local del mount point para un prefijo S3 dado."""
    mount_base = _get_s3_mount_base()  / perfil_rclone
    prefix_sanitizado = ruta_destino.replace("/", "_")
    return str(mount_base / prefix_sanitizado)


def desmontar_todos_los_mounts_s3() -> None:
    """Mata todos los procesos rclone mount de S3 activos y, si el punto de
    montaje sigue activo tras matar el proceso, fuerza el desmontaje a nivel
    de filesystem. Pensado para dispararse en atexit / señales de cierre
    (SIGTERM, SIGINT) — un cierre abrupto de sesión (DCV/Open OnDemand) no deja
    tiempo para un desmontaje ordenado del propio rclone.
    """
    global _s3_mount_processes
    print(f"[atexit] Terminating {len(_s3_mount_processes)} S3 mount processes...")
    sistema = platform.system()
    for proceso in list(_s3_mount_processes):
        mount_point = None
        try:
            args = proceso.args if hasattr(proceso, "args") else []
            if len(args) > 3:
                mount_point = args[3]
        except Exception:
            pass

        try:
            proceso.terminate()
            proceso.wait(timeout=3)
        except Exception as e:
            print(f"[atexit] Error terminating rclone mount: {e}")
            try:
                proceso.kill()
            except Exception:
                pass

        if mount_point and sistema != "Windows":
            try:
                time.sleep(0.3)
                if os.path.exists(mount_point) and os.path.ismount(mount_point):
                    _force_unmount_path(Path(mount_point))
            except Exception as e:
                print(f"[atexit] Error forcing filesystem unmount of {mount_point}: {e}")

    _s3_mount_processes.clear()
    print("[atexit] All S3 mounts terminated.")
