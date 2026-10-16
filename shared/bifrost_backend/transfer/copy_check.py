"""Ejecución de rclone copy y rclone check."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from sys import platform as sys_platform

from ..common.rclone import _get_user_agent, _subprocess_kwargs, get_rclone_executable
from .s3_tags import construir_tag_string


def ejecutar_rclone_copy(
    origen: str,
    destino_perfil: str,
    destino_path: str,
    rclone_config_path: str,
    metadatos_dict: dict,
    flags_adicionales: list[str],
    log_fn,
    on_success=None,
    on_finish=None,
    expose_proceso: dict | None = None,
) -> None:
    """Lanza rclone copy. Si *expose_proceso* es un dict, guarda el Popen en expose_proceso['proc']."""
    rclone = get_rclone_executable()
    tag_string   = construir_tag_string(metadatos_dict)
    header_value = f"x-amz-tagging:{tag_string}"
    print(f"[copy] tags applied → {tag_string or '(none)'}")

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
        "--user-agent", _get_user_agent(),
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
            print(f"[copy] finished OK → {origen} → {destino_perfil}:/{destino_path} (tags: {tag_string or '(none)'})")
            log_fn("\n✅ Copy completed successfully.\n")
            if on_success:
                on_success()
        else:
            print(f"[copy] FAILED (rc={proceso.returncode}) → {origen} → {destino_perfil}:/{destino_path}")
            log_fn(f"\n❌ Copy error. Code: {proceso.returncode}")
    except Exception as e:
        print(f"[copy] EXCEPTION → {origen} → {destino_perfil}:/{destino_path}: {e}")
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
            "--exclude", "**/.DS_Store",
            "--exclude", "**/*.Thumbs.db",
            "--exclude", ".snapshot/**",
            "--exclude", "**/.snapshot/**",
            "--exclude", ".snapshot/",
            "--exclude", "**/.Trash*/**",
            "--exclude", "**/.cache/**"
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
            carpeta = traducir_a_ruta_local_montada(origen, mounts_activos)
            return carpeta, None
        else:
            ruta_local_path = Path(ruta_local)
            fichero = ruta_local_path.name
            carpeta_remota = f"{remote}:{str(ruta_local_path.parent)}"
            carpeta = traducir_a_ruta_local_montada(
                carpeta_remota, mounts_activos
            )
            return carpeta + f"/{fichero}", fichero
    else:
        if os.path.isfile(origen):
            ruta_local_path = Path(origen)
            fichero = ruta_local_path.name
            return str(ruta_local_path.parent) + f"/{fichero}", fichero
        return origen, None
