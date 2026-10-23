"""Listados y utilidades rclone usados solo por bifrost-transfer."""

from __future__ import annotations

import json
import os
import subprocess

from ..common.rclone import _subprocess_kwargs, get_rclone_executable, rclone_lsd


def rclone_lsjson(perfil: str, path: str = "", timeout: int = 15) -> list[dict]:
    """
    Lista carpetas y ficheros (un nivel) de un path en un perfil rclone, vía JSON.

    Args:
        perfil: nombre del perfil rclone (ej. "sftp-src-abc123")
        path:   path dentro del perfil. "" = raíz

    Returns:
        Lista de dicts {"name": str, "is_dir": bool}, carpetas primero,
        luego alfabético case-insensitive dentro de cada grupo.

    Raises:
        RuntimeError: si rclone lsjson falla.
    """
    rclone = get_rclone_executable()
    target = f"{perfil}:{path}" if path else f"{perfil}:"

    result = subprocess.run(
        [rclone, "lsjson", target],
        capture_output=True,
        text=True,
        timeout=timeout,
        **_subprocess_kwargs(),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"rclone lsjson failed (code {result.returncode})")

    entradas = json.loads(result.stdout or "[]")
    items = [{"name": e["Name"], "is_dir": bool(e.get("IsDir"))} for e in entradas]
    return sorted(items, key=lambda i: (not i["is_dir"], i["name"].lower()))


def rclone_list_files_only(perfil_rclone: str, bucket: str, prefix: str, timeout: int = 15) -> list[str]:
    """Claves de los ficheros de un prefijo, sin subcarpetas (rclone lsf). Se llama bajo demanda para no
    ralentizar el navegador.

    Raises:
        RuntimeError: si rclone lsf falla.
    """
    base = prefix.rstrip("/")
    target = f"{perfil_rclone}:{bucket}/{base}" if base else f"{perfil_rclone}:{bucket}"
    result = subprocess.run(
        [get_rclone_executable(), "lsf", target, "--files-only"],
        capture_output=True,
        text=True,
        timeout=timeout,
        **_subprocess_kwargs(),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"rclone lsf failed (code {result.returncode})")
    names = (line.strip() for line in result.stdout.splitlines())
    return [f"{base}/{name}" if base else name for name in names if name]


def list_prefix_folders(perfil_rclone: str, bucket: str, prefix: str) -> list[str]:
    """Subcarpetas de un prefijo, como prefijos terminados en '/' (rclone lsd). Los ficheros se listan aparte y
    bajo demanda (rclone_list_files_only), por rendimiento.

    Raises:
        RuntimeError: si rclone lsd falla.
    """
    base = prefix.rstrip("/")
    folders = rclone_lsd(perfil=perfil_rclone, path=f"{bucket}/{base}" if base else bucket)
    return [f"{base}/{name}/" if base else f"{name}/" for name in folders]


def obtener_num_cpus() -> int:
    """Obtiene el número de CPUs disponibles. Prioriza SLURM_CPUS_PER_TASK."""
    cpus = os.environ.get("SLURM_CPUS_PER_TASK")
    if cpus:
        try:
            return int(cpus)
        except ValueError:
            pass
    return os.cpu_count() or 1


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
