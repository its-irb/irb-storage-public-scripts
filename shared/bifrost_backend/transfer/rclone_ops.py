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


def rclone_list_files_only(perfil_rclone: str, bucket: str, prefix: str) -> list[str]:
    """Lista exclusivamente los archivos de un prefijo usando rclone lsf.
    Se ejecuta bajo demanda para no ralentizar el browser principal.
    """
    import subprocess
    rclone = get_rclone_executable() # Usa tu función existente
    
    # Construimos el path para rclone
    path_rclone = bucket
    if prefix:
        path_rclone = f"{bucket}/{prefix.rstrip('/')}"
        
    target = f"{perfil_rclone}:{path_rclone}"

    try:
        # lsf con --files-only nos devuelve solo los nombres de archivos en este nivel
        result = subprocess.run(
            [rclone, "lsf", target, "--files-only"],
            capture_output=True,
            text=True,
            timeout=15,
            **_subprocess_kwargs(), # Usa tus kwargs existentes
        )
        if result.returncode != 0:
            print(f"[backend] ERROR rclone_list_files_only bucket={bucket!r} prefix={prefix!r}: {result.stderr.strip()}")
            return []

        files = []
        for line in result.stdout.splitlines():
            name = line.strip()
            if name:
                # El frontend espera la clave completa (prefix + nombre)
                if prefix:
                    files.append(f"{prefix.rstrip('/')}/{name}")
                else:
                    files.append(name)
        return files
    except Exception as e:
        print(f"[backend] ERROR rclone_list_files_only bucket={bucket!r} prefix={prefix!r}: {e}")
        return []


def list_prefix_contents(perfil_rclone: str, bucket: str, prefix: str) -> tuple[list[str], list[str]]:
    """Lista únicamente carpetas (prefijos) usando rclone lsd.
    Los ficheros se omiten por rendimiento.

    Returns:
        (folders, files): folders son prefijos terminados en '/',,
                          files siempre estará vacío [].
    """
    path_rclone = bucket
    if prefix:
        path_rclone = f"{bucket}/{prefix.rstrip('/')}"
    try:
        raw_folders = rclone_lsd(perfil=perfil_rclone, path=path_rclone)
        folders = []
        for f in raw_folders:
            if prefix:
                folders.append(f"{prefix.rstrip('/')}/{f}/")
            else:
                folders.append(f"{f}/")
                
    except Exception as e:
        print(f"[backend] ERROR list_prefix_contents bucket={bucket!r} prefix={prefix!r}: {e}")
        folders = []
    return folders, []


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
