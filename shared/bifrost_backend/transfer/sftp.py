"""Perfiles rclone SFTP y validación de conexión."""

from __future__ import annotations

import configparser
import subprocess
import uuid

from ..common.rclone import _subprocess_kwargs, get_rclone_executable, obtener_ruta_rclone_conf, rclone_lsd


def crear_perfil_rclone_sftp(
    nombre_perfil: str,
    host: str,
    port: str,
    username: str,
    password: str,
) -> None:
    """Crea (o reemplaza) un perfil SFTP temporal en rclone.conf."""
    rclone = get_rclone_executable()
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
    config[nombre_perfil] = {
        "type": "sftp",
        "host": host,
        "port": port,
        "user": username,
        "pass": subprocess.check_output(
            [rclone, "obscure", password],
            text=True,
            **_subprocess_kwargs(),
        ).strip(),
    }
    with open(config_path, "w") as f:
        config.write(f)


def eliminar_perfil_rclone(
    nombre_perfil: str,
    rclone_config_path: str | None = None,
) -> None:
    """Borra una sección de rclone.conf si existe."""
    config_path = rclone_config_path or obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
        with open(config_path, "w") as f:
            config.write(f)


def limpiar_perfiles_rclone_con_prefijo(
    prefijo: str,
    rclone_config_path: str | None = None,
) -> None:
    """Borra todas las secciones cuyo nombre empiece por *prefijo* (barrido de huérfanos)."""
    config_path = rclone_config_path or obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    for nombre in [s for s in config.sections() if s.startswith(prefijo)]:
        eliminar_perfil_rclone(nombre, config_path)


def generar_nombre_perfil_sftp() -> str:
    """Genera un nombre de perfil rclone único para una conexión SFTP efímera."""
    return f"sftp-src-{uuid.uuid4().hex[:8]}"


def validar_conexion_sftp(nombre_perfil: str, timeout: int = 15) -> tuple[bool, str | None]:
    """
    Valida que el perfil SFTP recién creado conecta correctamente, listando la raíz.

    Returns:
        (True, None) si conecta.
        (False, motivo) si falla — motivo ∈ {"unreachable", "auth", "timeout", "other"}.
    """
    try:
        rclone_lsd(nombre_perfil, "", timeout=timeout)
        return True, None
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except RuntimeError as e:
        mensaje = str(e).lower()
        if "auth" in mensaje or "permission denied" in mensaje:
            return False, "auth"
        if (
            "no such host" in mensaje
            or "connection refused" in mensaje
            or "i/o timeout" in mensaje
            or "network is unreachable" in mensaje
        ):
            return False, "unreachable"
        return False, "other"
