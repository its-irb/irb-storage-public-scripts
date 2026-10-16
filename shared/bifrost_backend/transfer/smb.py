"""Shares SMB/CIFS: credenciales, perfiles rclone, montaje y desmontaje."""

from __future__ import annotations

import configparser
import ctypes, ctypes.util
import json
import os
import platform
import requests
import subprocess
import time
from pathlib import Path

from ..common.rclone import _subprocess_kwargs, get_rclone_executable, obtener_ruta_rclone_conf


EXCEPCION_FILERS = ["filer12-svm-vm"]


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
    return os.path.expanduser(f"~/netapp-mount/{usuario_actual}/{nombre_share}")


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
        base_dir = Path.home() / "netapp-mount" / usuario_actual
        if not base_dir.exists():
            return
        for subdir in base_dir.iterdir():
            if subdir.is_dir() and os.path.ismount(subdir):
                try:
                    subprocess.run(["umount", "-f", str(subdir)], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"Error unmounting {subdir}: {e}")
        print("All SMB shares have been unmounted.")


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
