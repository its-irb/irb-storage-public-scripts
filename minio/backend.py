from __future__ import annotations

"""
IRB MinIO Rclone Data Transfer Tool — BACKEND
==============================================

Contiene toda la lógica de negocio sin dependencias de GUI (tkinter).

Módulos cubiertos:
- Utilidades del sistema (CPUs, rutas)
- Autenticación y grupos LDAP
- Gestión de shares SMB/CIFS
- Perfiles rclone (lectura, creación, actualización)
- Montaje/desmontaje de shares
- Ejecución de comandos rclone (copy, check)
"""

import os
import re
import sys
import json
import time
import shlex
import atexit
import getpass
import platform
import subprocess
import configparser
import threading
import urllib.parse
from pathlib import Path
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from ldap3 import Server, Connection, SUBTREE, SIMPLE
import requests
import urllib3

import minio_functions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# CONFIGURACIÓN Y UTILIDADES DEL SISTEMA
# ============================================================================

def obtener_num_cpus() -> int:
    """
    Obtiene el número de CPUs disponibles.
    Prioriza SLURM_CPUS_PER_TASK (entorno HPC) sobre os.cpu_count().
    """
    cpus = os.environ.get("SLURM_CPUS_PER_TASK")
    if cpus:
        try:
            return int(cpus)
        except ValueError:
            pass
    return os.cpu_count() or 1


def obtener_ruta_rclone_conf() -> Path:
    """
    Ejecuta `rclone config file` y devuelve la ruta absoluta al rclone.conf activo.
    """
    out = subprocess.check_output(
        ["rclone", "config", "file"],
        text=True,
        stderr=subprocess.STDOUT,
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
    """
    Convierte una ruta local a formato rclone remote:/ruta.

    Args:
        ruta_local: Ruta absoluta en el sistema de archivos local.
        mounts_activos: Lista de dicts con keys mount_path, remote_name, remote_subpath.

    Returns:
        Ruta en formato rclone o ruta_local si no pertenece a ningún mount.
    """
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


# ============================================================================
# AUTENTICACIÓN Y GESTIÓN DE USUARIOS LDAP
# ============================================================================

LDAP_SERVER_URL = "ldap://irbldap3.sc.irbbarcelona.org"
LDAP_BASE_DN = "o=irbbarcelona"


def get_ldap_groups(usuario: str) -> list[str]:
    """
    Obtiene los grupos LDAP a los que pertenece un usuario.

    Returns:
        Lista de nombres de grupos (solo CN, no DN completo).
    """
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


def validar_credenciales_ldap(credenciales_ldap: dict | None) -> bool:
    """
    Valida credenciales LDAP mediante un bind autenticado.

    Args:
        credenciales_ldap: {"usuario": str, "password": str}

    Returns:
        True si las credenciales son válidas.
    """
    if not credenciales_ldap:
        return False

    usuario = credenciales_ldap["usuario"]
    password = credenciales_ldap["password"]

    server = Server(LDAP_SERVER_URL)
    try:
        conn = Connection(server, auto_bind=True)
        conn.search(LDAP_BASE_DN, f"(cn={usuario})", SUBTREE, attributes=["dn"])
        if not conn.entries:
            return False
        user_dn = conn.entries[0].entry_dn
        conn_auth = Connection(
            server, user=user_dn, password=password, authentication=SIMPLE
        )
        if conn_auth.bind():
            conn_auth.unbind()
            conn.unbind()
            return True
        return False
    except Exception as e:
        print(f"LDAP validation error: {e}")
        return False


def construir_credenciales_smb(
    credenciales_ldap: dict,
    usar_privilegios_its: bool,
    credenciales_admin: dict | None = None,
) -> dict:
    """
    Construye las credenciales SMB finales según el modo de operación.

    Returns:
        {"usuario": str, "password": str}
    """
    if usar_privilegios_its:
        if (
            not credenciales_admin
            or not credenciales_admin["usuario"]
            or not credenciales_admin["password"]
        ):
            raise ValueError(
                "Missing admin credentials to construct SMB credentials with ITS privileges."
            )
        return {
            "usuario": credenciales_admin["usuario"],
            "password": credenciales_admin["password"],
        }
    return {
        "usuario": credenciales_ldap["usuario"],
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
    """
    Obtiene la lista de shares SMB/CIFS accesibles para el usuario.

    Returns:
        Lista de dicts {"name", "path", "host"}.
    """
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
    """
    Lee el rclone.conf y devuelve los nombres de los perfiles configurados.
    """
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
    """
    Crea (o reemplaza) un perfil SMB en rclone.conf.
    """
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    config.read(config_path)

    if nombre_perfil in config:
        config.remove_section(nombre_perfil)

    config[nombre_perfil] = {
        "type": "smb",
        "domain": "IRBBARCELONA",
        "host": host,
        "user": username,
        "pass": subprocess.getoutput(f"rclone obscure {password}"),
    }

    with open(config_path, "w") as f:
        config.write(f)


def actualizar_password_perfiles_rclone(
    usuario: str,
    nueva_password: str,
    rclone_config_path: str | None = None,
) -> None:
    """
    Actualiza la contraseña de todos los perfiles SMB del usuario
    (patrón: {usuario}-smbmount-*).
    """
    print(f"Actualizando contraseña para perfiles rclone tipo '{usuario}-smbmount-*'...")
    if not rclone_config_path:
        rclone_config_path = obtener_ruta_rclone_conf()

    config = configparser.ConfigParser()
    config.read(rclone_config_path)

    try:
        resultado = subprocess.run(
            ["rclone", "obscure", nueva_password],
            capture_output=True, text=True, check=True,
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
    """
    Genera el punto de montaje según el SO:
    - Windows: letra de unidad
    - Linux/macOS: ~/cifs-mount/{usuario}/{share}
    """
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
    """
    Monta un share SMB con rclone (modo lectura, sin cache VFS).

    Returns:
        True si el montaje fue exitoso, False en caso contrario.
    """
    rclone_config_path = obtener_ruta_rclone_conf()
    sistema = platform.system()

    if sistema != "Windows":
        os.makedirs(punto_montaje, exist_ok=True)

    if os.path.ismount(punto_montaje):
        return True  # ya montado

    comando = [
        "rclone", "mount",
        f"{nombre_perfil}:/{share_path}", str(punto_montaje),
        "--vfs-cache-mode", "off",
        "--read-only",
        "--config", str(rclone_config_path),
    ]
    if sistema == "Windows":
        comando.extend(["--volname", nombre_perfil])

    mounts_activos.append({
        "mount_path": str(punto_montaje),
        "remote_name": nombre_perfil,
        "remote_subpath": share_path,
    })

    print(f"Montando {comando}...")
    try:
        proceso = subprocess.Popen(
            comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
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
    """
    Desmonta todos los shares SMB del usuario (llamado en atexit).
    """
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
    """
    Desmonta un punto de montaje concreto (usado al cerrar la ventana de copia).

    Args:
        mount_point: Ruta del directorio montado.
        log_fn: Función opcional para emitir mensajes (ej. log_queue.put).
    """
    def _log(msg):
        print(msg)
        if log_fn:
            log_fn(msg)

    if not os.path.isdir(mount_point) or not os.path.ismount(mount_point):
        return

    try:
        sistema = platform.system()
        if sistema == "Linux":
            subprocess.run(["fusermount", "-u", mount_point], check=True)
        elif sistema == "Darwin":
            subprocess.run(["umount", mount_point], check=True)
        elif sistema == "Windows":
            subprocess.run(
                ["taskkill", "/F", "/FI", f"WINDOWTITLE eq {mount_point}*"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception as e:
        _log(f"\n⚠️ Could not unmount {mount_point}: {str(e)}\n")


def resolver_mount_point_destino(perfil_rclone: str, ruta_destino: str) -> str:
    """
    Calcula la ruta local del mount point para un prefijo S3 dado.
    """
    mount_base = Path.home() / "rclone-mounts" / perfil_rclone
    prefix_sanitizado = ruta_destino.replace("/", "_")
    return str(mount_base / prefix_sanitizado)


# ============================================================================
# OPERACIONES RCLONE (COPY / CHECK)
# ============================================================================

def construir_tag_string(metadatos_dict: dict) -> str:
    """
    Convierte el diccionario de metadatos en una cadena x-amz-tagging URL-encoded.
    """
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
) -> None:
    """
    Lanza rclone copy en un hilo separado.

    Args:
        origen: Ruta de origen (local o rclone remote).
        destino_perfil: Nombre del perfil rclone S3.
        destino_path: Ruta dentro del bucket.
        rclone_config_path: Ruta al rclone.conf.
        metadatos_dict: Dict con metadatos a adjuntar como tags S3.
        flags_adicionales: Lista de flags extra para rclone.
        num_cores: Número de cores disponibles.
        log_fn: Función callable para emitir líneas de log.
        on_success: Callback sin argumentos llamado si returncode == 0.
        on_finish: Callback sin argumentos llamado siempre al terminar.
    """
    tag_string = construir_tag_string(metadatos_dict)
    header_value = f"x-amz-tagging:{tag_string}"

    comando = [
        "rclone", "copy",
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

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
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
        if on_finish:
            on_finish()


def es_directorio_rclone(ruta_rclone: str, config_path: str) -> bool:
    """Devuelve True si la ruta rclone apunta a un directorio."""
    try:
        resultado = subprocess.run(
            ["rclone", "lsjson", ruta_rclone, "--config", config_path],
            capture_output=True, check=True, text=True,
        )
        salida = json.loads(resultado.stdout)
        if not salida:
            return False
        if len(salida) > 1:
            return True
        return salida[0].get("IsDir", False)
    except subprocess.CalledProcessError:
        return False


def traducir_a_ruta_local_montada(
    origen: str,
    mounts_activos: list,
    config_path: str,
) -> str:
    """
    Si 'origen' es un remote rclone con mount activo, devuelve la ruta local equivalente.
    """
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
    """
    Analiza el origen y lo normaliza para rclone check.

    Returns:
        (origen_ajustado, fichero_o_None)
        - Si es un fichero, fichero_o_None = nombre del fichero.
        - Si es directorio, fichero_o_None = None.
    """
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
) -> None:
    """
    Lanza rclone check en un hilo separado.

    Args:
        origen: Ruta origen (local o remote rclone).
        destino_perfil: Perfil rclone S3.
        destino_path: Ruta dentro del bucket.
        rclone_config_path: Ruta al rclone.conf.
        flags_adicionales: Flags extra para rclone.
        mounts_activos: Montajes activos (para traducción de rutas).
        log_fn: Callable para emitir líneas de log.
        on_finish: Callback llamado siempre al terminar.
    """
    origen_ajustado, fichero = preparar_origen_para_check(
        origen, mounts_activos, rclone_config_path
    )

    combined_path = Path.home() / "rclone-combined-check.txt"
    combined_path.parent.mkdir(parents=True, exist_ok=True)

    comando = [
        "rclone", "check",
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

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        for linea in proceso.stdout:
            log_fn(linea)
        proceso.wait()
        if proceso.returncode == 0:
            log_fn("\n✅ Verification OK: no differences found.\n")
        else:
            log_fn(
                f"\n⚠️ Verification finished with code {proceso.returncode}. "
                "Check for possible differences."
            )
    except Exception as e:
        log_fn(f"\n❌ Exception during verification: {str(e)}")
    finally:
        if on_finish:
            on_finish()


def verificar_ruta_rclone_accesible(perfil: str, ruta: str, timeout: int = 5) -> bool:
    """
    Comprueba si una ruta en un perfil rclone es accesible.

    Returns:
        True si rclone ls devuelve returncode 0.
    """
    if not ruta:
        return False
    try:
        result = subprocess.run(
            ["rclone", "ls", f"{perfil}:{ruta}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


# ============================================================================
# LÓGICA DE INICIALIZACIÓN (orquestación del flujo main)
# ============================================================================

def configurar_perfiles_smb_si_faltan(
    shares_accesibles: list,
    credenciales_smb: dict,
    perfiles_configurados: list,
) -> list:
    """
    Crea los perfiles rclone SMB que falten y devuelve la lista actualizada.
    """
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
    """
    Monta los shares seleccionados y devuelve lista de los que fallaron.
    """
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


def construir_recursos_cifs_dict(
    shares: list,
    usuario_actual: str,
) -> dict:
    """
    Construye el diccionario de recursos CIFS con sus datos de montaje.

    Returns:
        {nombre_share: {"nombre_perfil", "punto_montaje", "remote_path", "remote_host"}}
    """
    resultado = {}
    for share in shares:
        nombre_share = share["name"]
        remote_host = share["host"]
        resultado[nombre_share] = {
            "nombre_perfil": f"{usuario_actual}-smbmount-{remote_host}",
            "punto_montaje": generar_punto_montaje(usuario_actual, nombre_share),
            "remote_path": nombre_share,
            "remote_host": remote_host,
        }
    return resultado
