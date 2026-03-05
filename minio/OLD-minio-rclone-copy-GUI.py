from __future__ import annotations

"""
IRB MinIO Rclone Data Transfer Tool
====================================

Sistema integral para transferencia de datos entre recursos SMB/CIFS y MinIO S3.

ARQUITECTURA DEL SISTEMA:
------------------------
1. Autenticación LDAP del usuario IRB
2. Descubrimiento automático de shares SMB/CIFS accesibles
3. Montaje de recursos CIFS usando rclone
4. Configuración de credenciales temporales MinIO S3 (STS)
5. Interfaz gráfica para transferencia y verificación de datos

FLUJO PRINCIPAL:
---------------
main() → autenticación LDAP → obtener shares → montar CIFS → configurar S3 → GUI transferencia

DEPENDENCIAS:
------------
- rclone: Herramienta de sincronización de archivos en la nube
- ldap3: Cliente LDAP para Python
- tkinter: GUI nativa de Python
- boto3: SDK de AWS (para gestión de credenciales)
"""

import os
import sys
import re
import time
import json
import shlex
import atexit
import getpass
import platform
import threading
import subprocess
import configparser
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
import urllib.parse

# GUI imports
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import queue

# AWS/MinIO imports
import boto3
from botocore.exceptions import ClientError

# LDAP imports
from ldap3 import Server, Connection, SUBTREE, SIMPLE

# Network imports
import requests
import urllib3

# Módulo local con funciones específicas de MinIO
import minio_functions

# Desactivar warnings SSL (entorno corporativo con certificados internos)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# CONFIGURACIÓN Y UTILIDADES DEL SISTEMA
# ============================================================================

def obtener_num_cpus():
    """
    Obtiene el número de CPUs disponibles.
    Prioriza SLURM_CPUS_PER_TASK (entorno HPC) sobre os.cpu_count().
    
    Returns:
        int: Número de CPUs disponibles (mínimo 1)
    """
    cpus = os.environ.get("SLURM_CPUS_PER_TASK")
    if cpus:
        try:
            return int(cpus)
        except ValueError:
            pass  # fallback si hay valor corrupto

    return os.cpu_count() or 1  # fallback mínimo seguro

def traducir_ruta_a_remote(ruta_local, mounts_activos):
    """
    Convierte una ruta local a formato rclone remote:/ruta.
    
    Útil cuando el usuario selecciona un archivo del explorador y necesitamos
    traducirlo al remote correspondiente para comandos rclone.
    
    Args:
        ruta_local (str): Ruta absoluta en el sistema de archivos local
        mounts_activos (list): Lista de diccionarios con información de montajes
                               [{mount_path, remote_name, remote_subpath}, ...]
    
    Returns:
        str: Ruta en formato rclone (remote:/subpath) o ruta_local si no pertenece a ningún mount
    
    Ejemplo:
        ruta_local = "/home/user/cifs-mount/myuser/project/data.txt"
        mount = {
            "mount_path": "/home/user/cifs-mount/myuser",
            "remote_name": "myuser-smbmount-filer1",
            "remote_subpath": "project"
        }
        → Resultado: "myuser-smbmount-filer1:project/data.txt
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

def get_ldap_groups(usuario):
    """
    Obtiene los grupos LDAP a los que pertenece un usuario.
    
    Se usa para:
    1. Determinar privilegios (ej: grupo 'its' = administrador)
    2. Filtrar shares SMB accesibles según permisos de grupo
    
    Args:
        usuario (str): Username del usuario IRB
    
    Returns:
        list: Lista de nombres de grupos LDAP (solo CN, no DN completo)
    
    Ejemplo:
        get_ldap_groups("jdoe") → ["its", "bioinformatics", "all-users"]
    """
    LDAP_SERVER = "ldap://irbldap3.sc.irbbarcelona.org"
    BASE_DN = "o=irbbarcelona"
    ATTRS = ["groupMembership"]

    # Conexión anónima
    server = Server(LDAP_SERVER)
    conn = Connection(server, auto_bind=True)

    # Búsqueda del usuario
    filtro = f"(uid={usuario})"

    conn.search(search_base=BASE_DN,
                search_filter=filtro,
                search_scope=SUBTREE,
                attributes=ATTRS)

    cn_grupos = []
    for entrada in conn.entries:
        for dn in entrada.groupMembership.values:
            partes = dn.split(",")
            cn = next((p.split("=")[1] for p in partes if p.lower().startswith("cn=")), None)
            if cn:
                cn_grupos.append(cn)

    return cn_grupos

def validar_credenciales_ldap(credenciales_ldap):
    """
    Valida credenciales LDAP mediante un bind autenticado.
    
    Proceso:
    1. Búsqueda anónima del usuario para obtener su DN
    2. Intento de bind con el DN + password
    3. Éxito = credenciales válidas
    
    Args:
        credenciales_ldap (dict): {"usuario": str, "password": str}
    
    Returns:
        bool: True si las credenciales son válidas
    """

    if not credenciales_ldap:
        return False

    usuario_ldap = credenciales_ldap["usuario"]
    password_ldap = credenciales_ldap["password"]

    server = Server("ldap://irbldap3.sc.irbbarcelona.org")
    base_dn = "o=irbbarcelona"
    search_filter = f"(cn={usuario_ldap})"

    try:
        conn = Connection(server, auto_bind=True)
        conn.search(base_dn, search_filter, SUBTREE, attributes=['dn'])

        if not conn.entries:
            return False

        user_dn = conn.entries[0].entry_dn
        conn_auth = Connection(server, user=user_dn, password=password_ldap, authentication=SIMPLE)

        if conn_auth.bind():
            conn_auth.unbind()
            conn.unbind()
            return True
        else:
            return False

    except Exception as e:
        print(f"LDAP validation error: {e}")
        return False
    
# ============================================================================
# GESTIÓN DE SHARES SMB/CIFS
# ============================================================================

def obtener_shares_accesibles(grupos_usuario: list[str], username, password, usuario_actual, excepcion_filers: list[str], usar_privilegios: bool = False) -> list[dict]:
    """
    Obtiene la lista de shares SMB/CIFS a los que el usuario tiene acceso.
    
    Consulta la API de NetApp a través de un proxy interno y filtra los shares
    según los grupos LDAP del usuario y las ACLs configuradas.
    
    Args:
        grupos_usuario (list): Grupos LDAP del usuario
        username (str): Username para autenticación en la API
        password (str): Password para autenticación en la API
        usuario_actual (str): Username actual (para matching en ACLs)
        excepcion_filers (list): Filers a excluir (ej: ["filer12-svm-vm"])
        usar_privilegios (bool): Si True, incluye también shares con acceso a Domain Admins
    
    Returns:
        list: Lista de diccionarios con información de shares accesibles
              [{"name": str, "path": str, "host": str}, ...]
    
    Proceso de filtrado:
    1. Normalizar ACL principal (quitar prefijos LDAP, dominios, etc.)
    2. Comparar con username o grupos del usuario
    3. Incluir shares con acceso "Everyone" (acceso universal)
    4. Si usar_privilegios=True, incluir shares con acceso a Domain Admins
    5. Excluir filers especificados
    """

    # URL del servidor intermedio que ya hace de proxy con NetApp
    URL = "https://netapp-api-proxy.sc.irbbarcelona.org/get-shares"

    try:
        headers = {"Content-Type": "application/json"}
        payload = {
            "username": username,
            "password": password
        }

        respuesta = requests.post(URL, headers=headers, json=payload, verify=False)
        respuesta.raise_for_status()

        # Forzar carga JSON si se devuelve como string serializado
        raw = respuesta.json()
        if isinstance(raw, str):
            data = json.loads(raw)
        else:
            data = raw


    except Exception as e:
        print(f"Error getting shares from proxy: {e}")
        return []

    grupos_set = {g.strip().lower() for g in grupos_usuario}

    def normalizar_acl(principal: str) -> str:
        """
        Normaliza el formato de un principal de ACL.
        
        Formatos soportados:
        - "cn=username,ou=..." → "username"
        - "DOMAIN\\username" → "username"
        - "username@domain.com" → "username"
        """
        s = (principal or "").strip().lower()

        if s.startswith("cn="):
            return s.split(",", 1)[0].removeprefix("cn=").strip()
        if "\\" in s:
            return s.split("\\", 1)[1].strip()
        if "@" in s:
            return s.split("@", 1)[0].strip()
        return s

    # Filtrar shares según permisos
    resultado = []
    for share in data.get("records", []):
        # Excluir filers específicos
        if share["svm"]["name"] not in excepcion_filers:
            # Verificar ACLs del share
            for acl in share.get("acls", []):
                user_or_group = acl.get("user_or_group", "")
                user_or_group_lower = user_or_group.strip().lower()
                pnorm = normalizar_acl(user_or_group)

                # Usuario tiene acceso si su username o alguno de sus grupos coincide
                tiene_acceso = pnorm == usuario_actual.lower() or pnorm in grupos_set
                
                # Incluir shares con acceso "Everyone" (acceso universal)
                # if user_or_group_lower == "everyone":
                #     tiene_acceso = True
                
                # Si usa privilegios de admin, también incluir shares con acceso a Domain Admins
                if usar_privilegios and "domain admins" in user_or_group_lower:
                    tiene_acceso = True
                
                if tiene_acceso:
                    resultado.append({
                        "name": share["name"],
                        "path": share["path"],
                        "host": (share["svm"]["name"]).replace("-svm", "") + ".sc.irbbarcelona.org"  # <--- Aquí añadimos el host (NetApp)
                    })
                    break   # Ya encontramos permiso, no revisar más ACLs

    return resultado

def obtener_perfiles_rclone_config(config_path=None):
    """
    Lee el archivo de configuración de rclone y devuelve los perfiles configurados.
    
    Args:
        config_path (str): Ruta al rclone.conf (None = ruta por defecto)
    
    Returns:
        list: Nombres de secciones/perfiles configurados
    
    Ejemplo de rclone.conf:
        [minio-irb]
        type = s3
        ...
        
        [user-smbmount-filer1]
        type = smb
        ...
    
    → Devuelve: ["minio-irb", "user-smbmount-filer1"]
    """
    # if config_path is None:
    #     config_path = os.path.expanduser("~/.config/rclone/rclone.conf")

    config_path = obtener_ruta_rclone_conf()
    print(f"Using rclone config path: {config_path}")

    if not os.path.exists(config_path):
        return []

    config = configparser.ConfigParser()
    config.read(config_path)

    return config.sections()

def actualizar_password_perfiles_rclone(usuario: str, nueva_password: str, rclone_config_path: str = None):
    """
    Actualiza la contraseña de todos los perfiles SMB del usuario.
    
    Usa 'rclone obscure' para encriptar la password antes de guardarla.
    
    Args:
        usuario (str): Username (para identificar perfiles usuario-smbmount-*)
        nueva_password (str): Nueva contraseña en texto plano
        rclone_config_path (str): Ruta al config (None = por defecto)
    
    Perfiles actualizados: {usuario}-smbmount-* con type=smb
    """
    print(f"Actualizando contraseña para perfiles rclone tipo '{usuario}-smbmount-*'...")
    if not rclone_config_path:
        rclone_config_path = os.path.expanduser("~/.config/rclone/rclone.conf")

    config = configparser.ConfigParser()
    config.read(rclone_config_path)

    # Obscurecer la contraseña
    try:
        resultado = subprocess.run(
            ["rclone", "obscure", nueva_password],
            capture_output=True, text=True, check=True
        )
        password_obscurecida = resultado.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"❌ Error obscuring password: {e.stderr}")
        return

    actualizado = False

    for section in config.sections():
        if section.startswith(f"{usuario}-smbmount-") and config[section].get("type") == "smb":
            config[section]["pass"] = password_obscurecida
            actualizado = True

    if actualizado:
        with open(rclone_config_path, "w") as f:
            config.write(f)
        print(f"🔐 Password updated successfully for all SMB profiles of '{usuario}'")
    else:
        print(f"⚠️ No profiles of type '{usuario}-smbmount-*' found in rclone.conf")

def crear_perfil_rclone_smb(nombre_perfil,host, path, username, password):
    """
    Crea un nuevo perfil SMB en rclone.conf.
    
    Args:
        nombre_perfil (str): Nombre del perfil (ej: "user-smbmount-filer1")
        host (str): Hostname del servidor SMB
        path (str): No usado actualmente (compartibilidad futura)
        username (str): Usuario SMB
        password (str): Contraseña SMB (se obscurecerá)
    
    Configuración generada:
        [nombre_perfil]
        type = smb
        domain = IRBBARCELONA
        host = <host>
        user = <username>
        pass = <password_obscurecida>
    """
    config_path = obtener_ruta_rclone_conf()
    print(f"Using rclone config path: {config_path}")
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    config.read(config_path)

    # Eliminar si ya existe
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)

    # Crear nueva sección
    config[nombre_perfil] = {
        "type": "smb",
        "domain": "IRBBARCELONA",
        "host": host,
        "user": username,
        "pass": subprocess.getoutput(f"rclone obscure {password}")#,
        #"share": path
    }

    with open(config_path, "w") as f:
        config.write(f)

def obtener_letra_unidad_disponible():
    """
    Obtiene una letra de unidad disponible en Windows.
    
    Returns:
        str: Letra de unidad disponible (ej: "X:") o None si no hay disponible
    """
    import string
    if platform.system() != "Windows":
        return None
    
    # Letras disponibles para asignar (evitamos A:, B:, C: que son comunes)
    letras_disponibles = [f"{letra}:" for letra in string.ascii_uppercase[3:]]  # D: hasta Z:
    
    # Obtener letras en uso
    try:
        import ctypes
        drives_mask = ctypes.windll.kernel32.GetLogicalDrives()
        letras_en_uso = []
        for i, letra in enumerate(string.ascii_uppercase):
            if drives_mask & (1 << i):
                letras_en_uso.append(f"{letra}:")
        
        # Encontrar primera letra disponible
        for letra in letras_disponibles:
            if letra not in letras_en_uso:
                return letra
    except Exception as e:
        print(f"Error obteniendo letras de unidad: {e}")
    
    return None

def generar_punto_montaje(usuario_actual, nombre_share):
    """
    Genera el punto de montaje apropiado según el sistema operativo.
    
    Args:
        usuario_actual (str): Nombre del usuario
        nombre_share (str): Nombre del share a montar
    
    Returns:
        str: Ruta del punto de montaje (carpeta en Linux/macOS, letra de unidad en Windows)
    """
    sistema = platform.system()
    
    if sistema == "Windows":
        # En Windows usamos letras de unidad
        letra = obtener_letra_unidad_disponible()
        if letra:
            return letra
        else:
            raise Exception("No hay letras de unidad disponibles en Windows")
    else:
        # En Linux/macOS usamos carpetas
        return os.path.expanduser(f"~/cifs-mount/{usuario_actual}/{nombre_share}")

def montar_share_rclone(nombre_perfil, share_path, punto_montaje, mounts_activos):
    """
    Monta un share SMB usando rclone mount en modo lectura.
    
    Args:
        nombre_perfil (str): Nombre del perfil rclone configurado
        share_path (str): Ruta del share remoto
        punto_montaje (str): Directorio local donde montar
        mounts_activos (list): Lista global para tracking (se actualiza)
    
    Configuración del mount:
        - Modo lectura (--read-only)
        - Sin cache VFS (--vfs-cache-mode off)
        - Timeout de 30 segundos para verificar montaje
    
    IMPORTANTE: El proceso de rclone mount queda en background.
    Debe desmontarse con fusermount -u (Linux) o umount (macOS).
    """
    rclone_config_path = obtener_ruta_rclone_conf()
    sistema = platform.system()

    # Crear directorio de montaje si no existe (solo en Linux/macOS)
    if sistema != "Windows":
        os.makedirs(punto_montaje, exist_ok=True)

    # Comprobar si ya está montado
    if os.path.ismount(punto_montaje):
        return  # Ya está montado, no repetir

    comando = [
        "rclone", "mount",
        f"{nombre_perfil}:/{share_path}", str(punto_montaje),
        "--vfs-cache-mode", "off",
        "--read-only",
        # "--allow-other",
        "--config", rclone_config_path
    ]
    
    # En Windows, añadir flag para red de trabajo
    if sistema == "Windows":
        comando.extend(["--volname", nombre_perfil])

    mounts_activos.append({
        "mount_path": str(punto_montaje),
        "remote_name": nombre_perfil,
        "remote_subpath": share_path  
    })

    print(f"Montando {comando}...")

    try:
        # Lanzar rclone como proceso en segundo plano (no bloqueante)
        proceso = subprocess.Popen(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Esperar unos segundos para comprobar si el montaje se ha completado
        for _ in range(30):
            time.sleep(1)
            if os.path.ismount(punto_montaje):
                return  # Montaje correcto

        # Si no se montó tras el timeout, terminar el proceso
        proceso.terminate()
        messagebox.showerror("Error mounting SMB resource", f"Could not mount {nombre_perfil} on {punto_montaje} after 30 seconds.")
    except Exception as e:
        messagebox.showerror("Error mounting SMB resource", f"Exception: {str(e)}")

def desmontar_todos_los_shares(usuario_actual):
    """
    Desmonta todos los shares SMB del usuario.
    
    Se ejecuta automáticamente al salir de la aplicación (atexit).
    
    Args:
        usuario_actual (str): Username (determina el directorio base de montajes)
    
    Directorio base: ~/cifs-mount/{usuario}/ (Linux/macOS) o letras de unidad (Windows)
    """
    sistema = platform.system()
    
    if sistema == "Windows":
        # En Windows, desmontar todas las unidades montadas con rclone
        # Obtener lista de procesos rclone y matarlos
        try:
            subprocess.run(["taskkill", "/F", "/IM", "rclone.exe"], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL)
            print("All SMB shares have been unmounted.")
        except Exception as e:
            print(f"Error unmounting in Windows: {e}")
    else:
        # Linux/macOS: desmontar usando umount
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

def obtener_ruta_rclone_conf() -> Path:
    """
    Ejecuta `rclone config file`, limpia la salida (Windows/macOS/Linux) y devuelve
    la ruta ABSOLUTA al fichero rclone.conf que rclone está usando.

    Asume que `rclone` está en el PATH.
    """
    out = subprocess.check_output(
        ["rclone", "config", "file"],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()

    # Divide en líneas no vacías y recorre de atrás hacia delante
    lines = [l.strip().strip('"').strip("'") for l in out.splitlines() if l.strip()]

    # 1) Lo más fiable: una línea que termine en .conf
    for l in reversed(lines):
        if l.lower().endswith(".conf"):
            return Path(l).expanduser().resolve()

    # 2) Si no aparece .conf: intenta extraer una ruta absoluta (Windows o POSIX)
    candidates = []
    for l in lines:
        # Windows: C:\...
        if re.search(r"[A-Za-z]:\\", l):
            candidates.append(l[l.find(re.search(r"[A-Za-z]:\\", l).group(0)) :])
        # POSIX: /...
        if "/" in l:
            m = re.search(r"(/[^ \t\r\n]+)", l)
            if m:
                candidates.append(m.group(1))

    for c in reversed(candidates):
        c = c.strip().strip('"').strip("'")
        p = Path(c)
        # Si parece directorio, asume rclone.conf dentro
        if p.suffix.lower() != ".conf":
            p = p / "rclone.conf"
        return p.expanduser().resolve()

    raise RuntimeError(f"No pude extraer la ruta del config. Salida de `rclone config file`: {out!r}")


# ============================================================================
# INTERFACES GRÁFICAS (DIÁLOGOS)
# ============================================================================

def pedir_credenciales(root, titulo, pregunta, usuario_prefijado=None):
    """
    Diálogo genérico para solicitar credenciales.
    
    Args:
        root: Ventana padre de Tkinter
        titulo (str): Título de la ventana
        pregunta (str): Texto de la pregunta
        usuario_prefijado (str): Si se proporciona, el campo usuario está bloqueado
    
    Returns:
        dict: {"usuario": str, "password": str} o None si se cancela
    
    Funcionalidad:
        - Enter = Confirmar
        - Escape = Cancelar
        - Usuario bloqueado si se proporciona usuario_prefijado
    """
    resultado = {"usuario": None, "password": None}

    ventana = tk.Toplevel(root)
    ventana.title(titulo)
    ventana.geometry("350x180")
    ventana.transient(root)
    ventana.grab_set()

    tk.Label(ventana, text=pregunta).pack(pady=(10, 5))

    tk.Label(ventana, text="Username:").pack()
    usuario_var = tk.StringVar(value=usuario_prefijado if usuario_prefijado else "")
    entry_user = ttk.Entry(ventana, textvariable=usuario_var)
    entry_user.pack(pady=(0, 5))

    if usuario_prefijado:
        entry_user.configure(state="disabled")

    tk.Label(ventana, text="Password:").pack()
    password_var = tk.StringVar()
    entry_pass = ttk.Entry(ventana, textvariable=password_var, show="*")
    entry_pass.pack(pady=(0, 10))
    entry_pass.focus_set()

    def confirmar():
        usuario = usuario_var.get().strip()
        password = password_var.get().strip()
        if not usuario or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return
        resultado["usuario"] = usuario
        resultado["password"] = password
        ventana.destroy()

    def cancelar():
        ventana.destroy()

    ventana.bind("<Return>", lambda e: confirmar())
    ventana.bind("<Escape>", lambda e: cancelar())

    frame_botones = ttk.Frame(ventana)
    frame_botones.pack(pady=(0, 10))
    ttk.Button(frame_botones, text="Cancel", command=cancelar).pack(side=tk.LEFT, padx=10)
    ttk.Button(frame_botones, text="OK", command=confirmar).pack(side=tk.RIGHT, padx=10)

    ventana.wait_window()
    return resultado if resultado["usuario"] and resultado["password"] else None

def construir_credenciales_smb(credenciales_ldap, usar_privilegios_its, credenciales_admin=None):
    """
    Construye las credenciales SMB finales según el modo de operación.
    
    Args:
        credenciales_ldap (dict): Credenciales LDAP del usuario
        usar_privilegios_its (bool): Si usar cuenta admin (admin_username)
        credenciales_admin (dict): Credenciales de admin si usar_privilegios_its=True
    
    Returns:
        dict: {"usuario": str, "password": str}
    
    Modos:
        - Privilegios ITS: Usa admin_{username} con password diferente
        - Usuario normal: Usa credenciales LDAP directamente
    """
    if usar_privilegios_its:
        if not credenciales_admin or not credenciales_admin["usuario"] or not credenciales_admin["password"]:
            raise ValueError("Missing admin credentials to construct SMB credentials with ITS privileges.")
        return {
            "usuario": credenciales_admin["usuario"],
            "password": credenciales_admin["password"]
        }
    else:
        return {
            "usuario": credenciales_ldap["usuario"],
            "password": credenciales_ldap["password"]
        }

def seleccionar_shares_montar(root, shares, usuario_actual, mounts_activos, es_admin_its=False):
    """
    Diálogo para seleccionar qué shares CIFS montar.
    
    Args:
        root: Ventana padre
        shares (list): Lista de shares disponibles
        usuario_actual (str): Username actual
        mounts_activos (list): Lista global de montajes (se actualiza)
        es_admin_its (bool): Si el usuario tiene privilegios de admin
    
    Funcionalidad:
        - Checkboxes para cada share disponible
        - Distribución en columnas (hasta 4 columnas, 15 filas por columna)
        - Botón "Update SMB credentials" para renovar passwords
        - Monta los shares seleccionados al confirmar
    
    IMPORTANTE: Esta función modifica mounts_activos in-place.
    """
    ventana = tk.Toplevel(root)
    ventana.title("Select CIFS shares to mount as " + usuario_actual)
    tk.Label(ventana, text="Available SMB/CIFS resources:").pack(pady=(10, 5))
        # Contenedor con scroll
    frame_scroll = ttk.Frame(ventana)
    frame_scroll.pack(pady=(0, 10), fill="both", expand=True)

    canvas = tk.Canvas(frame_scroll)
    scrollbar = ttk.Scrollbar(frame_scroll, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)

    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    frame_cifs = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=frame_cifs, anchor="nw", tags="frame_cifs")

    def ajustar_scroll(event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfig("frame_cifs", width=canvas.winfo_width())

    frame_cifs.bind("<Configure>", ajustar_scroll)
    canvas.bind("<Configure>", ajustar_scroll)

    shares_seleccionados = {}
    recursos_cifs_dict = {}

    columnas = min(4, len(shares)) if shares else 1
    filas = (len(shares) + columnas - 1) // columnas

    filas_por_columna = 15
    for idx, share in enumerate(shares):
        nombre_share = share["name"]
        remote_path = share["name"]
        remote_host = share["host"]
        perfil_esperado = f"{usuario_actual}-smbmount-{remote_host}"
        punto_montaje = generar_punto_montaje(usuario_actual, nombre_share)

        recursos_cifs_dict[nombre_share] = {
            "nombre_perfil": perfil_esperado,
            "punto_montaje": punto_montaje,
            "remote_path": remote_path,
            "remote_host": remote_host
        }

        var = tk.BooleanVar(value=False)
        shares_seleccionados[nombre_share] = var

        fila = idx % filas_por_columna
        columna = idx // filas_por_columna

        chk = tk.Checkbutton(frame_cifs, text=nombre_share, variable=var, anchor="w")
        chk.grid(row=fila, column=columna, sticky="w", padx=10, pady=2)

    def continuar():
        # # Configuramos shares seleccionados
        recursos_seleccionados = [recurso for recurso, var in shares_seleccionados.items() if var.get()]

        for recurso in recursos_seleccionados:
            datos = recursos_cifs_dict[recurso]
            nombre_perfil = datos["nombre_perfil"]
            punto_montaje = datos["punto_montaje"]
            remote_path = datos["remote_path"]

            if not os.path.ismount(punto_montaje):
                sistema = platform.system()
                if sistema != "Windows":
                    os.makedirs(punto_montaje, exist_ok=True)
                montar_share_rclone(nombre_perfil, remote_path, punto_montaje, mounts_activos)
        ventana.destroy()

    def on_actualizar_credenciales_smb(usuario_actual, es_admin_its=False):
        """Actualiza las credenciales SMB de todos los perfiles del usuario."""
        resultado = pedir_credenciales(ventana, "Update SMB Credentials", "Enter new SMB credentials for user:", usuario_actual)

        if not es_admin_its:
            if not validar_credenciales_ldap(resultado):
                messagebox.showinfo("Cancelled", "Credentials not valid.")
                return

        usuario_actual = resultado["usuario"]
        nueva_password = resultado["password"]

        if not resultado:
            messagebox.showinfo("Cancelled", "Credentials were not updated.")
            return

        # nueva_password = resultado[1]
        try:
            actualizar_password_perfiles_rclone(usuario_actual, nueva_password)
            messagebox.showinfo("Success", f"Credentials have been updated for all profiles of {usuario_actual}.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not update credentials:\n{e}")

    ttk.Button(
    ventana,
    text="Update SMB credentials",
    command=lambda: on_actualizar_credenciales_smb(usuario_actual, es_admin_its)).pack(pady=(5, 0))
    ttk.Button(ventana, text="Continue", command=continuar).pack(pady=15)

    # Forzar cálculo del tamaño real
    ventana.update_idletasks()

    # ✅ Ajuste: calcula ancho y alto para priorizar que quepan filas (crecer verticalmente)
    shares_por_columna = 15
    columnas = max(1, len(shares) // shares_por_columna + (len(shares) % shares_por_columna > 0))
    # print(f"Calculated columns: {columnas}")
    ancho_ventana = max(500, 200 + (columnas * 160))  # un poco más ancho por columna

    # número de filas visibles (máximo filas_por_columna, pero si hay menos shares, menos)
    filas_visibles = min(filas_por_columna, len(shares)) if shares else 1

    # estimación de altura por fila (checkbox + padding)
    alto_por_fila = 30
    alto_base = 170  # título + márgenes + botones
    alto_ventana = alto_base + (filas_visibles * alto_por_fila)

    # límites razonables para no salirse de pantalla
    alto_max = int(ventana.winfo_screenheight() * 0.85)
    alto_ventana = min(max(400, alto_ventana), alto_max)

    # Centrado en pantalla
    x = (ventana.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y = (ventana.winfo_screenheight() // 2) - (alto_ventana // 2)

    # Aplicar dimensiones
    ventana.geometry(f"{ancho_ventana}x{alto_ventana}+{x}+{y}")

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()         # <--- Asegura que esté visible
    ventana.update_idletasks()  # <--- Fuerza actualización visual
    ventana.lift()              # <--- Eleva al frente
    ventana.focus_force()       # <--- Da foco real

    # ✅ Recentrado tras render real
    ancho_real = ventana.winfo_width()
    alto_real = ventana.winfo_height()
    x = (ventana.winfo_screenwidth() // 2) - (ancho_real // 2)
    y = (ventana.winfo_screenheight() // 2) - (alto_real // 2)
    ventana.geometry(f"{ancho_real}x{alto_real}+{x}+{y}")


    ventana.wait_window()
    return None

def seleccionar_servidor_minio(root, shares, perfiles_configurados):
    """
    Diálogo para seleccionar el servidor MinIO.
    
    Args:
        root: Ventana padre
        shares: No usado (compatibilidad)
        perfiles_configurados: No usado (compatibilidad)
    
    Returns:
        dict: {
            "servidor": str,      # Nombre del servidor seleccionado
            "perfil": str,        # Nombre del perfil rclone
            "endpoint": str       # URL del endpoint S3
        }
    """
    print("Select the MinIO server to use:") 
    resultado = {"servidor": None, "perfil": None, "endpoint": None}

    ventana = tk.Toplevel(root)
    ventana.title("Select MinIO server")

    ttk.Label(ventana, text="Select the MinIO server:").pack(pady=(10, 5))
    servidor_var = tk.StringVar(value=list(minio_functions.MINIO_SERVERS.keys())[0])
    servidor_menu = ttk.Combobox(ventana, textvariable=servidor_var, values=list(minio_functions.MINIO_SERVERS.keys()), state="readonly", width=30)
    servidor_menu.pack(pady=(0, 10))

    def continuar():
        # Configuramos servidor minio
        servidor = servidor_var.get()
        # red = red_var.get()
        perfil = minio_functions.MINIO_SERVERS[servidor]["IRB"]["profile"]
        endpoint = minio_functions.MINIO_SERVERS[servidor]["IRB"]["endpoint"]
        resultado.update({"servidor": servidor, "perfil": perfil, "endpoint": endpoint})

        ventana.destroy()

    ttk.Button(ventana, text="Continue", command=continuar).pack(pady=15)

    # Forzar cálculo del tamaño real
    ventana.update_idletasks()

    # Obtener dimensiones necesarias
    ancho = ventana.winfo_reqwidth() + 20
    alto = ventana.winfo_reqheight()

    # Calcular posición centrada
    x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    y = ((ventana.winfo_screenheight() + 20) // 2) - (alto // 2)

    # Aplicar centrado y redimensionado automático
    ventana.geometry(f"{ancho}x{alto}+{x}+{y}")

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()         # <--- Asegura que esté visible
    ventana.update_idletasks()  # <--- Fuerza actualización visual
    ventana.lift()              # <--- Eleva al frente
    ventana.focus_force()       # <--- Da foco real
    ventana.wait_window()
    return resultado

def prompt_credenciales_renovar(root, tiempo_restante: str):
    """
    Diálogo para decidir si renovar credenciales S3 temporales (STS).
    
    Args:
        root: Ventana padre
        tiempo_restante (str): Descripción del tiempo restante de las credenciales actuales
    
    Returns:
        dict: {
            "accion": "renovar" | "mantener" | None,
            "dias": int (solo si accion="renovar")
        }
    
    Opciones:
        - Mantener: Usar credenciales actuales
        - Renovar: Solicitar nuevas credenciales STS (1-30 días)
    """
    resultado = {"accion": None, "dias": None}

    ventana = tk.Toplevel(root)
    ventana.title("Minio S3 credentials renewal")

    tk.Label(ventana, text="Remaining lifespan for current credentials:", font=("Arial", 12)).pack(pady=(15, 5))
    tk.Label(ventana, text=tiempo_restante, fg="blue", font=("Arial", 10, "bold")).pack(pady=(0, 10))

    frame_dropdown = tk.Frame(ventana)
    frame_dropdown.pack(pady=(5, 10))
    tk.Label(frame_dropdown, text="Select lifespan for new STS credentials(days):").pack(side=tk.LEFT, padx=5)
    dias_var = tk.StringVar(value="7")
    desplegable = ttk.Combobox(frame_dropdown, textvariable=dias_var, values=[str(i) for i in range(1, 31)], width=4, state="readonly")
    desplegable.pack(side=tk.LEFT)

    def mantener():
        resultado["accion"] = "mantener"
        ventana.destroy()

    def renovar():
        resultado["accion"] = "renovar"
        resultado["dias"] = int(dias_var.get())
        ventana.destroy()

    frame_botones = tk.Frame(ventana)
    frame_botones.pack(pady=10)
    tk.Button(frame_botones, text="Keep current", width=12, command=mantener).grid(row=0, column=0, padx=10)
    tk.Button(frame_botones, text="Renew", width=12, command=renovar).grid(row=0, column=1, padx=10)


    # Forzar cálculo del tamaño real
    ventana.update_idletasks()

    # Obtener dimensiones necesarias
    ancho = ventana.winfo_reqwidth() + 20
    alto = ventana.winfo_reqheight()

    # Calcular posición centrada
    x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    y = ((ventana.winfo_screenheight() + 20) // 2) - (alto // 2)

    # Aplicar centrado y redimensionado automático
    ventana.geometry(f"{ancho}x{alto}+{x}+{y}")

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()         # <--- Asegura que esté visible
    ventana.update_idletasks()  # <--- Fuerza actualización visual
    ventana.lift()              # <--- Eleva al frente
    ventana.focus_force()       # <--- Da foco real
    ventana.wait_window()
    return resultado

# ============================================================================
# INTERFAZ PRINCIPAL DE TRANSFERENCIA
# ============================================================================


def abrir_interfaz_copia(root, perfil_rclone, mounts_activos):
    """
    Interfaz principal para copiar y verificar datos con rclone.
    
    COMPONENTES PRINCIPALES:
    -----------------------
    1. Campos de metadatos: Se adjuntan como tags S3 a los objetos copiados
    2. Selector de origen: Archivo o carpeta (local o remote)
    3. Selector de destino: Bucket/prefix en MinIO
    4. Flags avanzados: Parámetros adicionales de rclone
    5. Botones de acción:
       - Copy data: Ejecuta rclone copy con metadatos
       - Check data: Verifica integridad (rclone check)
       - Mount destination: Monta el bucket S3 localmente
       - Save Log: Exporta el log a archivo .log
    6. Log en tiempo real: ScrolledText que muestra salida de rclone
    
    Args:
        root: Ventana padre
        perfil_rclone (str): Nombre del perfil S3 configurado
        mounts_activos (list): Lista de montajes CIFS activos
    
    FLUJO DE OPERACIÓN:
    ------------------
    1. Usuario llena metadatos (opcional pero recomendado)
    2. Selecciona origen (archivo/carpeta)
    3. Escribe destino (verificación en tiempo real de accesibilidad)
    4. Ejecuta copia → metadatos se adjuntan como x-amz-tagging
    5. Verifica integridad con Check data
    
    CARACTERÍSTICAS TÉCNICAS:
    ------------------------
    - Threads para operaciones de rclone (no bloquea GUI)
    - Queue para comunicación thread → GUI
    - Verificación automática de ruta destino (colores verde/rojo)
    - Comandos rclone mostrados en el log para debugging
    - Desmontaje automático al cerrar (protocol WM_DELETE_WINDOW)
    """
    num_cores = obtener_num_cpus()

    _, rclone_config_path, _ = minio_functions.get_rclone_paths(perfil_rclone)

    ventana = tk.Toplevel(root)
    ventana.title("Copy and verify data with rclone")
    ventana.geometry("1024x768")
    ventana.update_idletasks()
    x = (ventana.winfo_screenwidth() // 2) - (ventana.winfo_width() // 2)
    y = (ventana.winfo_screenheight() // 2) - (ventana.winfo_height() // 2)
    ventana.geometry(f"+{x}+{y}")

    frame_metadata = ttk.LabelFrame(ventana, text="Metadata to attach to the copied objects")
    frame_metadata.pack(padx=10, pady=(15, 5), fill=tk.X)

    # Permitir que la segunda columna (los Entry) se expanda horizontalmente
    frame_metadata.columnconfigure(1, weight=1)

    labels = [
        ("Project", "project_name"),
        ("Host machine", "compute_node"),
        ("Sample type", "sample_type"),
        ("Input data type", "input_data_type"),
        ("Output data type", "output_data_type"),
        ("Requested by", "requested_by"),
        ("Research group", "research_group")
    ]

    metadata_vars = {}
    for idx, (label_text, var_name) in enumerate(labels):
        ttk.Label(frame_metadata, text=label_text).grid(row=idx, column=0, sticky="w", padx=5, pady=2)

        entry = ttk.Entry(frame_metadata)
        entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")  # <-- clave: sticky="ew"
        metadata_vars[var_name] = entry

    def seleccionar_archivo():
        ruta = traducir_ruta_a_remote(filedialog.askopenfilename(title="Select source file"), mounts_activos)
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)
            actualizar_ruta_resultante()

    def seleccionar_carpeta():
        ruta = traducir_ruta_a_remote(filedialog.askdirectory(title="Select source folder"), mounts_activos)
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)
            actualizar_ruta_resultante()

    ## Mecanismo de debounce para comprobar ruta destino
    debounce_timer = None

    def comprobar_ruta_accesible(event=None):
        nonlocal debounce_timer
        # print("🔁 Evento detectado: tecla pulsada en destino")

        if debounce_timer:
            debounce_timer.cancel()
            # print("⏱️ Timer anterior cancelado")

        debounce_timer = threading.Timer(0.5, verificar_ruta_remota)
        debounce_timer.start()
        # print("⏳ Nuevo timer iniciado")

    def verificar_ruta_remota():
        ruta = entrada_destino.get().strip()
        # print(f"📡 Verificando ruta: {ruta}")

        if not ruta:
            entrada_destino.configure(background="white")
            # print("⚪ Campo vacío: fondo blanco")
            return

        try:
            result = subprocess.run(
                ["rclone", "ls", f"{perfil_rclone}:{ruta}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )

            if result.returncode == 0:
                entrada_destino.configure(background="#d6f5d6")  # verde suave
                # print("✅ Ruta accesible: fondo verde")
            else:
                entrada_destino.configure(background="#f5d6d6")  # rojo suave
                # print("❌ Ruta no accesible: fondo rojo")

        except subprocess.TimeoutExpired:
            entrada_destino.configure(background="#f5d6d6")
            # print("⏰ Timeout al ejecutar rclone")
        except Exception as e:
            entrada_destino.configure(background="#f5d6d6")
            print(f"‼️ Excepción inesperada: {e}")

    def actualizar_ruta_resultante(*args):
        origen = entrada_origen.get().strip()
        destino = entrada_destino.get().strip().rstrip("/")

        if not origen or not destino:
            label_ruta_resultante.configure(text="Files will be copied into: [incomplete]")
            return

        ruta_esperada = f"{destino}/"
        label_ruta_resultante.configure(text=f"Files will be copied into: {ruta_esperada}")
    def manejar_evento_destino(event=None):
        comprobar_ruta_accesible()
        actualizar_ruta_resultante()

    frame_rutas = ttk.Frame(ventana)
    frame_rutas.pack(fill=tk.X, padx=10, pady=(15, 10))

    # --- Línea 1: Origen (entrada + botones)
    ttk.Label(frame_rutas, text="Source path (local or rclone profile):").grid(row=0, column=0, columnspan=3, sticky="w")

    entrada_origen = ttk.Entry(frame_rutas, width=60)
    entrada_origen.grid(row=1, column=0, sticky="ew", padx=(0, 5))

    boton_archivo = ttk.Button(frame_rutas, text="📄 File", command=seleccionar_archivo)
    boton_archivo.grid(row=1, column=1, padx=(0, 5))

    boton_carpeta = ttk.Button(frame_rutas, text="📁 Folder", command=seleccionar_carpeta)
    boton_carpeta.grid(row=1, column=2)

    # --- Línea 2: Destino
    ttk.Label(frame_rutas, text=f"Destination path (bucket in profile {perfil_rclone}):").grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))
    entrada_destino = tk.Entry(frame_rutas)  # usa tk.Entry, no ttk.Entry
    entrada_destino.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 10))

    # --- Línea informativa de ruta final esperada ---
    ## enlazamos evento de comprobación de ruta destino
    entrada_destino.bind("<KeyRelease>", manejar_evento_destino)
    entrada_origen.bind("<KeyRelease>", actualizar_ruta_resultante)

    label_ruta_resultante = ttk.Label(frame_rutas, text="Los archivos se copiarán en: [ruta no determinada aún]", wraplength=750, justify="left")
    label_ruta_resultante.grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 10))

    # --- Línea 3: Flags avanzados
    ttk.Label(frame_rutas, text="Advanced (experts only): Additional flags for rclone:").grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))

    entry_flags = ttk.Entry(frame_rutas)
    entry_flags.insert(0, f"--transfers={num_cores} --checkers={num_cores} --s3-no-check-bucket")
    entry_flags.grid(row=6, column=0, columnspan=3, sticky="ew")

    # Que se expanda solo la columna 0 (donde va la entrada de texto)
    frame_rutas.columnconfigure(0, weight=1)

    # --- Fin campo flags avanzados ---

    # --- Botones de acción ---

    frame_botones = ttk.Frame(ventana)
    frame_botones.pack(pady=(15, 0))

    boton_copiar = ttk.Button(frame_botones, text="Copy data")
    boton_copiar.grid(row=0, column=0, padx=10)

    boton_check = ttk.Button(frame_botones, text="Check data")
    boton_check.grid(row=0, column=1, padx=10)

    boton_montar = ttk.Button(frame_botones, text="Mount destination folder")
    boton_montar.grid(row=0, column=2, padx=10)

    boton_guardar_log = ttk.Button(frame_botones, text="Save Log…", command=lambda: guardar_log_en_fichero(log_text))
    boton_guardar_log.grid(row=0, column=3, padx=10)

    # --- Fin botones de acción ---

    def guardar_log_en_fichero(log_widget):
        """
        Abre un diálogo para guardar el contenido de log_widget en un .txt
        """

        # Fecha y hora actual
        ahora = datetime.now()
        timestamp_str = ahora.strftime("%Y-%m-%d %H:%M:%S")
        filename_default = f"bifrost-{ahora.strftime('%Y-%m-%d_%H-%M-%S')}.log"


        contenido = f"### Log saved at: {timestamp_str} ###\n\n"
        contenido += "### Log Output ###\n"
        contenido += log_widget.get("1.0", tk.END).rstrip()
        if not contenido:
            messagebox.showinfo("Save Log", "There is no log content to save.")
            return

        # Diálogo “Guardar como”
        ruta_guardado = filedialog.asksaveasfilename(
            title="Save log as…",
            defaultextension=".log",
            initialfile=filename_default,
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not ruta_guardado:
            return  # El usuario canceló

        try:
            with open(ruta_guardado, "w", encoding="utf-8") as f:
                f.write(contenido)
            messagebox.showinfo("Save Log", f"Log saved successfully to:\n{ruta_guardado}")
        except Exception as e:
            messagebox.showerror("Save Log", f"Error saving log:\n{str(e)}")

    def lanzar_montaje():
        ruta_destino = entrada_destino.get().strip()
        if not ruta_destino:
            messagebox.showerror("Error","You must specify a destination path to mount.")
            return
        minio_functions.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta_destino)

    boton_montar.config(command=lanzar_montaje)

    log_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=25)
    log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    log_queue = queue.Queue()

    def procesar_queue():
        try:
            while True:
                item = log_queue.get_nowait()
                if isinstance(item, tuple):
                    tipo, valor = item
                    if tipo == "enable_button":
                        if valor == "copiar":
                            boton_copiar.config(state="normal")
                        elif valor == "check":
                            boton_check.config(state="normal")
                else:
                    log_text.insert(tk.END, item)
                    log_text.see(tk.END)
        except queue.Empty:
            pass
        ventana.after(100, procesar_queue)

    def lanzar_copia():
        origen = entrada_origen.get().strip()
        destino = entrada_destino.get().strip()

        flags_adicionales = entry_flags.get().strip().split()
        

        if not origen or not destino:
            messagebox.showerror("Error","You must enter both source and destination.")
            return
        
        # 🟩 CONSTRUIR EL JSON DE METADATOS EN EL HILO PRINCIPAL
        metadatos_dict = {clave: campo.get().strip() for clave, campo in metadata_vars.items()}
        # Convertimos a cadena estilo URL
        tag_string = "&".join(f"{k}={urllib.parse.quote(v)}" for k, v in metadatos_dict.items())

        # Luego lo pasas como header a rclone (en el comando)
        header_value = f"x-amz-tagging:{tag_string}"

        print("Encoded tag value:", header_value)
        # tag_argument = f"metadata={json_metadatos}"

        boton_copiar.config(state="disabled")
        boton_check.config(state="disabled")

        # Insertar timestamp y metadatos en el log antes de la copia
        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_text.insert(tk.END, f"### Copy operation started at {ahora} ###\n")

        log_text.insert(tk.END, "### Metadata ###\n")
        for clave, valor in metadatos_dict.items():
            log_text.insert(tk.END, f"{clave}: {valor}\n")
        log_text.insert(tk.END, "\n")

        log_text.insert(tk.END, f"Executing: rclone copy {origen} {perfil_rclone}:/{destino}\n")

        def ejecutar_rclone_copy():
            try:
                comando = [
                    "rclone", "copy",
                    origen,
                    f"{perfil_rclone}:/{destino}",
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
                    "--header-upload", header_value
                ]

                comando.extend(flags_adicionales)

                # Mostrar el comando final en la GUI
                comando_str = " ".join(shlex.quote(arg) for arg in comando)
                log_queue.put(f"\n🧾 Full command:\n{comando_str}\n\n")

                proceso = subprocess.Popen(
                    comando,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                for linea in proceso.stdout:
                    log_queue.put(linea)
                proceso.wait()
                if proceso.returncode == 0:
                    log_queue.put("\n✅ Copy completed successfully.\n")
                    log_queue.put(("enable_button", "check"))
                else:
                    log_queue.put(f"\n❌ Copy error. Code: {proceso.returncode}")
            except Exception as e:
                log_queue.put(f"\n❌ Exception while executing rclone: {str(e)}")
            finally:
                log_queue.put(("enable_button", "copiar"))

        threading.Thread(target=ejecutar_rclone_copy, daemon=True).start()

    def lanzar_check():
        origen = entrada_origen.get().strip()
        destino = entrada_destino.get().strip()

        flags_adicionales = entry_flags.get().strip().split()

        if not origen or not destino:
            messagebox.showerror("Error","You must enter both source and destination.")
            return
        
        def es_directorio_rclone(ruta_rclone: str, config_path: str) -> bool:
            try:
                resultado = subprocess.run(
                    ["rclone", "lsjson", ruta_rclone, "--config", config_path],
                    capture_output=True,
                    check=True,
                    text=True
                )
                salida = json.loads(resultado.stdout)
                if not salida:
                    return False
                if len(salida) > 1:
                    return True
                return salida[0].get("IsDir", False)
            except subprocess.CalledProcessError:
                return False

        def traducir_a_ruta_local_montada(origen, mounts_activos, config_path):
            """
            Si 'origen' es un remote rclone y tiene un mount activo asociado, devuelve
            la ruta local equivalente (con fichero si es necesario). Si no, devuelve origen.
            """
            if ":" in origen and not origen.startswith("/"):
                try:
                    remote, ruta_relativa = origen.split(":", 1)
                except ValueError:
                    return origen

                ruta_relativa = ruta_relativa.lstrip("/")

                for mount in mounts_activos:
                    if all(k in mount for k in ("remote_name", "mount_path", "remote_subpath")):
                        if mount["remote_name"] == remote and ruta_relativa.startswith(mount["remote_subpath"]):
                            subruta = ruta_relativa[len(mount["remote_subpath"]):].lstrip("/")
                            ruta_base = Path(mount["mount_path"]) / subruta

                            # 🧠 Comprobamos si es archivo o carpeta usando rclone
                            if es_directorio_rclone(origen, config_path):
                                return str(ruta_base)  # Carpeta
                            else:
                                return str(ruta_base)  # Fichero también, ya viene completo

            return origen

        # --- Determinar tipo de origen y ajustar ruta ---
        if ":" in origen and not origen.startswith("/"):
            # Origen rclone remoto
            remote, ruta_local = origen.split(":", 1)
            ruta_local = ruta_local.lstrip("/")
            if es_directorio_rclone(origen, rclone_config_path):
                # Origen es una carpeta remota
                fichero = None
                carpeta = traducir_a_ruta_local_montada(origen, mounts_activos, rclone_config_path)
                origen_ajustado = carpeta
            else:
                # Origen es un archivo remoto
                ruta_local_path = Path(ruta_local)
                fichero = ruta_local_path.name
                carpeta_remota = f"{remote}:{str(ruta_local_path.parent)}"
                carpeta = traducir_a_ruta_local_montada(carpeta_remota, mounts_activos, rclone_config_path)
                origen_ajustado = carpeta + f"/{fichero}"
        else:
            # Origen local
            if os.path.isfile(origen):
                # Origen es un archivo local
                ruta_local_path = Path(origen)
                fichero = ruta_local_path.name
                carpeta = str(ruta_local_path.parent)
                origen_ajustado = carpeta + f"/{fichero}"
            else:
                # Origen es una carpeta local
                fichero = None
                origen_ajustado = origen

        origen = origen_ajustado

        # --- Lógica de verificación ---
        boton_check.config(state="disabled")
        log_text.insert(tk.END, f"\n🔍 Verifying with: rclone check {origen} {perfil_rclone}:/{destino}\n\n")

        def ejecutar_rclone_check():
            combined_path = Path.home() / "rclone-combined-check.txt"   # HOME en los 3 SO
            combined_path.parent.mkdir(parents=True, exist_ok=True)

            comando = [
                "rclone", "check",
                origen,
                f"{perfil_rclone}:/{destino}",
                "--config", rclone_config_path,
                "--progress",
                "--stats=1s"
            ]

            if fichero:
                comando += [
                    "--one-way",
                    "--copy-links"
                ]
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
                    "--exclude", "**/.snapshots/**"
                ]

            # comando.extend(extension_comando)
            comando.extend(flags_adicionales)

            comando_str = " ".join(shlex.quote(arg) for arg in comando)
            log_queue.put(f"\n🧾 Full command:\n{comando_str}\n\n")

            try:
                proceso = subprocess.Popen(
                    comando,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                for linea in proceso.stdout:
                    log_queue.put(linea)
                proceso.wait()
                if proceso.returncode == 0:
                    log_queue.put("\n✅ Verification OK: no differences found.\n")
                else:
                    log_queue.put(f"\n⚠️ Verification finished with code {proceso.returncode}. Check for possible differences.")
            except Exception as e:
                log_queue.put(f"\n❌ Exception during verification: {str(e)}")
            finally:
                log_queue.put(("enable_button", "check"))

        threading.Thread(target=ejecutar_rclone_check, daemon=True).start()

    def cerrar_aplicacion():
        log_queue.put("\n🧹 Unmounting mount points...\n")
        print("Closing application, unmounting mount points...")
        desmontar_todos_los_mountpoints()
        log_queue.put("✅ Unmount completed. Closing application.\n")
        print("Unmount completed. Closing application.")
        root.destroy()
        sys.exit(0)

    def desmontar_todos_los_mountpoints():        
        ruta_destino = entrada_destino.get().strip()
        if not ruta_destino:
            return
        mount_base = Path.home() / "rclone-mounts" / perfil_rclone
        prefix_sanitizado = ruta_destino.replace("/", "_")
        mount_point_path = mount_base / prefix_sanitizado

        print("Desmontando en:", mount_point_path)
        if not os.path.isdir(mount_point_path):
            return
        
        full_path = str(mount_point_path)
        if os.path.ismount(full_path):
            try:
                sistema = platform.system()
                if sistema == "Linux":
                    subprocess.run(["fusermount", "-u", full_path], check=True)
                elif sistema == "Darwin":  # macOS
                    subprocess.run(["umount", full_path], check=True)
                elif sistema == "Windows":
                    # En Windows, matar el proceso rclone correspondiente
                    subprocess.run(["taskkill", "/F", "/FI", f"WINDOWTITLE eq {full_path}*"], 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL)
            except Exception as e:
                log_queue.put(f"\n⚠️ Could not unmount {full_path}: {str(e)}\n")
                print(f"Could not unmount {full_path}: {str(e)}")    

    ventana.protocol("WM_DELETE_WINDOW", cerrar_aplicacion)

    boton_copiar.config(command=lanzar_copia)
    boton_check.config(command=lanzar_check)

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()
    ventana.update_idletasks()
    ventana.lift()
    ventana.focus_force()

    ventana.columnconfigure(0, weight=1)
    
    procesar_queue()
    ventana.wait_window()
  

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """
    Función principal del programa.
    
    FLUJO COMPLETO:
    ==============
    1. Configuración inicial
       - Parseo de argumentos (--customuser para permitir usuario arbitrario, --update para forzar actualización)
       - Creación de ventana raíz invisible
    
    2. Autenticación LDAP
       - Solicitar credenciales del usuario
       - Validar contra servidor LDAP IRB
       - Obtener grupos LDAP del usuario
    
    3. Verificación de privilegios ITS
       - Si usuario pertenece a grupo 'its': ofrecer modo admin
       - Modo admin: usa credenciales admin_{username} para SMB
    
    4. Gestión de recursos SMB/CIFS
       - Consultar shares accesibles desde NetApp
       - Crear perfiles rclone SMB si no existen
       - Permitir selección y montaje de shares
    
    5. Configuración MinIO S3
       - Seleccionar servidor MinIO
       - Verificar credenciales STS existentes
       - Renovar credenciales si es necesario
    
    6. Lanzar interfaz principal
       - Abrir GUI de transferencia de datos
    
    VARIABLES GLOBALES IMPORTANTES:
    ==============================
    - mounts_activos: Lista de montajes CIFS activos
    - credenciales_ldap: Credenciales del usuario principal
    - credenciales_smb: Credenciales efectivas para SMB (usuario o admin)
    
    EXCEPCIÓN DE FILERS:
    ===================
    - EXCEPCION_FILERS: Filers excluidos del listado (ej: filers de testing)
    """

    EXCEPCION_FILERS = ["filer12-svm-vm"]
    if "--customuser" in sys.argv or "-c" in sys.argv:
        PERMITIR_USUARIO_CUSTOM = True
    else:
        PERMITIR_USUARIO_CUSTOM = False

    # Variable global
    mounts_activos = []  # Cada entrada será un dict con keys: mount_path, remote_name, remote_subpath

    # Configuración inicial y obtención de shares accesibles desde NetApp
    root = tk.Tk()
    # root = ThemedTk(theme="plastik")
    root.title("MinIO Rclone Launcher")
    root.geometry("1x1+0+0")  # Ventana invisible de 1x1 píxeles
    root.overrideredirect(True)  # Sin bordes, completamente invisible

    # ====== PASO 0: COMPROBAR ACTUALIZACIONES (antes de cualquier otra cosa) ====
    minio_functions.check_and_handle_update(root)
    # Si el usuario eligió actualizar, actualizar_y_reiniciar() ya reinició el script
    # Si el usuario eligió continuar, el script sigue aquí

    # ========================================================================
    # PASO 1: AUTENTICACIÓN LDAP 
    # ========================================================================
    # Obtener credenciales LDAP del usuario
    usuario_ldap = None
    while not usuario_ldap:
        if PERMITIR_USUARIO_CUSTOM:
            credenciales_ldap = pedir_credenciales(root, "Enter your username", "Enter your username:")
        else:
            credenciales_ldap = pedir_credenciales(root, "Enter your username", "Enter your username:", getpass.getuser())
        if validar_credenciales_ldap(credenciales_ldap):
            usuario_ldap = credenciales_ldap["usuario"]
    
    print(f"LDAP credentials obtained. User: {credenciales_ldap['usuario']}")

    # ========================================================================
    # PASO 2: OBTENER GRUPOS Y VERIFICAR PRIVILEGIOS
    # ========================================================================
    # Obtener grupos LDAP del usuario
    grupos_ldap = get_ldap_groups(usuario_ldap)
    print("User's LDAP groups:", grupos_ldap)
    # Comprobar si el usuario pertenece al grupo its
    if "its" in grupos_ldap:
        usar_privilegios = messagebox.askyesno("Confirmation", "Do you want to use ITS administrator privileges for CIFS shares?")
        if usar_privilegios:
            credenciales_admin = pedir_credenciales(root, "Enter your username", "Enter your username:", "admin_" + usuario_ldap)
            # Aseguramos el desmontaje de shares al salir
            atexit.register(lambda: desmontar_todos_los_shares(credenciales_admin["usuario"]))
        else:
            credenciales_admin = None
            # Aseguramos el desmontaje de shares al salir
            atexit.register(lambda: desmontar_todos_los_shares(usuario_ldap))
    else:
        usar_privilegios = False
        credenciales_admin = None
        # Aseguramos el desmontaje de shares al salir
        atexit.register(lambda: desmontar_todos_los_shares(usuario_ldap))
    credenciales_smb = construir_credenciales_smb(
        credenciales_ldap,
        usar_privilegios_its=usar_privilegios,
        credenciales_admin=credenciales_admin
    )

    print("Using ITS admin privileges:", usar_privilegios)
    print("Current LDAP user:", usuario_ldap)
    print("Admin credentials:", credenciales_admin['usuario'] if credenciales_admin else 'None')
    print(f"SMB credentials obtained. User: {credenciales_smb['usuario'] if credenciales_smb else 'None'}")

    # ========================================================================
    # PASO 3: GESTIÓN DE RECURSOS SMB/CIFS
    # ========================================================================
    # Obtener perfiles configurados en rclone
    perfiles_configurados = obtener_perfiles_rclone_config()
    print("Configured rclone profiles:", perfiles_configurados)

    shares_no_configurados = []

    # Obtener shares accesibles desde NetApp
    shares_accesibles = obtener_shares_accesibles(grupos_ldap, credenciales_ldap["usuario"], credenciales_ldap["password"], credenciales_smb['usuario'], EXCEPCION_FILERS, usar_privilegios)
    print("Shares accessible from NetApp:")
    for share in shares_accesibles:
        print(f"- {share['name']} (Path: {share['path']}), Host: {share['host']}")
        nombre_perfil_esperado = f"{credenciales_smb['usuario']}-smbmount-{share['host']}"
        # Comprobamos si tenemos perfiles para los shares, si no, pedimos credenciales SMB y los creamos
        if nombre_perfil_esperado not in perfiles_configurados:
            shares_no_configurados.append(share["name"])
    
    # Si hay shares sin configurar, pedimos credenciales SMB y los creamos
    if shares_no_configurados:
        if not credenciales_smb:
            messagebox.showerror("Error", "No SMB credentials provided. Exiting.")
            sys.exit("No SMB credentials provided. Exiting.")

        for share in shares_accesibles:
            nombre_perfil_esperado = f"{credenciales_smb['usuario']}-smbmount-{share['host']}"
            if nombre_perfil_esperado not in perfiles_configurados:
                
                crear_perfil_rclone_smb(
                    nombre_perfil=nombre_perfil_esperado,
                    host=share["host"],
                    path=share["name"],
                    username=credenciales_smb["usuario"],
                    password=credenciales_smb["password"]
                )
                print(f"Rclone profile created for share {share['name']}: {nombre_perfil_esperado}")

        # Update the list of configured profiles
        perfiles_configurados = obtener_perfiles_rclone_config()
        print("Checked configured rclone profiles:", perfiles_configurados)
    
    # ========================================================================
    # PASO 4: FUNCIÓN DE INICIO DE APLICACIÓN
    # ========================================================================
    def iniciar_aplicacion():
        """
        Función que inicia la aplicación tras la configuración inicial.
        Se ejecuta tras un delay para asegurar que la ventana raíz esté lista.
        """
        seleccionar_shares_montar(root, shares_accesibles, credenciales_smb["usuario"], mounts_activos, usar_privilegios)
        
        # Mostrar selector de servidor
        eleccion = seleccionar_servidor_minio(root, shares_accesibles, perfiles_configurados)
        servidor_s3_rcloneconfig = eleccion["perfil"]
        endpoint = eleccion["endpoint"]

        minio_functions.check_rclone_installation()

        current_session_token = minio_functions.get_rclone_session_token(servidor_s3_rcloneconfig)
        if current_session_token == "":
            current_expiration_time = "There are not current credentials configured, let's configure it now."
        else:
            current_expiration_time = minio_functions.get_expiration_from_session_token(current_session_token)

        respuesta = prompt_credenciales_renovar(root, current_expiration_time)

        if respuesta["accion"] == "renovar":
            print(f"Requesting new temporary credentials for user {credenciales_ldap['usuario']}...")
            credentials = minio_functions.get_credentials(endpoint, credenciales_ldap["usuario"], credenciales_ldap["password"], int(respuesta['dias']) * 86400)

            if credentials is None:
                from tkinter import messagebox
                messagebox.showerror("Bad Credentials", "Provided credentials are not correct, please try again or contact ITS")
                sys.exit("Provided credentials are not correct, please try again or contact ITS")

            minio_functions.configure_rclone(
                credentials['AccessKeyId'],
                credentials['SecretAccessKey'],
                credentials['SessionToken'],
                endpoint,
                servidor_s3_rcloneconfig
            )

        elif respuesta["accion"] == "mantener":
            print("User chose to keep the current credentials.")
        else:
            print("No action taken.")

        # Show the main interface
        abrir_interfaz_copia(root, servidor_s3_rcloneconfig, mounts_activos)

    # Launch the entire application after root has been fully created
    root.after(100, iniciar_aplicacion)
    root.mainloop()

if __name__ == "__main__":
    main()