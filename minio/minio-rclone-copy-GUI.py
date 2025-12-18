"""

"""
import minio_functions

import tkinter as tk
# from ttkthemes import ThemedTk

from tkinter import ttk, messagebox, scrolledtext
import boto3
import getpass
import sys
import platform
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from minio_functions import MINIO_SERVERS
import subprocess
import threading
import queue
import os
from pathlib import Path
import json
from urllib.parse import quote
import urllib
import configparser
import requests
import getpass


import time

from ldap3 import Server, Connection, SUBTREE, SIMPLE
from botocore.exceptions import ClientError
# Desactivar warnings de SSL inseguros
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import atexit
import shlex


import os

def obtener_num_cpus():
    cpus = os.environ.get("SLURM_CPUS_PER_TASK")
    if cpus:
        try:
            return int(cpus)
        except ValueError:
            pass  # fallback si hay valor corrupto

    return os.cpu_count() or 1  # fallback mínimo seguro

def traducir_ruta_a_remote(ruta_local, mounts_activos):
    """
    Traduce una ruta local a formato rclone remote:/ruta usando la variable global mounts_activos.
    Si no pertenece a ningún mount activo, devuelve None.
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

# def get_secret(secret_name):
#     """
#     Retrieve secret from AWS Secrets Manager.
#     """
#     region_name = "eu-west-1"
#     session = boto3.session.Session()
#     client = session.client(service_name='secretsmanager', region_name=region_name)

#     try:
#         get_secret_value_response = client.get_secret_value(SecretId=secret_name)
#     except ClientError as e:
#         raise e

#     return get_secret_value_response['SecretString']

# def obtener_shares_accesibles(grupos_usuario: list[str], username, password, usuario_actual, excepcion_filers: list[str]) -> list[dict]:
#     usuario = usuario_actual

#     URL = "https://nacluster.irbbarcelona.pcb.ub.es/api/protocols/cifs/shares?fields=name,svm.name,path,acls"
#     try:
#         headers = {"Accept": "application/json"}
#         respuesta = requests.get(URL, auth=(username, password), headers=headers, verify=False)
#         respuesta.raise_for_status()
#         data = respuesta.json()
#     except Exception as e:
#         print(f"Error al obtener shares desde NetApp: {e}")
#         return []

#     grupos_set = {g.strip().lower() for g in grupos_usuario}

#     def normalizar_acl(principal: str) -> str:
#         s = (principal or "").strip().lower()

#         if s.startswith("cn="):
#             return s.split(",", 1)[0].removeprefix("cn=").strip()
#         if "\\" in s:
#             return s.split("\\", 1)[1].strip()
#         if "@" in s:
#             return s.split("@", 1)[0].strip()
#         return s

#     resultado = []
#     for share in data.get("records", []):
#         if share["svm"]["name"] not in excepcion_filers:
#             for acl in share.get("acls", []):
#                 principal = acl.get("user_or_group", "")
#                 pnorm = normalizar_acl(principal)

#                 if pnorm == usuario.lower() or pnorm in grupos_set:
#                     resultado.append({
#                         "name": share["name"],
#                         "path": share["path"],
#                         "host": (share["svm"]["name"]).replace("-svm", "") + ".sc.irbbarcelona.org"  # <--- Aquí añadimos el host (NetApp)
#                     })
#                     break

#     return resultado

def obtener_shares_accesibles(grupos_usuario: list[str], username, password, usuario_actual, excepcion_filers: list[str]) -> list[dict]:
    usuario = usuario_actual

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
                principal = acl.get("user_or_group", "")
                pnorm = normalizar_acl(principal)

                if pnorm == usuario.lower() or pnorm in grupos_set:
                    resultado.append({
                        "name": share["name"],
                        "path": share["path"],
                        "host": (share["svm"]["name"]).replace("-svm", "") + ".sc.irbbarcelona.org"  # <--- Aquí añadimos el host (NetApp)
                    })
                    break

    return resultado

def get_ldap_groups():
    # usuario = "esancho" 
    usuario = getpass.getuser()
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

def obtener_perfiles_rclone_config(config_path=None):
    """
    Devuelve una lista con los nombres de perfiles configurados en rclone.conf.

    Args:
        config_path (str): Ruta al archivo de configuración. Por defecto se usa ~/.config/rclone/rclone.conf

    Returns:
        list[str]: Lista de nombres de secciones/perfiles.
    """
    if config_path is None:
        config_path = os.path.expanduser("~/.config/rclone/rclone.conf")

    if not os.path.exists(config_path):
        return []

    config = configparser.ConfigParser()
    config.read(config_path)

    return config.sections()

def pedir_credenciales_smb(parent, usuario_actual, es_admin_its=False):
    resultado = {"usuario": None, "password": None}

    ventana = tk.Toplevel(parent)
    ventana.title("IRB Credentials Required")
    ventana.geometry("350x180")
    ventana.transient(parent)
    ventana.grab_set()

    tk.Label(ventana, text="Enter your credentials").pack(pady=(10, 5))

    tk.Label(ventana, text="Username:").pack()
    usuario_var = tk.StringVar(parent, value=usuario_actual)
    entry_user = ttk.Entry(ventana, textvariable=usuario_var, state="disabled")
    entry_user.pack(pady=(0, 5))

    tk.Label(ventana, text="Password:").pack()
    password_var = tk.StringVar()
    entry_pass = ttk.Entry(ventana, textvariable=password_var, show="*")
    entry_pass.pack(pady=(0, 10))

    # Asociar teclas Enter y Escape
    ventana.bind("<Return>", lambda event: confirmar())
    ventana.bind("<Escape>", lambda event: cancelar())

    # Foco inicial en el campo de contraseña
    entry_pass.focus_set()

    def confirmar(es_admin_its=es_admin_its):
        username = usuario_var.get().strip()
        password = password_var.get().strip()

        # DN corregido según estructura LDAP real
        user_dn = f"cn={username},ou=users,ou=admini,o=irbbarcelona"
        server = Server("ldap://irbldap3.sc.irbbarcelona.org")

        try:
            if not es_admin_its:
                conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, auto_bind=True)
                conn.unbind()
            resultado["usuario"] = username
            resultado["password"] = password
            ventana.destroy()
        except Exception as e:
            print("LDAP bind failed:", str(e))  # Optional debug
            messagebox.showerror("Authentication Error", "Incorrect username or password.")

    def cancelar():
        ventana.destroy()

    btn_frame = ttk.Frame(ventana)
    btn_frame.pack()
    ttk.Button(btn_frame, text="Cancel", command=cancelar).pack(side=tk.LEFT, padx=10)
    ttk.Button(btn_frame, text="OK", command=confirmar).pack(side=tk.RIGHT, padx=10)

    ventana.wait_window()

    if resultado["usuario"] and resultado["password"]:
        return {"usuario": resultado["usuario"], "password": resultado["password"]}
    return None

def actualizar_password_perfiles_rclone(usuario: str, nueva_password: str, rclone_config_path: str = None):
    """
    Obscurece la nueva contraseña y actualiza todos los perfiles rclone tipo 'usuario-smbmount-*' con esa password.
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
    config_path = Path.home() / ".config" / "rclone" / "rclone.conf"
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

# def comprobar_credenciales_rclone_smb(nombre_perfil: str) -> bool:
#     try:
#         resultado = subprocess.run(
#             ["rclone", "ls", f"{nombre_perfil}:/", "--config", str(Path.home() / ".config" / "rclone" / "rclone.conf")],
#             stdout=subprocess.DEVNULL,
#             stderr=subprocess.DEVNULL,
#             timeout=10
#         )
#         return resultado.returncode == 0
#     except Exception:
#         return False

def montar_share_rclone(nombre_perfil, share_path, punto_montaje, mounts_activos):
    rclone_config_path = str(Path.home() / ".config" / "rclone" / "rclone.conf")

    # Crear directorio de montaje si no existe
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
    usuario = usuario_actual
    base_dir = Path.home() / "cifs-mount" / usuario

    if not base_dir.exists():
        return

    for subdir in base_dir.iterdir():
        if subdir.is_dir() and os.path.ismount(subdir):
            try:
                subprocess.run(["umount", "-f", str(subdir)], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error unmounting {subdir}: {e}")
    print("All SMB shares have been unmounted.")


def seleccionar_shares_montar(root, shares, usuario_actual, mounts_activos, es_admin_its=False):
    ventana = tk.Toplevel(root)
    ventana.title("Select CIFS shares to mount as " + usuario_actual)
    # ventana.geometry("400x300")

    # ancho = ventana.winfo_reqwidth()
    # alto = ventana.winfo_reqheight()
    # x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    # y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    # ventana.geometry(f'+{x}+{y}')

    tk.Label(ventana, text="Available SMB/CIFS resources:").pack(pady=(10, 5))
    # frame_cifs = ttk.Frame(ventana)
    # frame_cifs.pack(pady=(0, 10), fill=tk.X)

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

    # def ajustar_scroll(event):
    #     canvas.configure(scrollregion=canvas.bbox("all"))

    # frame_cifs.bind("<Configure>", ajustar_scroll)

    # def distribuir_shares_en_columnas(frame_padre, lista_shares, check_vars, max_columnas=4):
    #     total = len(lista_shares)
    #     columnas = min(max_columnas, total)
    #     filas = (total + columnas - 1) // columnas  # redondeo hacia arriba
    #
    #     for idx, share in enumerate(lista_shares):
    #         fila = idx % filas
    #         columna = idx // filas
    #         var = tk.BooleanVar()
    #         chk = ttk.Checkbutton(frame_padre, text=share, variable=var)
    #         chk.grid(row=fila, column=columna, sticky="w", padx=8, pady=4)
    #         check_vars[share] = var

    # ✅ Ajuste: mantener el frame del canvas al ancho del canvas y recalcular scrollregion
    def ajustar_scroll(event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfig("frame_cifs", width=canvas.winfo_width())

    frame_cifs.bind("<Configure>", ajustar_scroll)
    canvas.bind("<Configure>", ajustar_scroll)

    # usuario = getpass.getuser()
    shares_seleccionados = {}
    recursos_cifs_dict = {}

    # for share in shares:
    #     nombre_share = share["name"]
    #     remote_path = share["name"]
    #     remote_host = share["host"]
    #     perfil_esperado = f"{usuario_actual}-smbmount-{remote_host}"
    #     punto_montaje = os.path.expanduser(f"~/cifs-mount/{usuario_actual}/{nombre_share}")
    #
    #     recursos_cifs_dict[nombre_share] = {
    #         "nombre_perfil": perfil_esperado,
    #         "punto_montaje": punto_montaje,
    #         "remote_path": remote_path,
    #         "remote_host": remote_host
    #     }
    #
    #     # Checkbox para que el usuario seleccione si desea montar este recurso
    #     var = tk.BooleanVar(value=False)
    #     shares_seleccionados[nombre_share] = var
    #
    #     frame_fila = tk.Frame(frame_cifs)
    #     frame_fila.pack(anchor="w", padx=10)
    #
    #     chk = tk.Checkbutton(frame_fila, variable=var)
    #     chk.pack(side=tk.LEFT)
    #
    #     color = "black"
    #     lbl = tk.Label(frame_fila, text=nombre_share, fg=color)
    #     lbl.pack(side=tk.LEFT, padx=5)

    columnas = min(4, len(shares)) if shares else 1
    filas = (len(shares) + columnas - 1) // columnas

    filas_por_columna = 15
    for idx, share in enumerate(shares):
        nombre_share = share["name"]
        remote_path = share["name"]
        remote_host = share["host"]
        perfil_esperado = f"{usuario_actual}-smbmount-{remote_host}"
        punto_montaje = os.path.expanduser(f"~/cifs-mount/{usuario_actual}/{nombre_share}")

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

        # # ¿Falta algún perfil?
        # recursos_sin_perfil = [r for r in recursos_seleccionados if not recursos_cifs_dict[r]["tiene_perfil"]]

        # credenciales = None
        # if recursos_sin_perfil:
        #     credenciales = pedir_credenciales_smb(ventana)
        #     if not credenciales:
        #         return  # Usuario canceló

        print

        for recurso in recursos_seleccionados:
            datos = recursos_cifs_dict[recurso]
            nombre_perfil = datos["nombre_perfil"]
            punto_montaje = datos["punto_montaje"]
            remote_path = datos["remote_path"]

            # if not datos["tiene_perfil"]:
            #     crear_perfil_rclone_smb(
            #         nombre_perfil=nombre_perfil,
            #         # host=remote_path.split("/")[0],
            #         # path="/".join(remote_path.split("/")[1:]),
            #         host=datos["remote_host"],
            #         path=remote_path,
            #         username=credenciales["usuario"],
            #         password=credenciales["password"]
            #     )

            if not os.path.ismount(punto_montaje):
                os.makedirs(punto_montaje, exist_ok=True)
                montar_share_rclone(nombre_perfil, remote_path, punto_montaje, mounts_activos)
        ventana.destroy()

    def on_actualizar_credenciales_smb(usuario_actual, es_admin_its=False):
        # usuario_actual = getpass.getuser()
        resultado = pedir_credenciales_smb(ventana, usuario_actual, es_admin_its)

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

    # # Forzar cálculo del tamaño real
    # ventana.update_idletasks()
    #
    # # Obtener dimensiones necesarias
    # ancho = ventana.winfo_reqwidth() + 20
    # alto = ventana.winfo_reqheight()
    #
    # # Calcular posición centrada
    # x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    # y = ((ventana.winfo_screenheight() + 20) // 2) - (alto // 2)
    #
    # # Aplicar centrado y redimensionado automático
    # ventana.geometry(f"{ancho}x{alto}+{x}+{y}")

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
    print("Select the MinIO server to use:") 
    resultado = {"servidor": None, "perfil": None, "endpoint": None}

    ventana = tk.Toplevel(root)
    ventana.title("Select MinIO server")
    # ventana.geometry("400x300")

    # ancho = ventana.winfo_reqwidth()
    # alto = ventana.winfo_reqheight()
    # x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    # y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    # ventana.geometry(f'+{x}+{y}')

    ttk.Label(ventana, text="Select the MinIO server:").pack(pady=(10, 5))
    servidor_var = tk.StringVar(value=list(MINIO_SERVERS.keys())[0])
    servidor_menu = ttk.Combobox(ventana, textvariable=servidor_var, values=list(MINIO_SERVERS.keys()), state="readonly", width=30)
    servidor_menu.pack(pady=(0, 10))

    # ttk.Label(ventana, text="Selecciona la red desde la que accedes:").pack()
    # red_var = tk.StringVar(value="IRB")
    # frame_radios = tk.Frame(ventana)
    # frame_radios.pack(pady=5)
    # tk.Radiobutton(frame_radios, text="Red IRB", variable=red_var, value="IRB").pack(side=tk.LEFT, padx=10)
    # tk.Radiobutton(frame_radios, text="Red HPC Cluster", variable=red_var, value="HPC").pack(side=tk.LEFT, padx=10)




    # ttk.Label(ventana, text="Recursos CIFS disponibles:").pack(pady=(10, 5))
    # frame_cifs = ttk.Frame(ventana)
    # frame_cifs.pack(pady=(0, 10), fill=tk.X)

    
    # usuario = getpass.getuser()
    # shares_seleccionados = {}
    # recursos_cifs_dict = {}

    # for share in shares:
    #     nombre_share = share["name"]
    #     remote_path = share["name"]
    #     remote_host = share["host"]
    #     perfil_esperado = f"{usuario}-smbmount-{nombre_share}"
    #     punto_montaje = os.path.expanduser(f"~/cifs-mount/{usuario}/{nombre_share}")
    #     tiene_perfil = perfil_esperado in perfiles_configurados

    #     # Guardamos info para uso posterior
    #     recursos_cifs_dict[nombre_share] = {
    #         "nombre_perfil": perfil_esperado,
    #         "punto_montaje": punto_montaje,
    #         "remote_path": remote_path,
    #         "remote_host": remote_host,
    #         "tiene_perfil": tiene_perfil
    #     }

    #     # Checkbox para que el usuario seleccione si desea montar este recurso
    #     var = tk.BooleanVar(value=False)
    #     shares_seleccionados[nombre_share] = var

    #     color = "green" if tiene_perfil else "orange"

    #     frame_fila = tk.Frame(frame_cifs)
    #     frame_fila.pack(anchor="w", padx=10)

    #     chk = tk.Checkbutton(frame_fila, variable=var)
    #     chk.pack(side=tk.LEFT)

    #     lbl = tk.Label(frame_fila, text=nombre_share, fg=color)
    #     lbl.pack(side=tk.LEFT, padx=5)







    def continuar():
        # Configuramos servidor minio
        servidor = servidor_var.get()
        # red = red_var.get()
        perfil = MINIO_SERVERS[servidor]["IRB"]["profile"]
        endpoint = MINIO_SERVERS[servidor]["IRB"]["endpoint"]
        resultado.update({"servidor": servidor, "perfil": perfil, "endpoint": endpoint})

        # # Configuramos shares seleccionados
        # recursos_seleccionados = [recurso for recurso, var in shares_seleccionados.items() if var.get()]

        # # ¿Falta algún perfil?
        # recursos_sin_perfil = [r for r in recursos_seleccionados if not recursos_cifs_dict[r]["tiene_perfil"]]

        # credenciales = None
        # if recursos_sin_perfil:
        #     credenciales = pedir_credenciales_smb(ventana)
        #     if not credenciales:
        #         return  # Usuario canceló

        # for recurso in recursos_seleccionados:
        #     datos = recursos_cifs_dict[recurso]
        #     nombre_perfil = datos["nombre_perfil"]
        #     punto_montaje = datos["punto_montaje"]
        #     remote_path = datos["remote_path"]

        #     if not datos["tiene_perfil"]:
        #         crear_perfil_rclone_smb(
        #             nombre_perfil=nombre_perfil,
        #             # host=remote_path.split("/")[0],
        #             # path="/".join(remote_path.split("/")[1:]),
        #             host=datos["remote_host"],
        #             path=remote_path,
        #             username=credenciales["usuario"],
        #             password=credenciales["password"]
        #         )

        #     if not os.path.ismount(punto_montaje):
        #         os.makedirs(punto_montaje, exist_ok=True)
        #         montar_share_rclone(nombre_perfil, remote_path, punto_montaje)


        ventana.destroy()



    # def on_actualizar_credenciales_smb():
    #     # usuario_actual = getpass.getuser()
    #     resultado = pedir_credenciales_smb(ventana)

    #     usuario_actual = resultado["usuario"]
    #     nueva_password = resultado["password"]

    #     if not resultado:
    #         messagebox.showinfo("Cancelado", "No se actualizaron las credenciales.")
    #         return

    #     # nueva_password = resultado[1]
    #     try:
    #         actualizar_password_perfiles_rclone(usuario_actual, nueva_password)
    #         messagebox.showinfo("Éxito", f"Se han actualizado las credenciales para los perfiles de {usuario_actual}.")
    #     except Exception as e:
    #         messagebox.showerror("Error", f"No se pudieron actualizar las credenciales:\n{e}")


    # ttk.Button(ventana, text="Actualizar credenciales SMB", command=on_actualizar_credenciales_smb).pack(pady=(5, 0))
    ttk.Button(ventana, text="Continue", command=continuar).pack(pady=15)

    # Comprobar si hay una nueva versión disponible
    if getattr(sys, 'frozen', False):  # Si es un ejecutable PyInstaller
        ultima_version = minio_functions.check_update_version()
        if ultima_version:
            frame_update = ttk.Frame(ventana)
            frame_update.pack(pady=(10, 0))
            ttk.Label(frame_update, text=f"🚀 New version available: {ultima_version}", foreground="green").pack()
            ttk.Button(
                frame_update,
                text="Update to latest version",
                command=lambda: minio_functions.actualizar_y_reiniciar(ventana, "minio-rclone-copy-GUI")
            ).pack(pady=(5, 10))


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
    resultado = {"accion": None, "dias": None}

    ventana = tk.Toplevel(root)
    ventana.title("Minio S3 credentials renewal")
    # ventana.geometry("400x200")

    # ancho = ventana.winfo_reqwidth()
    # alto = ventana.winfo_reqheight()
    # x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    # y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    # ventana.geometry(f'+{x}+{y}')

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

def pedir_credenciales_irb(root, usuario_actual):
    resultado = {"username": None, "password": None}
    ventana = tk.Toplevel(root)
    ventana.title("Configure IRB Minio S3 to use with rclone as " + usuario_actual)
    # ventana.geometry("350x150")

    # x_Left = int(ventana.winfo_screenwidth() / 2 - 350 / 2)
    # y_Top = int(ventana.winfo_screenheight() / 2 - 150 / 2)
    # ventana.geometry(f"+{x_Left}+{y_Top}")

    ttk.Label(ventana, text="Type your IRB username:").pack(pady=(10, 0))
    username_var = tk.StringVar(value=usuario_actual)
    username_entry = ttk.Entry(ventana, textvariable=username_var, state="readonly")
    username_entry.pack()

    ttk.Label(ventana, text="Type your IRB password:").pack(pady=(10, 0))
    password_var = tk.StringVar()
    password_entry = ttk.Entry(ventana, textvariable=password_var, show="*")
    password_entry.pack()

    def submit():
        resultado["username"] = username_var.get()
        resultado["password"] = password_var.get()
        ventana.destroy()

    ttk.Button(ventana, text="Set new Rclone credentials", command=submit).pack(pady=(15, 10))
    ventana.bind("<Return>", lambda e: submit())
    ventana.bind("<KP_Enter>", lambda e: submit())


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

def abrir_interfaz_copia(root, perfil_rclone, mounts_activos):
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    import subprocess
    import threading
    import queue
    import minio_functions
    import sys

    num_cores = obtener_num_cpus()

    _, rclone_config_path, _ = minio_functions.get_rclone_paths(perfil_rclone)

    ventana = tk.Toplevel(root)
    ventana.title("Copy and verify data with rclone")
    ventana.geometry("1024x768")
    ventana.update_idletasks()
    x = (ventana.winfo_screenwidth() // 2) - (ventana.winfo_width() // 2)
    y = (ventana.winfo_screenheight() // 2) - (ventana.winfo_height() // 2)
    ventana.geometry(f"+{x}+{y}")

    # frame_metadata = ttk.LabelFrame(ventana, text="Metadata to attach to the copied objects")
    # frame_metadata.pack(padx=10, pady=(15, 5), fill=tk.X)

    # labels = [
    #     ("Project", "project_name"),
    #     ("Host machine", "compute_node"),
    #     ("Sample type", "sample_type"),
    #     ("Input data type", "input_data_type"),
    #     ("Output data type", "output_data_type"),
    #     ("Requested by", "requested_by"),
    #     ("Research group", "research_group")
    # ]

    # metadata_vars = {}
    # for idx, (label_text, var_name) in enumerate(labels):
    #     ttk.Label(frame_metadata, text=label_text).grid(row=idx, column=0, sticky=tk.W, padx=5, pady=2)
    #     entry = ttk.Entry(frame_metadata, width=50)
    #     entry.grid(row=idx, column=1, padx=5, pady=2, sticky=tk.W)
    #     metadata_vars[var_name] = entry

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

    # ttk.Label(ventana, text="Ruta origen (local o perfil rclone):").pack(pady=(15, 0))

    # frame_origen = ttk.Frame(ventana)
    # frame_origen.pack(pady=(0, 10))

    # entrada_origen = ttk.Entry(frame_origen, width=60)
    # entrada_origen.pack(side=tk.LEFT, padx=(0, 5))

    def seleccionar_archivo():
        ruta = traducir_ruta_a_remote(filedialog.askopenfilename(title="Select source file"), mounts_activos)
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)

    def seleccionar_carpeta():
        ruta = traducir_ruta_a_remote(filedialog.askdirectory(title="Select source folder"), mounts_activos)
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)

    # boton_archivo = ttk.Button(frame_origen, text="📄 Archivo", command=seleccionar_archivo)
    # boton_archivo.pack(side=tk.LEFT, padx=(0, 5))

    # boton_carpeta = ttk.Button(frame_origen, text="📁 Carpeta", command=seleccionar_carpeta)
    # boton_carpeta.pack(side=tk.LEFT)

    # ttk.Label(ventana, text=f"Ruta destino (bucket en perfil {perfil_rclone}):").pack(pady=(5, 0))
    # entrada_destino = ttk.Entry(ventana, width=86)
    # entrada_destino.pack(pady=(0, 10))

    # # --- Campo visible de flags avanzados (solo expertos) ---
    # frame_flags = ttk.Frame(ventana)
    # frame_flags.pack(fill=tk.X, pady=(10, 5))

    # ttk.Label(frame_flags, text="Avanzado (solo expertos): Flags adicionales para rclone:").pack(pady=(5, 0))

    # entry_flags = ttk.Entry(frame_flags)
    # entry_flags.insert(0, " --transfers=4 --checkers=8 --s3-no-check-bucket ")  # configuración por defecto
    # entry_flags.pack(side=tk.LEFT, fill=tk.X, expand=True)

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
    entrada_destino = ttk.Entry(frame_rutas)
    entrada_destino.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 10))

    # --- Línea 3: Flags avanzados
    ttk.Label(frame_rutas, text="Advanced (experts only): Additional flags for rclone:").grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))

    entry_flags = ttk.Entry(frame_rutas)
    entry_flags.insert(0, f"--transfers={num_cores} --checkers={num_cores} --s3-no-check-bucket")
    entry_flags.grid(row=5, column=0, columnspan=3, sticky="ew")

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

    # boton_montar_smb = ttk.Button(frame_botones, text="Montar SMB (rclone)", command=montar_volumen_smb_con_rclone)
    # boton_montar_smb.grid(row=0, column=3, padx=10)

    # --- Fin botones de acción ---

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
        # json_metadatos = json.dumps(metadatos_dict, separators=(",", ":"))
        # encoded_tag_value = quote(json_metadatos)
        # Convertimos a cadena estilo URL
        tag_string = "&".join(f"{k}={urllib.parse.quote(v)}" for k, v in metadatos_dict.items())

        # Luego lo pasas como header a rclone (en el comando)
        header_value = f"x-amz-tagging:{tag_string}"

        print("Encoded tag value:", header_value)
        # tag_argument = f"metadata={json_metadatos}"


        boton_copiar.config(state="disabled")
        boton_check.config(state="disabled")
        # log_text.delete("1.0", tk.END)
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
                    "--exclude", "/.DS_Store",
                    "--exclude", "**/.DS_Store",
                    "--exclude", "/Thumbs.db",
                    "--exclude", "**/Thumbs.db",
                    "--exclude", ".snapshots/**",
                    "--exclude", "**/.snapshots/**",
                    "--progress",
                    "--stats=1s",
                    # "--transfers=4",
                    # "--checkers=8",
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
        
        # def es_directorio_rclone(ruta_rclone: str, config_path: str) -> bool:
        #     try:
        #         resultado = subprocess.run(
        #             ["rclone", "lsjson", ruta_rclone, "--config", config_path],
        #             capture_output=True,
        #             check=True,
        #             text=True
        #         )
        #         salida = json.loads(resultado.stdout)
        #         if not salida:
        #             return False  # No existe o está vacío
        #         if len(salida) > 1:
        #             return True  # Múltiples elementos = carpeta
        #         return salida[0].get("IsDir", False)  # único elemento = miramos si es dir
        #     except subprocess.CalledProcessError:
        #         return False

        # def traducir_a_ruta_local_montada(origen, mounts_activos):
        #     """
        #     Si 'origen' es una ruta remota y tiene un mount activo asociado, devuelve la ruta local montada.
        #     Si no, devuelve 'origen' tal cual.
        #     """
        #     if ":" in origen and not origen.startswith("/"):
        #         try:
        #             remote, ruta_relativa = origen.split(":", 1)
        #         except ValueError:
        #             return origen  # No tiene estructura remote:/path

        #         ruta_relativa = ruta_relativa.lstrip("/")

        #         for mount in mounts_activos:
        #             if "remote_name" not in mount or "mount_path" not in mount or "remote_subpath" not in mount:
        #                 continue  # Saltar montajes mal formateados

        #             if mount["remote_name"] == remote:
        #                 if ruta_relativa.startswith(mount["remote_subpath"]):
        #                     subruta = ruta_relativa[len(mount["remote_subpath"]):].lstrip("/")
        #                     return str(Path(mount["mount_path"]) / subruta)

        #     return origen

        # if ":" in origen and not origen.startswith("/"):
        #     # Origen rclone remoto
        #     # remote = origen.split(":", 1)[0]
        #     ruta_local = origen.split(":", 1)[1]
        #     # CAMBIAMOS A RECURSO MONTADO PARA PODER USAR CHECKSUM
        #     carpeta = traducir_a_ruta_local_montada(origen, mounts_activos)
        #     if es_directorio_rclone(origen, rclone_config_path):
        #         # Origen es una carpeta remota
        #         # CAMBIAMOS A RECURSO MONTADO PARA PODER USAR CHECKSUM
        #         # carpeta = remote + ":" + ruta_local.rstrip("/")
        #         # carpeta = mounts_activos.get(perfil_rclone, {}).get(ruta_local.rstrip("/"), origen)
        #         fichero = None
        #     else:
        #         # Origen es un archivo remoto
        #         ruta_local_path = Path(ruta_local)
        #         fichero = ruta_local_path.name
        #         # CAMBIAMOS A RECURSO MONTADO PARA PODER USAR CHECKSUM
        #         # carpeta = remote + ":" + str(ruta_local_path.parent)
        #         # carpeta = mounts_activos.get(perfil_rclone, {}).get(str(ruta_local_path.parent), origen)
        # else:
        #     # Origen local
        #     if os.path.isfile(origen):
        #         # Origen es un archivo local
        #         ruta_local_path = Path(origen)
        #         fichero = ruta_local_path.name
        #         carpeta = str(ruta_local_path.parent)
        #     else:
        #         # Origen es una carpeta local
        #         carpeta = origen
        #         fichero = None

        # if fichero:
        #     extension_comando = ["--include", f"{fichero}", "--no-traverse"]
        #     origen = carpeta
        # else:
        #     extension_comando = []

        # boton_check.config(state="disabled")
        # log_text.insert(tk.END, f"\n🔍 Verificando con: rclone check {origen} {perfil_rclone}:/{destino}\n\n")
        
        # def ejecutar_rclone_check():
        #     comando = [
        #         "rclone", "check",
        #         origen,
        #         f"{perfil_rclone}:/{destino}",
        #         "--config", rclone_config_path,
        #         "--progress",
        #         "--stats=1s"
        #     ]

        #     if fichero:
        #         # Archivo individual → NO usamos excludes ni filtros incompatibles
        #         comando += [
        #             "--checksum",
        #             "--one-way"
        #         ]
        #     else:
        #         # Carpeta → se permiten excludes y filtros completos
        #         comando += [
        #             "--one-way",
        #             "--combined",
        #             "--checksum",
        #             "--check-first",
        #             "--copy-links",
        #             "--exclude", "/.DS_Store",
        #             "--exclude", "**/.DS_Store",
        #             "--exclude", "/Thumbs.db",
        #             "--exclude", "**/Thumbs.db",
        #             "--exclude", ".snapshots/**",
        #             "--exclude", "**/.snapshots/**"
        #         ]
            
        #     # Añadir flags adicionales (parseados con shlex para preservar comillas)
        #     comando.extend(extension_comando)
        #     comando.extend(flags_adicionales)
        #     # if flags_adicionales:
        #     #     comando.extend(shlex.split(flags_adicionales))

        #     # return comando

        # # def ejecutar_rclone_check():
        #     try:
        #         # comando = [
        #         #     "rclone", "check",
        #         #     origen,
        #         #     f"{perfil_rclone}:/{destino}",
        #         #     "--config", rclone_config_path,
        #         #     "--one-way",
        #         #     # "--checkers=8",
        #         #     "--combined",
        #         #     "--checksum",
        #         #     "--check-first",
        #         #     "--copy-links",
        #         #     "--exclude", "/.DS_Store",
        #         #     "--exclude", "**/.DS_Store",
        #         #     "--exclude", "/Thumbs.db",
        #         #     "--exclude", "**/Thumbs.db",
        #         #     "--exclude", ".snapshots/**",
        #         #     "--exclude", "**/.snapshots/**",
        #         #     "--progress",
        #         #     "--stats=1s"
        #         # ]

        #         # comando.extend(flags_adicionales)
        #         # Mostrar el comando final en la GUI
        #         comando_str = " ".join(shlex.quote(arg) for arg in comando)
        #         log_queue.put(f"\n🧾 Comando completo:\n{comando_str}\n\n")

        #         proceso = subprocess.Popen(
        #             comando,
        #             stdout=subprocess.PIPE,
        #             stderr=subprocess.STDOUT,
        #             universal_newlines=True
        #         )
        #         for linea in proceso.stdout:
        #             log_queue.put(linea)
        #         proceso.wait()
        #         if proceso.returncode == 0:
        #             log_queue.put("\n✅ Verificación OK: no se encontraron diferencias.\n")
        #         else:
        #             log_queue.put(f"\n⚠️ Verificación finalizó con código {proceso.returncode}. Revisa posibles diferencias.")
        #     except Exception as e:
        #         log_queue.put(f"\n❌ Excepción durante verificación: {str(e)}")
        #     finally:
        #         log_queue.put(("enable_button", "check"))

        # threading.Thread(target=ejecutar_rclone_check, daemon=True).start()

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

        # if fichero:
        #     extension_comando = ["--include", f"{fichero}", "--no-traverse"]
        #     origen = origen_ajustado
        # else:
        #     extension_comando = []
        origen = origen_ajustado

        # --- Lógica de verificación ---
        boton_check.config(state="disabled")
        log_text.insert(tk.END, f"\n🔍 Verifying with: rclone check {origen} {perfil_rclone}:/{destino}\n\n")

        def ejecutar_rclone_check():
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
                    "--checksum",
                    "--one-way",
                    "--copy-links"
                ]
            else:
                comando += [
                    "--one-way",
                    "--combined",
                    "--checksum",
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
                if platform.system() == "Linux":
                    subprocess.run(["fusermount", "-u", full_path], check=True)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["umount", full_path], check=True)
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
    procesar_queue()
    ventana.wait_window()
    




def main():
    EXCEPCION_FILERS = ["filer12-svm-vm"]
    # Variable global
    mounts_activos = []  # Cada entrada será un dict con keys: mount_path, remote_name, remote_subpath

    
    # Configuración inicial y obtención de shares accesibles desde NetApp
    root = tk.Tk()
    # root = ThemedTk(theme="plastik")
    root.title("MinIO Rclone Launcher")
    root.geometry("1x1+0+0")  # Ventana invisible de 1x1 píxeles
    root.overrideredirect(True)  # Sin bordes, completamente invisible

    # Aseguramos el desmontaje de shares al salir
    atexit.register(lambda: desmontar_todos_los_shares(usuario_actual))

    # Obtener credenciales LDAP del usuario
    credenciales_smb = pedir_credenciales_smb(root, getpass.getuser(), False)
    print(f"SMB credentials obtained. User: {credenciales_smb['usuario']}")
    
    # Obtener grupos LDAP del usuario
    grupos_ldap = get_ldap_groups()
    print("User's LDAP groups:", grupos_ldap)
    # Comprobar si el usuario pertenece al grupo its
    if "its" in grupos_ldap:
        pregunta_admin = messagebox.askyesno("Confirmation", "Do you want to use ITS administrator privileges for CIFS shares?")
        if not pregunta_admin:
            usuario_actual = getpass.getuser()
            es_admin_its = False

        else:
            usuario_actual = "admin_" + getpass.getuser()
            grupos_ldap.append("Domain Admins")
            es_admin_its = True

            credenciales_admin = pedir_credenciales_smb(root, usuario_actual, True)
            print(f"SMB credentials obtained. User: {credenciales_smb['usuario']}")

    else:
        es_admin_its = False
    print("Is ITS admin user?", es_admin_its)
    # """
    # Retrieve login credentials for netapp from AWS Secrets Manager
    # """
    # login_secret = json.loads(get_secret("netapp-analitycs-login"))
    # netapp_username = login_secret.get("username")
    # netapp_password = login_secret.get("password")
    
    # Obtener perfiles configurados en rclone
    perfiles_configurados = obtener_perfiles_rclone_config()
    print("Configured rclone profiles:", perfiles_configurados)

    shares_no_configurados = []

    # Obtener shares accesibles desde NetApp
    shares_accesibles = obtener_shares_accesibles(grupos_ldap, credenciales_smb["usuario"], credenciales_smb["password"], usuario_actual, EXCEPCION_FILERS)
    print("Shares accessible from NetApp:")
    for share in shares_accesibles:
        print(f"- {share['name']} (Path: {share['path']}), Host: {share['host']}")
        nombre_perfil_esperado = f"{usuario_actual}-smbmount-{share['host']}"
        # Comprobamos si tenemos perfiles para los shares, si no, pedimos credenciales SMB y los creamos
        if nombre_perfil_esperado not in perfiles_configurados:
            shares_no_configurados.append(share["name"])
    
    # Si hay shares sin configurar, pedimos credenciales SMB y los creamos
    if shares_no_configurados:
        if not credenciales_smb:
            messagebox.showerror("Error", "No SMB credentials provided. Exiting.")
            sys.exit("No SMB credentials provided. Exiting.")

        for share in shares_accesibles:
            nombre_perfil_esperado = f"{usuario_actual}-smbmount-{share['host']}"
            if nombre_perfil_esperado not in perfiles_configurados:
                if es_admin_its:
                    crear_perfil_rclone_smb(
                        nombre_perfil=nombre_perfil_esperado,
                        host=share["host"],
                        path=share["name"],
                        username=credenciales_admin["usuario"],
                        password=credenciales_admin["password"]
                    )
                else:
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
    
    # # Montamos todos los shares SMB configurados
    # for share in shares_accesibles:
    #     nombre_perfil_esperado = f"{getpass.getuser()}-smbmount-{share['host']}"
    #     punto_montaje = os.path.expanduser(f"~/cifs-mount/{getpass.getuser()}/{share['name']}")
    #     if nombre_perfil_esperado in perfiles_configurados:
    #         montar_share_rclone(nombre_perfil_esperado, share["name"], punto_montaje)
    #     else:
    #         print(f"⚠️ Perfil rclone no encontrado para share {share['name']}: {nombre_perfil_esperado}, no se montará.")
    
    
    # exit(0) 






    def iniciar_aplicacion():
        seleccionar_shares_montar(root, shares_accesibles, usuario_actual, mounts_activos, es_admin_its)
        
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
            # credenciales = pedir_credenciales_irb(root, usuario_actual)
            # username = credenciales["username"]
            # password = credenciales["password"]
            # credentials = minio_functions.get_credentials(endpoint, username, password, int(respuesta['dias']) * 86400)
            credentials = minio_functions.get_credentials(endpoint, credenciales_smb["usuario"], credenciales_smb["password"], int(respuesta['dias']) * 86400)

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