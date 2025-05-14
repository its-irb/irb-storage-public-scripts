"""

"""

import requests
from xml.etree import ElementTree as etree
from pathlib import Path
import os
import re
import sys
from sys import platform
import subprocess
import configparser
from datetime import datetime, timezone
import jwt
import shutil
from tkinter import messagebox, Tk

# Diccionario de servidores y sus variantes de red
MINIO_SERVERS = {
    "minio-gordo": {
        "IRB": {
            "profile": "minio-gordo",
            "endpoint": "https://minio-gordo.irbbarcelona.pcb.ub.es:9000"
        },
        "HPC": {
            "profile": "minio-gordo-hpc",
            "endpoint": "https://minio-gordo.hpc.irbbarcelona.pcb.ub.es:9000"
        }
    },
    "minio-bbg": {
        "IRB": {
            "profile": "minio-bbg",
            "endpoint": "http://irbminio.irbbarcelona.pcb.ub.es:9000"
        },
        "HPC": {
            "profile": "minio-bbg-hpc",
            "endpoint": "http://irbminio.hpc.irbbarcelona.pcb.ub.es:9000"
        }
    }
}

REPO = "its-irb/irb-storage-public-scripts" 

try:
    from version import __version__
except ImportError:
    __version__ = "unknown"

def check_version():
    print(f"Version de este ejecutable: {__version__}")
    try:
        url = f"https://api.github.com/repos/{REPO}/releases/latest"
        print(f"Comprobando la última versión de {REPO}... en url: {url}")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            latest_tag = response.json().get("tag_name", "")
            # print(f"\nÚltima versión disponbile: {latest_tag}")
            if latest_tag and latest_tag.strip("v") > __version__:
                print(f"\n🚀 Hay una nueva versión disponible: {latest_tag}")
                print(f"👉 Descárgala aquí: https://github.com/{REPO}/releases/latest\n")
                # Si estás en macOS, muestra una alerta
                if platform == "darwin":
                    alert_gui(latest_tag)
                # Si estás en Windows, muestra un mensaje de error
                elif platform == "win32":
                    from tkinter import messagebox
                    messagebox.showerror("Nueva versión disponible", f"Versión {latest_tag} ya está disponible.\nDescárgala aqui: https://github.com/{REPO}/releases/latest.")
            elif latest_tag and latest_tag.strip("v") == __version__:
                print(f"✅ Estás usando la última versión: {latest_tag}")
        else:
            print("⚠️ No se pudo comprobar la última versión.")
    except Exception as e:
        print(f"⚠️ Error verificando actualización: {e}")

def alert_gui(version):
    root = Tk()
    root.withdraw()  # Oculta ventana principal
    messagebox.showinfo("Nueva versión disponible", f"Versión {version} ya está disponible.\nDescárgala desde GitHub.")

def get_rclone_paths(servidor_s3_rcloneconfig):
    user_home_dir_path = str(Path.home())
    if platform == "linux" or platform == "linux2":
        # linux
        print("linux")
        rclone_config_directory_path = user_home_dir_path + "/.config/rclone"
        rclone_config_file_path = rclone_config_directory_path + "/rclone.conf"
        mount_point_path = user_home_dir_path + "/" + servidor_s3_rcloneconfig + "-"
        print(rclone_config_file_path)
    elif platform == "darwin":
        # OS X
        print("OS X")
        rclone_config_directory_path = user_home_dir_path + "/.config/rclone"
        rclone_config_file_path = rclone_config_directory_path + "/rclone.conf"
        mount_point_path = user_home_dir_path + "/" + servidor_s3_rcloneconfig + "-"
        print(rclone_config_file_path)
    elif platform == "win32":
        print("Windows...")
        # Windows...
        rclone_config_directory_path = user_home_dir_path + "\\AppData\\Roaming\\rclone"
        rclone_config_file_path = rclone_config_directory_path + "\\rclone.conf"
        mount_point_path = user_home_dir_path + "\\Documents\\" + servidor_s3_rcloneconfig + "-"
        print(rclone_config_file_path)
    return rclone_config_directory_path, rclone_config_file_path, mount_point_path


def get_credentials(endpoint, username, password, durationseconds = 86400):
    params = {
        "Action": "AssumeRoleWithLDAPIdentity",
        "LDAPUsername": username,
        "LDAPPassword": password,
        "DurationSeconds": durationseconds,
        "Version": "2011-06-15",
    }
    r = requests.post(endpoint, params=params)
    credentials = {}
    content = r.content
    root = etree.fromstring(content)
    ns = {"ns": "https://sts.amazonaws.com/doc/2011-06-15/"}
    et = root.find("ns:AssumeRoleWithLDAPIdentityResult/ns:Credentials", ns)
    if(et is None):
        print("ERROR: Invalid LDAP credentials")
        return None
    else:
        for el in et:
            _, _, tag = el.tag.rpartition("}")
            credentials[tag] = el.text
        return credentials

def configure_rclone(aws_access_key_id, aws_secret_access_key, aws_session_token, endpoint, profilename="minio-gordo"):
    # servidor_s3_rcloneconfig = "irb-minio"
    rclone_config_directory_path, rclone_config_file_path, mount_point_path = get_rclone_paths(profilename)
    # print(rclone_config_file_path)
    if (os.path.isfile(rclone_config_file_path)):
        print("Rclone config file exist")
        with open(rclone_config_file_path, "r") as file:
            full_config_file_string = file.read()
        file.close()
    else:
        print("Rclone config file does not exist")

        # comprobamos si existe el directorio de configuracion de rclone 
        isExist = os.path.exists(rclone_config_directory_path)
        if not isExist:
            # y lo creamos en caso que no exista
            os.makedirs(rclone_config_directory_path)
            print("The new directory is created!")

        full_config_file_string = ""
        # creamos el fichero de configuracion de rclone
        open(rclone_config_file_path, "a").close()

    if re.search(re.escape("[" + profilename + "]"), full_config_file_string):
        print("Updating rclone config file.")
        # obtenfo el string posterior a la cabecera de configuracion para nuestro server
        res = full_config_file_string.split("[" + profilename + "]", 1)
        resto_config_file_string = res[1]
        # print(resto_config_file_string)
        resto_config_file_string = re.sub('endpoint = (.+)',"endpoint = " + endpoint,resto_config_file_string, 1)
        resto_config_file_string = re.sub('access_key_id = (.+)',"access_key_id = " + aws_access_key_id,resto_config_file_string, 1)
        resto_config_file_string = re.sub('secret_access_key = (.+)',"secret_access_key = " + aws_secret_access_key,resto_config_file_string, 1)
        resto_config_file_string = re.sub('session_token = (.+)',"session_token = " + aws_session_token,resto_config_file_string, 1)
        # print(resto_config_file_string)
        full_config_file_string_editado = res[0] + "[" + profilename + "]" + resto_config_file_string
        # print(full_config_file_string_editado)
    else:
        print("Creating profile in rclone config file.")
        
        resto_config_file_string = "\n[" + profilename + "]\ntype = s3\nprovider = Minio\nendpoint = " + endpoint + "\nacl = bucket-owner-full-control\nenv_auth = false\n"
        # print(resto_config_file_string)
        resto_config_file_string = resto_config_file_string + "access_key_id = " + aws_access_key_id + "\n"
        resto_config_file_string = resto_config_file_string + "secret_access_key = " + aws_secret_access_key + "\n"
        resto_config_file_string = resto_config_file_string + "session_token = " + aws_session_token + "\n"
        # print(resto_config_file_string)
        full_config_file_string_editado = full_config_file_string + resto_config_file_string
        # print(full_config_file_string_editado)
    f = open(rclone_config_file_path, "w")
    f.write(full_config_file_string_editado)
    f.close()

# Lanzo proceso de rclone para el montado del bucket
def mount_rclone_S3_bucket_to_folder(mount_point_folder, servidor_s3_rcloneconfig, bucket):
    print(f"Mounting {servidor_s3_rcloneconfig}:{bucket} to {mount_point_folder}")
    subprocess.Popen(["rclone", "mount" ,servidor_s3_rcloneconfig + ":" + bucket, mount_point_folder, "--allow-non-empty", "--read-only"])

def open_file(path):
    if platform == "win32":
        FILEBROWSER_PATH = os.path.join(os.getenv('WINDIR'), 'explorer.exe')

        path = os.path.normpath(path + "\\")
        print(path)
        subprocess.run([FILEBROWSER_PATH, path])
    elif platform == "darwin":
        subprocess.Popen(["open", path])
    # elif platform == "linux" or platform == "linux2":
    #     subprocess.Popen(["xdg-open", path])

def is_brew_installed():
    """
    Comprueba si Homebrew (brew) está instalado en el sistema.
    
    :return: True si está instalado, False en caso contrario.
    """
    return shutil.which("brew") is not None

def check_rclone_installation():
    # Compruebo si está instalado rclone y si está en el path ###########################################################
    try:
        subprocess.check_call(["rclone", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as error:
        print("rclone is not installed")
        if platform == "linux" or platform == "linux2":
            # linux
            print("linux")
            sys.exit("Linux is not supported yet. Please install rclone and fuse-t manually")
        elif platform == "darwin":
            if not is_brew_installed():
                from tkinter import messagebox
                messagebox.showerror("Rclone is not installed", "❌ Rclone is not installed, and Homebrew is not installed also. Please, install hombrew and run again this program to install rclone on your computer. To install homebrew, follow the guide at https://brew.sh/")
                sys.exit("❌ Rclone is not installed, and Homebrew is not installed also. Please, install hombrew and run again this program to install rclone on your computer. To install homebrew, follow the guide at https://brew.sh/")
            # OS X
            print("OS X")
            # instalamos fuse-t
            print("brew tap macos-fuse-t/homebrew-cask")
            call = os.system("brew tap macos-fuse-t/homebrew-cask")
            print("brew install fuse-t")
            call = os.system("brew install fuse-t")
            # instalamos rclone
            print("sudo -v ; curl https://rclone.org/install.sh | sudo bash")
            call = os.system("sudo -v ; curl https://rclone.org/install.sh | sudo bash")
        elif platform == "win32":
            print("Windows...")
            from tkinter import messagebox
            messagebox.showerror("Rclone.exe not found", "Download, uncompress zip file and put rclone.exe in the same folder as this executable file. Download rclone from https://rclone.org/downloads/.\r Also download and install winsfp from https://winfsp.dev/rel/")
            sys.exit("Download, uncompress zip file and put rclone.exe in the same folder as this executable file. Download rclone from https://rclone.org/downloads/.\r Also download and install winsfp from https://winfsp.dev/rel/")
            # Windows...
    else:
        print("Rclone is installed")

def get_rclone_session_token(profile_name, config_path=None):
    if platform == "darwin" and not config_path:
        # macOS
        config_path = os.path.expanduser("~/.config/rclone/rclone.conf")
    elif platform == "win32" and not config_path:
        # Windows
        config_path = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "rclone", "rclone.conf")
    elif platform == "linux" and not config_path:
        # Linux
        config_path = os.path.expanduser("~/.config/rclone/rclone.conf")
    
    # Si no existe el archivo, devolver cadena vacía
    if not os.path.isfile(config_path):
        print(f"El fichero de configuracion de rclone {config_path} no existe")
        return ""

    config = configparser.ConfigParser()
    config.read(config_path)

    if profile_name not in config:
        print(f"Perfil '{profile_name}' no encontrado en {config_path}")
        return ""

    section = config[profile_name]
    session_token = section.get("session_token")
      
    return session_token

def get_expiration_from_session_token(session_token):
    try:
        # Decodifica sin verificar la firma (solo queremos ver el payload)
        payload = jwt.decode(session_token, options={"verify_signature": False})
        exp_timestamp = payload.get("exp")
        if not exp_timestamp:
            print("El token no contiene 'exp'.")
            return None

        exp_time = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = exp_time - now

        print(f"Expira en: {remaining} ({exp_time})")
        return remaining
    except Exception as e:
        print(f"Error decodificando token: {e}")
        return None
    
def launch_rclonebrowser():
    # system = platform.system()

    if platform == "darwin":  # macOS
        app_path = "/Applications/Rclone Browser.app"
        if os.path.exists(app_path):
            subprocess.Popen(["open", "-a", app_path])
        else:
            show_error("RcloneBrowser not installed in /Applications. Please, install RcloneBrowser from https://github.com/kapitainsky/RcloneBrowser/releases")
    elif platform == "win32":
        exe_path = r"C:\Program Files\Rclone Browser\RcloneBrowser.exe"
        if os.path.exists(exe_path):
            subprocess.Popen([exe_path], shell=True)
        else:
            show_error("RcloneBrowser not installed in 'C:\\Program Files\\Rclone Browser\\'. Please, install RcloneBrowser from https://github.com/kapitainsky/RcloneBrowser/releases")
    else:
        show_error("Sistema operativo no compatible con este lanzador automático.")

def show_error(message):
    from tkinter import messagebox
    messagebox.showerror("Error", message)
    sys.exit(1)