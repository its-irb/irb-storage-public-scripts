"""

"""
import minio_functions

import tkinter as tk
from tkinter import ttk, scrolledtext
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


# Function to validate the login
# def validate_login():
#     global username, password
#     username = username_entry.get()
#     password = password_entry.get()
#     parent.quit()

def seleccionar_servidor_minio(root):
    print("Seleccionar servidor MinIO") 
    resultado = {"servidor": None, "perfil": None, "endpoint": None}

    ventana = tk.Toplevel(root)
    ventana.title("Seleccionar servidor MinIO")
    ventana.geometry("400x300")

    ancho = ventana.winfo_reqwidth()
    alto = ventana.winfo_reqheight()
    x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    ventana.geometry(f'+{x}+{y}')

    ttk.Label(ventana, text="Selecciona el servidor MinIO:").pack(pady=(10, 5))
    servidor_var = tk.StringVar(value=list(MINIO_SERVERS.keys())[0])
    servidor_menu = ttk.Combobox(ventana, textvariable=servidor_var, values=list(MINIO_SERVERS.keys()), state="readonly", width=30)
    servidor_menu.pack(pady=(0, 10))

    ttk.Label(ventana, text="Selecciona la red desde la que accedes:").pack()
    red_var = tk.StringVar(value="IRB")
    frame_radios = tk.Frame(ventana)
    frame_radios.pack(pady=5)
    tk.Radiobutton(frame_radios, text="Red IRB", variable=red_var, value="IRB").pack(side=tk.LEFT, padx=10)
    tk.Radiobutton(frame_radios, text="Red HPC Cluster", variable=red_var, value="HPC").pack(side=tk.LEFT, padx=10)

    def continuar():
        servidor = servidor_var.get()
        red = red_var.get()
        perfil = MINIO_SERVERS[servidor][red]["profile"]
        endpoint = MINIO_SERVERS[servidor][red]["endpoint"]
        resultado.update({"servidor": servidor, "perfil": perfil, "endpoint": endpoint})
        ventana.destroy()

    ttk.Button(ventana, text="Continuar", command=continuar).pack(pady=15)

    # Comprobar si hay una nueva versión disponible
    if getattr(sys, 'frozen', False):  # Si es un ejecutable PyInstaller
        ultima_version = minio_functions.check_update_version()
        if ultima_version:
            frame_update = ttk.Frame(ventana)
            frame_update.pack(pady=(10, 0))
            ttk.Label(frame_update, text=f"🚀 Nueva versión disponible: {ultima_version}", foreground="green").pack()
            ttk.Button(
                frame_update,
                text="Actualizar a última versión",
                command=lambda: minio_functions.actualizar_y_reiniciar(ventana, "minio-rclone-copy-GUI")
            ).pack(pady=(5, 10))

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
    ventana.geometry("400x200")

    ancho = ventana.winfo_reqwidth()
    alto = ventana.winfo_reqheight()
    x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    ventana.geometry(f'+{x}+{y}')

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

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()         # <--- Asegura que esté visible
    ventana.update_idletasks()  # <--- Fuerza actualización visual
    ventana.lift()              # <--- Eleva al frente
    ventana.focus_force()       # <--- Da foco real
    ventana.wait_window()
    return resultado

def pedir_credenciales_irb(root):
    resultado = {"username": None, "password": None}
    ventana = tk.Toplevel(root)
    ventana.title("Configure IRB Minio S3 to use with rclone")
    ventana.geometry("350x150")

    x_Left = int(ventana.winfo_screenwidth() / 2 - 350 / 2)
    y_Top = int(ventana.winfo_screenheight() / 2 - 150 / 2)
    ventana.geometry(f"+{x_Left}+{y_Top}")

    ttk.Label(ventana, text="Type your IRB username:").pack(pady=(10, 0))
    username_var = tk.StringVar(value=getpass.getuser())
    username_entry = ttk.Entry(ventana, textvariable=username_var)
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

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()         # <--- Asegura que esté visible
    ventana.update_idletasks()  # <--- Fuerza actualización visual
    ventana.lift()              # <--- Eleva al frente
    ventana.focus_force()       # <--- Da foco real
    ventana.wait_window()
    return resultado

def abrir_interfaz_copia(root, perfil_rclone):
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    import subprocess
    import threading
    import queue
    import minio_functions
    import sys

    _, rclone_config_path, _ = minio_functions.get_rclone_paths(perfil_rclone)

    ventana = tk.Toplevel(root)
    ventana.title("Copiar y verificar datos con rclone")
    ventana.geometry("800x580")
    ventana.update_idletasks()
    x = (ventana.winfo_screenwidth() // 2) - (ventana.winfo_width() // 2)
    y = (ventana.winfo_screenheight() // 2) - (ventana.winfo_height() // 2)
    ventana.geometry(f"+{x}+{y}")

    frame_metadata = ttk.LabelFrame(ventana, text="Metadata to attach to the copied objects")
    frame_metadata.pack(padx=10, pady=(15, 5), fill=tk.X)

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
        ttk.Label(frame_metadata, text=label_text).grid(row=idx, column=0, sticky=tk.W, padx=5, pady=2)
        entry = ttk.Entry(frame_metadata, width=50)
        entry.grid(row=idx, column=1, padx=5, pady=2, sticky=tk.W)
        metadata_vars[var_name] = entry

    ttk.Label(ventana, text="Ruta origen (local o perfil rclone):").pack(pady=(15, 0))

    frame_origen = ttk.Frame(ventana)
    frame_origen.pack(pady=(0, 10))

    entrada_origen = ttk.Entry(frame_origen, width=60)
    entrada_origen.pack(side=tk.LEFT, padx=(0, 5))

    def seleccionar_archivo():
        ruta = filedialog.askopenfilename(title="Selecciona archivo de origen")
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)

    def seleccionar_carpeta():
        ruta = filedialog.askdirectory(title="Selecciona carpeta de origen")
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)

    boton_archivo = ttk.Button(frame_origen, text="📄 Archivo", command=seleccionar_archivo)
    boton_archivo.pack(side=tk.LEFT, padx=(0, 5))

    boton_carpeta = ttk.Button(frame_origen, text="📁 Carpeta", command=seleccionar_carpeta)
    boton_carpeta.pack(side=tk.LEFT)

    ttk.Label(ventana, text=f"Ruta destino (bucket en perfil {perfil_rclone}):").pack(pady=(5, 0))
    entrada_destino = ttk.Entry(ventana, width=86)
    entrada_destino.pack(pady=(0, 10))

    frame_botones = ttk.Frame(ventana)
    frame_botones.pack(pady=(15, 0))

    boton_copiar = ttk.Button(frame_botones, text="Copiar")
    boton_copiar.grid(row=0, column=0, padx=10)

    boton_check = ttk.Button(frame_botones, text="Verificar copia", state="disabled")
    boton_check.grid(row=0, column=1, padx=10)

    boton_montar = ttk.Button(frame_botones, text="Montar destino")
    boton_montar.grid(row=0, column=2, padx=10)

    def lanzar_montaje():
        ruta_destino = entrada_destino.get().strip()
        if not ruta_destino:
            minio_functions.alert_gui("Debes indicar una ruta de destino para montar.")
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

        if not origen or not destino:
            minio_functions.alert_gui("Debes introducir tanto origen como destino.")
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
        log_text.delete("1.0", tk.END)
        log_text.insert(tk.END, f"Ejecutando: rclone copy {origen} {perfil_rclone}:/{destino}\n")

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
                    "--transfers=4",
                    "--checkers=8",
                    "--header-upload", header_value
                ]
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
                    log_queue.put("\n✅ Copia finalizada correctamente.\n")
                    log_queue.put(("enable_button", "check"))
                else:
                    log_queue.put(f"\n❌ Error en la copia. Código: {proceso.returncode}")
            except Exception as e:
                log_queue.put(f"\n❌ Excepción al ejecutar rclone: {str(e)}")
            finally:
                log_queue.put(("enable_button", "copiar"))

        threading.Thread(target=ejecutar_rclone_copy, daemon=True).start()

    def lanzar_check():
        origen = entrada_origen.get().strip()
        destino = entrada_destino.get().strip()

        if not origen or not destino:
            minio_functions.alert_gui("Debes introducir tanto origen como destino.")
            return

        boton_check.config(state="disabled")
        log_text.insert(tk.END, f"\n🔍 Verificando con: rclone check {origen} {perfil_rclone}:/{destino}\n\n")

        def ejecutar_rclone_check():
            try:
                comando = [
                    "rclone", "check",
                    origen,
                    f"{perfil_rclone}:/{destino}",
                    "--config", rclone_config_path,
                    "--one-way",
                    "--checkers=8",
                    "--combined",
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
                    "--stats=1s"
                ]
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
                    log_queue.put("\n✅ Verificación OK: no se encontraron diferencias.\n")
                else:
                    log_queue.put(f"\n⚠️ Verificación finalizó con código {proceso.returncode}. Revisa posibles diferencias.")
            except Exception as e:
                log_queue.put(f"\n❌ Excepción durante verificación: {str(e)}")
            finally:
                log_queue.put(("enable_button", "check"))

        threading.Thread(target=ejecutar_rclone_check, daemon=True).start()

    def cerrar_aplicacion():
        log_queue.put("\n🧹 Desmontando puntos de montaje...\n")
        print("Cerrando aplicación, desmontando puntos de montaje...")
        desmontar_todos_los_mountpoints()
        log_queue.put("✅ Desmontaje completado. Cerrando aplicación.\n")
        print("Desmontaje completado. Cerrando aplicación.")
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
                log_queue.put(f"\n⚠️ No se pudo desmontar {full_path}: {str(e)}\n")
                print(f"No se pudo desmontar {full_path}: {str(e)}")

    



                    

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
    
# minio_functions.check_update_version("minio-rclone-copy-GUI")
def main():
    is_pyinstaller_executable = getattr(sys, 'frozen', False)

    root = tk.Tk()
    root.withdraw()  # Oculta la raíz
    root.update()

    eleccion = seleccionar_servidor_minio(root)
    servidor_s3_rcloneconfig = eleccion["perfil"]
    endpoint = eleccion["endpoint"]

    buckets_accesibles = []
    print("Perfil de rclone seleccionado:", servidor_s3_rcloneconfig)

    rclone_config_directory_path, rclone_config_file_path, mount_point_path = minio_functions.get_rclone_paths(servidor_s3_rcloneconfig)

    # comprobamos si rclone está instalado y si no lo está lo instalamos (solo macos)
    minio_functions.check_rclone_installation()

    current_session_token = minio_functions.get_rclone_session_token(servidor_s3_rcloneconfig)
    if current_session_token == "":
        print("No hay credenciales de rclone configuradas.")
        current_expiration_time = "There are not current credentials configured, let's configure it now."
        
    else:
        current_expiration_time = minio_functions.get_expiration_from_session_token(current_session_token)

    respuesta = prompt_credenciales_renovar(root, current_expiration_time)
    if respuesta["accion"] == "renovar":
        print(f"Usuario eligió renovar por {respuesta['dias']} días.")

        credenciales = pedir_credenciales_irb(root)
        username = credenciales["username"]
        password = credenciales["password"]

        # # Create the main window
        # # parent = tk.Tk()
        # parent = tk.Toplevel(root)
        # parent.title("Configure IRB Minio S3 to use with rclone")

        # # Create and place the username label and entry
        # username_label = tk.Label(parent, text="Type your IRB username:")
        # username_label.pack()

        # username_entry = tk.Entry(parent)
        # username_entry.insert(0, getpass.getuser())
        # username_entry.pack()

        # # Create and place the password label and entry
        # password_label = tk.Label(parent, text="Type your IRB Password:")
        # password_label.pack()

        # password_entry = tk.Entry(parent, show="*")  # Show asterisks for password
        # password_entry.pack()

        # # Create and place the login button
        # login_button = tk.Button(parent, text="Set new Rclone credentials", command=validate_login)
        # login_button.pack()

        # # Give focus to username
        # password_entry.focus_set()

        # # Bind return key to submit button
        # def func(event):
        #     print("You hit return.")
        #     validate_login()
        # parent.bind('<Return>', func)
        # parent.bind('<KP_Enter>', func)

        # #Set desired Tkinter Window Size.
        # parent.geometry("350x150")

        # #Same size will be defined in variable for center screen in Tk_Width and Tk_height
        # Tk_Width = 350
        # Tk_Height = 150

        # #calculate coordination of screen and window form
        # x_Left = int(parent.winfo_screenwidth()/2 - Tk_Width/2)
        # y_Top = int(parent.winfo_screenheight()/2 - Tk_Height/2)

        # # Write following format for center screen
        # parent.geometry("+{}+{}".format(x_Left, y_Top))

        # # Start the Tkinter event loop
        # # parent.mainloop()
        # # parent.destroy()
        # parent.grab_set()
        # parent.wait_window()

        # # durationseconds = 3600 * 24
        # # endpoint = "http://irbminio.irbbarcelona.pcb.ub.es:9000"

        credentials = minio_functions.get_credentials(endpoint, username, password, int(respuesta['dias']) * 86400)

        if credentials is None:
            from tkinter import messagebox
            messagebox.showerror("Bad Credentials", "Provided credentials are not correct, please try again or contact ITS")
            sys.exit("Provided credentials are not correct, please try again or contact ITS")
            # sys.exit(1)

        print("-------------------------------------")
        print("S3 CREDENTIALS:----------------------")
        print(f"AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
        print(f"AWS_SECRET_ACCESS_KEY={credentials['SecretAccessKey']}")
        print(f"AWS_SESSION_TOKEN={credentials['SessionToken']}")
        print(f"S3_ENDPOINT_URL={endpoint}")
        print(f"Time to expiry: {respuesta['dias']} days")
        print("-------------------------------------")
        print("BUCKETS AVAILABLE FOR THESE CREDENTIALS:")

        s3_resource = boto3.resource(
            "s3",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name="eu-west-1",
            endpoint_url=endpoint,
        )

        for bucket in s3_resource.buckets.all():
            print(bucket.name)
            buckets_accesibles.append(bucket.name)

        aws_access_key_id = credentials['AccessKeyId']
        aws_secret_access_key = credentials['SecretAccessKey']
        aws_session_token = credentials['SessionToken']

        # Configuramos rclone
        minio_functions.configure_rclone(aws_access_key_id, aws_secret_access_key, aws_session_token, endpoint, servidor_s3_rcloneconfig)
    elif respuesta["accion"] == "mantener":
        print("Usuario eligió mantener las credenciales actuales.")
    else:
        print("No se tomó ninguna acción.")

    # Finalmente abrimos la interfaz de copia en una nueva ventana
    # ventana_copia = tk.Toplevel(root)
    abrir_interfaz_copia(root, servidor_s3_rcloneconfig)

    root.mainloop()

if __name__ == "__main__":
    main()