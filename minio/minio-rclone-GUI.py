"""

"""
import minio_functions

import tkinter as tk
from tkinter import ttk
import boto3
import getpass
import sys
from sys import platform
import tkinter as tk
from tkinter import ttk
from minio_functions import MINIO_SERVERS

def seleccionar_servidor_minio():
    resultado = {"servidor": None, "perfil": None, "endpoint": None}

    def continuar():
        servidor = servidor_var.get()
        red = red_var.get()
        perfil = MINIO_SERVERS[servidor][red]["profile"]
        endpoint = MINIO_SERVERS[servidor][red]["endpoint"]
        resultado.update({"servidor": servidor, "perfil": perfil, "endpoint": endpoint})
        ventana.destroy()

    ventana = tk.Tk()
    ventana.title("Seleccionar servidor MinIO")
    ventana.geometry("400x180")
    ventana.eval('tk::PlaceWindow . center')

    # Lista de servidores
    ttk.Label(ventana, text="Selecciona el servidor MinIO:").pack(pady=(10, 5))
    servidor_var = tk.StringVar(value=list(MINIO_SERVERS.keys())[0])
    servidor_menu = ttk.Combobox(ventana, textvariable=servidor_var, values=list(MINIO_SERVERS.keys()), state="readonly", width=30)
    servidor_menu.pack(pady=(0, 10))

    # Radios para red IRB / HPC
    ttk.Label(ventana, text="Selecciona la red desde la que accedes:").pack()
    red_var = tk.StringVar(value="IRB")
    frame_radios = tk.Frame(ventana)
    frame_radios.pack(pady=5)
    tk.Radiobutton(frame_radios, text="Red IRB", variable=red_var, value="IRB").pack(side=tk.LEFT, padx=10)
    tk.Radiobutton(frame_radios, text="Red HPC Cluster", variable=red_var, value="HPC").pack(side=tk.LEFT, padx=10)

    # Botón continuar
    ttk.Button(ventana, text="Continuar", command=continuar).pack(pady=15)

    ventana.mainloop()
    return resultado

def prompt_credenciales_renovar(tiempo_restante: str):
    print(tiempo_restante)
    resultado = {"accion": None, "dias": None}

    def mantener():
        resultado["accion"] = "mantener"
        root.destroy()

    def renovar():
        resultado["accion"] = "renovar"
        resultado["dias"] = int(dias_var.get())
        root.destroy()

    # Crear ventana
    root = tk.Tk()
    root.title("Minio S3 credentials renewal")
    root.geometry("400x200")
    root.eval('tk::PlaceWindow . center')

    # Mostrar tiempo restante
    label = tk.Label(root, text="Remaining lifespan for current credentials:", font=("Arial", 12))
    label.pack(pady=(15, 5))

    texto = tk.Label(root, text=tiempo_restante, fg="blue", font=("Arial", 10, "bold"))
    texto.pack(pady=(0, 10))

    # Desplegable para días
    frame_dropdown = tk.Frame(root)
    frame_dropdown.pack(pady=(5, 10))

    tk.Label(frame_dropdown, text="Select lifespan for new STS credentials(days):").pack(side=tk.LEFT, padx=5)

    dias_var = tk.StringVar(value="7")
    desplegable = ttk.Combobox(frame_dropdown, textvariable=dias_var, values=[str(i) for i in range(1, 31)], width=4, state="readonly")
    desplegable.pack(side=tk.LEFT)

    # Botones
    frame_botones = tk.Frame(root)
    frame_botones.pack(pady=10)

    boton_mantener = tk.Button(frame_botones, text="Keep current", width=12, command=mantener)
    boton_mantener.grid(row=0, column=0, padx=10)

    boton_renovar = tk.Button(frame_botones, text="Renew", width=12, command=renovar)
    boton_renovar.grid(row=0, column=1, padx=10)

    root.mainloop()
    return resultado

# Function to validate the login
def validate_login():
    global username, password
    username = username_entry.get()
    password = password_entry.get()
    parent.quit()

minio_functions.check_version()

eleccion = seleccionar_servidor_minio()
servidor_s3_rcloneconfig = eleccion["perfil"]
endpoint = eleccion["endpoint"]

buckets_accesibles = []
print(servidor_s3_rcloneconfig)

rclone_config_directory_path, rclone_config_file_path, mount_point_path = minio_functions.get_rclone_paths(servidor_s3_rcloneconfig)

# comprobamos si rclone está instalado y si no lo está lo instalamos (solo macos)
minio_functions.check_rclone_installation()

current_session_token = minio_functions.get_rclone_session_token(servidor_s3_rcloneconfig)
if current_session_token == "":
    print("No hay credenciales de rclone configuradas.")
    current_expiration_time = "There are not current credentials configured, let's configure it now."
    
else:
    current_expiration_time = minio_functions.get_expiration_from_session_token(current_session_token)

respuesta = prompt_credenciales_renovar(current_expiration_time)
if respuesta["accion"] == "renovar":
    print(f"Usuario eligió renovar por {respuesta['dias']} días.")

    username = ""
    password = ""

    # Create the main window
    parent = tk.Tk()
    parent.title("Configure IRB Minio S3 to use with rclone")

    # Create and place the username label and entry
    username_label = tk.Label(parent, text="Type your IRB username:")
    username_label.pack()

    username_entry = tk.Entry(parent)
    username_entry.insert(0, getpass.getuser())
    username_entry.pack()

    # Create and place the password label and entry
    password_label = tk.Label(parent, text="Type your IRB Password:")
    password_label.pack()

    password_entry = tk.Entry(parent, show="*")  # Show asterisks for password
    password_entry.pack()

    # Create and place the login button
    login_button = tk.Button(parent, text="Set new Rclone credentials", command=validate_login)
    login_button.pack()

    # Give focus to username
    password_entry.focus_set()

    # Bind return key to submit button
    def func(event):
        print("You hit return.")
        validate_login()
    parent.bind('<Return>', func)
    parent.bind('<KP_Enter>', func)

    #Set desired Tkinter Window Size.
    parent.geometry("350x150")

    #Same size will be defined in variable for center screen in Tk_Width and Tk_height
    Tk_Width = 350
    Tk_Height = 150

    #calculate coordination of screen and window form
    x_Left = int(parent.winfo_screenwidth()/2 - Tk_Width/2)
    y_Top = int(parent.winfo_screenheight()/2 - Tk_Height/2)

    # Write following format for center screen
    parent.geometry("+{}+{}".format(x_Left, y_Top))

    # Start the Tkinter event loop
    parent.mainloop()
    parent.destroy()

    # durationseconds = 3600 * 24
    # endpoint = "http://irbminio.irbbarcelona.pcb.ub.es:9000"

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

minio_functions.launch_rclonebrowser()