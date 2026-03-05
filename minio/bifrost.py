from __future__ import annotations

"""
IRB MinIO Rclone Data Transfer Tool — FRONTEND
===============================================

Contiene toda la interfaz gráfica (tkinter).
No contiene lógica de negocio: delega en backend.py.

Flujo de ventanas:
  main()
    → check_and_handle_update
    → pedir_credenciales (LDAP)
    → seleccionar_shares_montar
    → seleccionar_servidor_minio
    → prompt_credenciales_renovar
    → abrir_interfaz_copia
"""

import os
import sys
import stat
import atexit
import getpass
import platform
import tempfile
import subprocess
import threading
import queue
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

import backend


# ============================================================================
# ACTUALIZACIÓN AUTOMÁTICA — GUI
# ============================================================================

def check_and_handle_update(parent_window=None) -> bool:
    """
    Comprueba si hay actualizaciones y muestra popup al usuario si las hay.

    Returns:
        True para continuar (excepto si actualizar_y_reiniciar hace os.execv/os._exit).
    """
    if not backend.should_check_for_updates():
        return True

    force_update = "--update" in sys.argv
    ultima_version = backend.check_update_version(force_update=force_update)

    if ultima_version:
        _mostrar_aviso_version_nueva(ultima_version, "bifrost", parent_window)

    return True


def _mostrar_aviso_version_nueva(ultima_version: str, file_name: str, parent_window=None) -> bool:
    """
    Muestra un popup informando de la nueva versión disponible.

    Returns:
        False si el usuario cancela, True si elige actualizar
        (en cuyo caso la función no retorna normalmente).
    """
    if parent_window:
        ventana = tk.Toplevel(parent_window)
        ventana.transient(parent_window)
        ventana.grab_set()
    else:
        _root = tk.Tk()
        _root.withdraw()
        ventana = tk.Toplevel(_root)

    ventana.title("New version available")
    ventana.geometry("450x180")

    if parent_window:
        x = parent_window.winfo_rootx() + 50
        y = parent_window.winfo_rooty() + 50
        ventana.geometry(f"+{x}+{y}")

    tk.Label(
        ventana,
        text=f"There is a new version available:\n{ultima_version}",
        font=("Arial", 11),
    ).pack(pady=(20, 10))

    resultado = {"eleccion": None}

    def actualizar_wrapper():
        try:
            _actualizar_y_reiniciar(ventana, file_name)
        except Exception as e:
            messagebox.showerror("Error", f"Could not update:\n{str(e)}")
        resultado["eleccion"] = "update"

    def cancelar():
        resultado["eleccion"] = "cancel"
        ventana.destroy()

    frame_botones = tk.Frame(ventana)
    frame_botones.pack(pady=(0, 15))
    tk.Button(frame_botones, text="Update now", command=actualizar_wrapper).pack(side=tk.LEFT, padx=5)
    tk.Button(frame_botones, text="Continue",   command=cancelar).pack(side=tk.LEFT, padx=5)

    ventana.wait_window()
    return resultado["eleccion"] != "cancel"


def _actualizar_y_reiniciar(ventana_parent, file_name: str) -> None:
    """
    Descarga el nuevo binario y reemplaza el ejecutable actual.
    En macOS/Linux hace os.execv para relanzar. En Windows lanza un .bat.
    """
    ruta_actual = os.path.abspath(sys.argv[0])
    print(f"Current executable path: {ruta_actual}")

    try:
        nueva_ruta = backend.download_new_binary(file_name)

        if sys.platform == "win32":
            _escribir_y_lanzar_updater_windows(ruta_actual, nueva_ruta)
        else:
            os.replace(nueva_ruta, ruta_actual)
            os.chmod(ruta_actual, os.stat(ruta_actual).st_mode | stat.S_IEXEC)
            messagebox.showinfo(
                "Update completed",
                "The application will now restart with the new version.",
            )
            args_relanzar = [arg for arg in sys.argv[1:] if arg != "--update"]
            os.execv(ruta_actual, [ruta_actual] + args_relanzar)

    except Exception as e:
        messagebox.showerror("Error", f"Could not update:\n{str(e)}")


def _escribir_y_lanzar_updater_windows(ruta_actual: str, nueva_ruta: str) -> None:
    """
    En Windows escribe un .bat que reemplaza el exe tras cerrarse y lo lanza.
    Termina el proceso actual con os._exit(0).
    """
    updater_code = f"""@echo off
setlocal
set "OLD_EXE={ruta_actual}"
set "NEW_EXE={nueva_ruta}"

echo Waiting for the application to close...

set /a i=0
:waitloop
if %i% geq 30 goto timeout_err
del /f "%OLD_EXE%" >nul 2>&1
if not exist "%OLD_EXE%" goto do_move
timeout /t 1 /nobreak >nul
set /a i+=1
goto waitloop

:do_move
move /y "%NEW_EXE%" "%OLD_EXE%"
if errorlevel 1 (
    echo ERROR: Could not replace the executable.
    pause
    exit /b 1
)
echo.
echo  Update completed successfully!
echo  Please reopen the application manually.
echo.
pause
exit /b 0

:timeout_err
echo ERROR: Could not delete the old executable after 30 seconds.
pause
exit /b 1
"""
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".bat", mode="w", encoding="utf-8"
    ) as f:
        f.write(updater_code)
        updater_path = f.name

    subprocess.Popen(["cmd.exe", "/c", "start", "", updater_path], shell=False)
    os._exit(0)


# ============================================================================
# COMPROBACIÓN E INSTALACIÓN DE RCLONE — GUI
# ============================================================================

def check_rclone_installation() -> None:
    """
    Comprueba si rclone está instalado. Si no lo está, intenta instalarlo
    (macOS vía Homebrew) o muestra un error con instrucciones (Windows/Linux).
    """
    if backend.detect_rclone_installed():
        print("Rclone is installed")
        return

    print("rclone is not installed")
    sistema = sys.platform

    if sistema in ("linux", "linux2"):
        sys.exit("Linux is not supported yet. Please install rclone and fuse-t manually")

    elif sistema == "darwin":
        if not backend.is_brew_installed():
            messagebox.showerror(
                "Rclone is not installed",
                "❌ Rclone is not installed, and Homebrew is not installed either. "
                "Please install Homebrew first and run this program again. "
                "Guide: https://brew.sh/",
            )
            sys.exit("❌ Rclone not found and Homebrew not available.")
        print("Installing rclone via Homebrew...")
        backend.install_rclone_macos()

    elif sistema == "win32":
        messagebox.showerror(
            "Rclone.exe not found",
            "Download, uncompress the zip file and put rclone.exe in the same folder "
            "as this executable. Download rclone from https://rclone.org/downloads/\r\n"
            "Also download and install WinFsp from https://winfsp.dev/rel/",
        )
        sys.exit(
            "Download rclone.exe and place it in the same folder as this executable."
        )


def show_error(message: str) -> None:
    """Muestra un messagebox de error y termina el proceso."""
    messagebox.showerror("Error", message)
    sys.exit(1)


def alert_gui(version: str) -> None:
    """Muestra un messagebox informando de una nueva versión."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "New version available",
        f"Version {version} is now available.\n"
        f"Download it from GitHub: https://github.com/{backend.REPO}/releases/latest.",
    )


# ============================================================================
# DIÁLOGOS GENÉRICOS
# ============================================================================

def pedir_credenciales(
    root,
    titulo: str,
    pregunta: str,
    usuario_prefijado: str | None = None,
) -> dict | None:
    """
    Diálogo para solicitar credenciales (usuario + password).

    Returns:
        {"usuario": str, "password": str} o None si se cancela.
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
        usuario  = usuario_var.get().strip()
        password = password_var.get().strip()
        if not usuario or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return
        resultado["usuario"]  = usuario
        resultado["password"] = password
        ventana.destroy()

    def cancelar():
        ventana.destroy()

    ventana.bind("<Return>", lambda e: confirmar())
    ventana.bind("<Escape>", lambda e: cancelar())

    frame_botones = ttk.Frame(ventana)
    frame_botones.pack(pady=(0, 10))
    ttk.Button(frame_botones, text="Cancel", command=cancelar).pack(side=tk.LEFT,  padx=10)
    ttk.Button(frame_botones, text="OK",     command=confirmar).pack(side=tk.RIGHT, padx=10)

    ventana.wait_window()
    return resultado if resultado["usuario"] and resultado["password"] else None


# ============================================================================
# DIÁLOGO: SELECCIÓN Y MONTAJE DE SHARES CIFS
# ============================================================================

def seleccionar_shares_montar(
    root,
    shares: list,
    usuario_actual: str,
    mounts_activos: list,
    es_admin_its: bool = False,
) -> None:
    """
    Diálogo con checkboxes para seleccionar qué shares CIFS montar.
    """
    recursos_cifs_dict = backend.construir_recursos_cifs_dict(shares, usuario_actual)

    ventana = tk.Toplevel(root)
    ventana.title(f"Select CIFS shares to mount as {usuario_actual}")
    tk.Label(ventana, text="Available SMB/CIFS resources:").pack(pady=(10, 5))

    frame_scroll = ttk.Frame(ventana)
    frame_scroll.pack(pady=(0, 10), fill="both", expand=True)

    canvas    = tk.Canvas(frame_scroll)
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
    canvas.bind("<Configure>",    ajustar_scroll)

    shares_seleccionados = {}
    filas_por_columna    = 15

    for idx, share in enumerate(shares):
        nombre_share = share["name"]
        var = tk.BooleanVar(value=False)
        shares_seleccionados[nombre_share] = var
        fila    = idx % filas_por_columna
        columna = idx // filas_por_columna
        tk.Checkbutton(frame_cifs, text=nombre_share, variable=var, anchor="w").grid(
            row=fila, column=columna, sticky="w", padx=10, pady=2
        )

    def continuar():
        seleccionados = [n for n, v in shares_seleccionados.items() if v.get()]
        fallidos = backend.montar_shares_seleccionados(
            seleccionados, recursos_cifs_dict, mounts_activos
        )
        for nombre in fallidos:
            datos = recursos_cifs_dict[nombre]
            messagebox.showerror(
                "Error mounting SMB resource",
                f"Could not mount {datos['nombre_perfil']} on {datos['punto_montaje']} "
                "after 30 seconds.",
            )
        ventana.destroy()

    def on_actualizar_credenciales_smb():
        resultado = pedir_credenciales(
            ventana, "Update SMB Credentials",
            "Enter new SMB credentials for user:", usuario_actual,
        )
        if not resultado:
            messagebox.showinfo("Cancelled", "Credentials were not updated.")
            return
        if not es_admin_its and not backend.validar_credenciales_ldap(resultado):
            messagebox.showinfo("Cancelled", "Credentials not valid.")
            return
        try:
            backend.actualizar_password_perfiles_rclone(resultado["usuario"], resultado["password"])
            messagebox.showinfo(
                "Success",
                f"Credentials have been updated for all profiles of {resultado['usuario']}.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Could not update credentials:\n{e}")

    ttk.Button(
        ventana, text="Update SMB credentials", command=on_actualizar_credenciales_smb
    ).pack(pady=(5, 0))
    ttk.Button(ventana, text="Continue", command=continuar).pack(pady=15)

    ventana.update_idletasks()
    filas_visibles  = min(filas_por_columna, len(shares)) if shares else 1
    columnas        = max(1, len(shares) // filas_por_columna + (len(shares) % filas_por_columna > 0))
    ancho_ventana   = max(500, 200 + columnas * 160)
    alto_ventana    = min(
        max(400, 170 + filas_visibles * 30),
        int(ventana.winfo_screenheight() * 0.85),
    )
    x = ventana.winfo_screenwidth()  // 2 - ancho_ventana // 2
    y = ventana.winfo_screenheight() // 2 - alto_ventana  // 2
    ventana.geometry(f"{ancho_ventana}x{alto_ventana}+{x}+{y}")

    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()
    ventana.update_idletasks()
    ventana.lift()
    ventana.focus_force()

    ancho_real = ventana.winfo_width()
    alto_real  = ventana.winfo_height()
    x = ventana.winfo_screenwidth()  // 2 - ancho_real // 2
    y = ventana.winfo_screenheight() // 2 - alto_real  // 2
    ventana.geometry(f"{ancho_real}x{alto_real}+{x}+{y}")

    ventana.wait_window()


# ============================================================================
# DIÁLOGO: SELECCIÓN DE SERVIDOR MINIO
# ============================================================================

def seleccionar_servidor_minio(root, shares, perfiles_configurados) -> dict:
    """
    Diálogo para seleccionar el servidor MinIO.

    Returns:
        {"servidor": str, "perfil": str, "endpoint": str}
    """
    resultado = {"servidor": None, "perfil": None, "endpoint": None}

    ventana = tk.Toplevel(root)
    ventana.title("Select MinIO server")

    ttk.Label(ventana, text="Select the MinIO server:").pack(pady=(10, 5))
    servidor_var = tk.StringVar(value=list(backend.MINIO_SERVERS.keys())[0])
    ttk.Combobox(
        ventana,
        textvariable=servidor_var,
        values=list(backend.MINIO_SERVERS.keys()),
        state="readonly",
        width=30,
    ).pack(pady=(0, 10))

    def continuar():
        servidor = servidor_var.get()
        resultado.update({
            "servidor": servidor,
            "perfil":   backend.MINIO_SERVERS[servidor]["IRB"]["profile"],
            "endpoint": backend.MINIO_SERVERS[servidor]["IRB"]["endpoint"],
        })
        ventana.destroy()

    ttk.Button(ventana, text="Continue", command=continuar).pack(pady=15)

    _centrar_ventana(ventana)
    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()
    ventana.update_idletasks()
    ventana.lift()
    ventana.focus_force()
    ventana.wait_window()
    return resultado


# ============================================================================
# DIÁLOGO: RENOVACIÓN DE CREDENCIALES STS
# ============================================================================

def prompt_credenciales_renovar(root, tiempo_restante: str) -> dict:
    """
    Diálogo para decidir si renovar credenciales S3 temporales (STS).

    Returns:
        {"accion": "renovar"|"mantener"|None, "dias": int|None}
    """
    resultado = {"accion": None, "dias": None}

    ventana = tk.Toplevel(root)
    ventana.title("Minio S3 credentials renewal")

    tk.Label(ventana, text="Remaining lifespan for current credentials:", font=("Arial", 12)).pack(pady=(15, 5))
    tk.Label(ventana, text=tiempo_restante, fg="blue", font=("Arial", 10, "bold")).pack(pady=(0, 10))

    frame_dropdown = tk.Frame(ventana)
    frame_dropdown.pack(pady=(5, 10))
    tk.Label(frame_dropdown, text="Select lifespan for new STS credentials (days):").pack(side=tk.LEFT, padx=5)
    dias_var = tk.StringVar(value="7")
    ttk.Combobox(
        frame_dropdown, textvariable=dias_var,
        values=[str(i) for i in range(1, 31)], width=4, state="readonly",
    ).pack(side=tk.LEFT)

    def mantener():
        resultado["accion"] = "mantener"
        ventana.destroy()

    def renovar():
        resultado["accion"] = "renovar"
        resultado["dias"]   = int(dias_var.get())
        ventana.destroy()

    frame_botones = tk.Frame(ventana)
    frame_botones.pack(pady=10)
    tk.Button(frame_botones, text="Keep current", width=12, command=mantener).grid(row=0, column=0, padx=10)
    tk.Button(frame_botones, text="Renew",         width=12, command=renovar).grid(row=0, column=1, padx=10)

    _centrar_ventana(ventana)
    ventana.transient(root)
    ventana.grab_set()
    ventana.deiconify()
    ventana.update_idletasks()
    ventana.lift()
    ventana.focus_force()
    ventana.wait_window()
    return resultado


# ============================================================================
# INTERFAZ PRINCIPAL DE TRANSFERENCIA
# ============================================================================

def abrir_interfaz_copia(root, perfil_rclone: str, mounts_activos: list) -> None:
    """Ventana principal de copia y verificación de datos con rclone."""
    num_cores = backend.obtener_num_cpus()
    _, rclone_config_path, _ = backend.get_rclone_paths(perfil_rclone)

    ventana = tk.Toplevel(root)
    ventana.title("Copy and verify data with rclone")
    ventana.geometry("1024x768")
    ventana.update_idletasks()
    x = ventana.winfo_screenwidth()  // 2 - ventana.winfo_width()  // 2
    y = ventana.winfo_screenheight() // 2 - ventana.winfo_height() // 2
    ventana.geometry(f"+{x}+{y}")

    # ── Metadatos ──────────────────────────────────────────────────────────
    frame_metadata = ttk.LabelFrame(ventana, text="Metadata to attach to the copied objects")
    frame_metadata.pack(padx=10, pady=(15, 5), fill=tk.X)
    frame_metadata.columnconfigure(1, weight=1)

    labels = [
        ("Project",          "project_name"),
        ("Host machine",     "compute_node"),
        ("Sample type",      "sample_type"),
        ("Input data type",  "input_data_type"),
        ("Output data type", "output_data_type"),
        ("Requested by",     "requested_by"),
        ("Research group",   "research_group"),
    ]
    metadata_vars = {}
    for idx, (label_text, var_name) in enumerate(labels):
        ttk.Label(frame_metadata, text=label_text).grid(row=idx, column=0, sticky="w", padx=5, pady=2)
        entry = ttk.Entry(frame_metadata)
        entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
        metadata_vars[var_name] = entry

    # ── Rutas ──────────────────────────────────────────────────────────────
    frame_rutas = ttk.Frame(ventana)
    frame_rutas.pack(fill=tk.X, padx=10, pady=(15, 10))
    frame_rutas.columnconfigure(0, weight=1)

    ttk.Label(frame_rutas, text="Source path (local or rclone profile):").grid(
        row=0, column=0, columnspan=3, sticky="w"
    )
    entrada_origen = ttk.Entry(frame_rutas, width=60)
    entrada_origen.grid(row=1, column=0, sticky="ew", padx=(0, 5))

    def seleccionar_archivo():
        ruta = backend.traducir_ruta_a_remote(
            filedialog.askopenfilename(title="Select source file"), mounts_activos
        )
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)
            actualizar_ruta_resultante()

    def seleccionar_carpeta():
        ruta = backend.traducir_ruta_a_remote(
            filedialog.askdirectory(title="Select source folder"), mounts_activos
        )
        if ruta:
            entrada_origen.delete(0, tk.END)
            entrada_origen.insert(0, ruta)
            actualizar_ruta_resultante()

    ttk.Button(frame_rutas, text="📄 File",   command=seleccionar_archivo).grid(row=1, column=1, padx=(0, 5))
    ttk.Button(frame_rutas, text="📁 Folder", command=seleccionar_carpeta).grid(row=1, column=2)

    ttk.Label(frame_rutas, text=f"Destination path (bucket in profile {perfil_rclone}):").grid(
        row=2, column=0, columnspan=3, sticky="w", pady=(10, 0)
    )
    entrada_destino = tk.Entry(frame_rutas)
    entrada_destino.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 10))

    label_ruta_resultante = ttk.Label(
        frame_rutas, text="Files will be copied into: [incomplete]", wraplength=750, justify="left"
    )
    label_ruta_resultante.grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 10))

    ttk.Label(frame_rutas, text="Advanced (experts only): Additional flags for rclone:").grid(
        row=5, column=0, columnspan=3, sticky="w", pady=(10, 0)
    )
    entry_flags = ttk.Entry(frame_rutas)
    entry_flags.insert(0, f"--transfers={num_cores} --checkers={num_cores} --s3-no-check-bucket")
    entry_flags.grid(row=6, column=0, columnspan=3, sticky="ew")

    # ── Debounce verificación ruta destino ─────────────────────────────────
    debounce_timer = None

    def actualizar_ruta_resultante(*args):
        origen  = entrada_origen.get().strip()
        destino = entrada_destino.get().strip().rstrip("/")
        if not origen or not destino:
            label_ruta_resultante.configure(text="Files will be copied into: [incomplete]")
            return
        label_ruta_resultante.configure(text=f"Files will be copied into: {destino}/")

    def comprobar_ruta_accesible(event=None):
        nonlocal debounce_timer
        if debounce_timer:
            debounce_timer.cancel()
        debounce_timer = threading.Timer(0.5, _verificar_ruta_en_hilo)
        debounce_timer.start()

    def _verificar_ruta_en_hilo():
        ruta       = entrada_destino.get().strip()
        accesible  = backend.verificar_ruta_rclone_accesible(perfil_rclone, ruta)
        color      = "#d6f5d6" if accesible else "#f5d6d6"
        if ruta:
            ventana.after(0, lambda: entrada_destino.configure(background=color))

    def manejar_evento_destino(event=None):
        comprobar_ruta_accesible()
        actualizar_ruta_resultante()

    entrada_destino.bind("<KeyRelease>", manejar_evento_destino)
    entrada_origen.bind("<KeyRelease>",  actualizar_ruta_resultante)

    # ── Botones de acción ──────────────────────────────────────────────────
    frame_botones = ttk.Frame(ventana)
    frame_botones.pack(pady=(15, 0))

    boton_copiar  = ttk.Button(frame_botones, text="Copy data")
    boton_check   = ttk.Button(frame_botones, text="Check data")
    boton_montar  = ttk.Button(frame_botones, text="Mount destination folder")
    boton_guardar = ttk.Button(frame_botones, text="Save Log…")

    boton_copiar.grid( row=0, column=0, padx=10)
    boton_check.grid(  row=0, column=1, padx=10)
    boton_montar.grid( row=0, column=2, padx=10)
    boton_guardar.grid(row=0, column=3, padx=10)

    # ── Log ────────────────────────────────────────────────────────────────
    log_text  = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=25)
    log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    log_queue = queue.Queue()

    def procesar_queue():
        try:
            while True:
                item = log_queue.get_nowait()
                if isinstance(item, tuple):
                    tipo, valor = item
                    if tipo == "enable_button":
                        {"copiar": boton_copiar, "check": boton_check}[valor].config(state="normal")
                else:
                    log_text.insert(tk.END, item)
                    log_text.see(tk.END)
        except queue.Empty:
            pass
        ventana.after(100, procesar_queue)

    # ── Guardar log ────────────────────────────────────────────────────────
    def guardar_log():
        ahora    = datetime.now()
        filename = f"bifrost-{ahora.strftime('%Y-%m-%d_%H-%M-%S')}.log"
        contenido = (
            f"### Log saved at: {ahora.strftime('%Y-%m-%d %H:%M:%S')} ###\n\n"
            "### Log Output ###\n"
            + log_text.get("1.0", tk.END).rstrip()
        )
        if not contenido.strip():
            messagebox.showinfo("Save Log", "There is no log content to save.")
            return
        ruta = filedialog.asksaveasfilename(
            title="Save log as…",
            defaultextension=".log",
            initialfile=filename,
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not ruta:
            return
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(contenido)
            messagebox.showinfo("Save Log", f"Log saved successfully to:\n{ruta}")
        except Exception as e:
            messagebox.showerror("Save Log", f"Error saving log:\n{str(e)}")

    boton_guardar.config(command=guardar_log)

    # ── Montar destino ─────────────────────────────────────────────────────
    def lanzar_montaje():
        ruta_destino = entrada_destino.get().strip()
        if not ruta_destino:
            messagebox.showerror("Error", "You must specify a destination path to mount.")
            return
        try:
            backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta_destino)
        except EnvironmentError as e:
            messagebox.showerror("FUSE / WinFSP not detected", str(e))
        except Exception as e:
            messagebox.showerror("Error mounting", f"Could not mount the prefix:\n{str(e)}")

    boton_montar.config(command=lanzar_montaje)

    # ── Copiar ─────────────────────────────────────────────────────────────
    def lanzar_copia():
        origen  = entrada_origen.get().strip()
        destino = entrada_destino.get().strip()
        if not origen or not destino:
            messagebox.showerror("Error", "You must enter both source and destination.")
            return

        metadatos_dict    = {k: e.get().strip() for k, e in metadata_vars.items()}
        flags_adicionales = entry_flags.get().strip().split()

        boton_copiar.config(state="disabled")
        boton_check.config(state="disabled")

        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_text.insert(tk.END, f"### Copy operation started at {ahora} ###\n")
        log_text.insert(tk.END, "### Metadata ###\n")
        for k, v in metadatos_dict.items():
            log_text.insert(tk.END, f"{k}: {v}\n")
        log_text.insert(tk.END, "\n")
        log_text.insert(tk.END, f"Executing: rclone copy {origen} {perfil_rclone}:/{destino}\n")

        threading.Thread(
            target=backend.ejecutar_rclone_copy,
            kwargs=dict(
                origen=origen,
                destino_perfil=perfil_rclone,
                destino_path=destino,
                rclone_config_path=rclone_config_path,
                metadatos_dict=metadatos_dict,
                flags_adicionales=flags_adicionales,
                num_cores=num_cores,
                log_fn=log_queue.put,
                on_success=lambda: log_queue.put(("enable_button", "check")),
                on_finish=lambda: log_queue.put(("enable_button", "copiar")),
            ),
            daemon=True,
        ).start()

    boton_copiar.config(command=lanzar_copia)

    # ── Check ──────────────────────────────────────────────────────────────
    def lanzar_check():
        origen  = entrada_origen.get().strip()
        destino = entrada_destino.get().strip()
        if not origen or not destino:
            messagebox.showerror("Error", "You must enter both source and destination.")
            return

        flags_adicionales = entry_flags.get().strip().split()
        boton_check.config(state="disabled")
        log_text.insert(
            tk.END,
            f"\n🔍 Verifying with: rclone check {origen} {perfil_rclone}:/{destino}\n\n",
        )

        threading.Thread(
            target=backend.ejecutar_rclone_check,
            kwargs=dict(
                origen=origen,
                destino_perfil=perfil_rclone,
                destino_path=destino,
                rclone_config_path=rclone_config_path,
                flags_adicionales=flags_adicionales,
                mounts_activos=mounts_activos,
                log_fn=log_queue.put,
                on_finish=lambda: log_queue.put(("enable_button", "check")),
            ),
            daemon=True,
        ).start()

    boton_check.config(command=lanzar_check)

    # ── Cierre ─────────────────────────────────────────────────────────────
    def cerrar_aplicacion():
        log_queue.put("\n🧹 Unmounting mount points...\n")
        ruta_destino = entrada_destino.get().strip()
        if ruta_destino:
            mount_point = backend.resolver_mount_point_destino(perfil_rclone, ruta_destino)
            backend.desmontar_punto_montaje(mount_point, log_fn=log_queue.put)
        log_queue.put("✅ Unmount completed. Closing application.\n")
        root.destroy()
        sys.exit(0)

    ventana.protocol("WM_DELETE_WINDOW", cerrar_aplicacion)

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
# UTILIDAD INTERNA DE CENTRADO
# ============================================================================

def _centrar_ventana(ventana) -> None:
    """Centra una ventana Toplevel en la pantalla."""
    ventana.update_idletasks()
    ancho = ventana.winfo_reqwidth() + 20
    alto  = ventana.winfo_reqheight()
    x = ventana.winfo_screenwidth()  // 2 - ancho // 2
    y = ventana.winfo_screenheight() // 2 - alto  // 2
    ventana.geometry(f"{ancho}x{alto}+{x}+{y}")


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """Punto de entrada. Orquesta el flujo completo delegando lógica en backend."""
    EXCEPCION_FILERS       = backend.EXCEPCION_FILERS
    PERMITIR_USUARIO_CUSTOM = "--customuser" in sys.argv or "-c" in sys.argv

    mounts_activos = []

    root = tk.Tk()
    root.title("MinIO Rclone Launcher")
    root.geometry("1x1+0+0")
    root.overrideredirect(True)

    # ── Paso 0: Comprobar actualizaciones ───────────────────────────────────
    check_and_handle_update(root)

    # ── Paso 1: Autenticación LDAP ──────────────────────────────────────────
    usuario_ldap = None
    while not usuario_ldap:
        credenciales_ldap = pedir_credenciales(
            root, "Enter your username", "Enter your username:",
            None if PERMITIR_USUARIO_CUSTOM else getpass.getuser(),
        )
        if backend.validar_credenciales_ldap(credenciales_ldap):
            usuario_ldap = credenciales_ldap["usuario"]
    print(f"LDAP credentials obtained. User: {usuario_ldap}")

    # ── Paso 2: Grupos y privilegios ────────────────────────────────────────
    grupos_ldap = backend.get_ldap_groups(usuario_ldap)
    print("User's LDAP groups:", grupos_ldap)

    usar_privilegios  = False
    credenciales_admin = None

    if "its" in grupos_ldap:
        usar_privilegios = messagebox.askyesno(
            "Confirmation",
            "Do you want to use ITS administrator privileges for CIFS shares?",
        )
        if usar_privilegios:
            credenciales_admin = pedir_credenciales(
                root, "Enter your username", "Enter your username:", "admin_" + usuario_ldap
            )
            atexit.register(lambda: backend.desmontar_todos_los_shares(credenciales_admin["usuario"]))
        else:
            atexit.register(lambda: backend.desmontar_todos_los_shares(usuario_ldap))
    else:
        atexit.register(lambda: backend.desmontar_todos_los_shares(usuario_ldap))

    credenciales_smb = backend.construir_credenciales_smb(
        credenciales_ldap, usar_privilegios, credenciales_admin
    )
    print("Using ITS admin privileges:", usar_privilegios)
    print("SMB user:", credenciales_smb["usuario"])

    # ── Paso 3: Perfiles rclone y shares ────────────────────────────────────
    perfiles_configurados = backend.obtener_perfiles_rclone_config()
    shares_accesibles = backend.obtener_shares_accesibles(
        grupos_ldap,
        credenciales_ldap["usuario"],
        credenciales_ldap["password"],
        credenciales_smb["usuario"],
        EXCEPCION_FILERS,
        usar_privilegios,
    )
    print("Accessible shares:", [s["name"] for s in shares_accesibles])

    perfiles_configurados = backend.configurar_perfiles_smb_si_faltan(
        shares_accesibles, credenciales_smb, perfiles_configurados
    )
    print("Configured rclone profiles:", perfiles_configurados)

    # ── Paso 4: Iniciar aplicación ──────────────────────────────────────────
    def iniciar_aplicacion():
        seleccionar_shares_montar(
            root, shares_accesibles, credenciales_smb["usuario"], mounts_activos, usar_privilegios
        )

        eleccion               = seleccionar_servidor_minio(root, shares_accesibles, perfiles_configurados)
        servidor_s3_rcloneconfig = eleccion["perfil"]
        endpoint               = eleccion["endpoint"]

        check_rclone_installation()

        current_session_token   = backend.get_rclone_session_token(servidor_s3_rcloneconfig)
        current_expiration_time = (
            "There are no current credentials configured, let's configure it now."
            if current_session_token == ""
            else backend.get_expiration_from_session_token(current_session_token)
        )

        respuesta = prompt_credenciales_renovar(root, current_expiration_time)

        if respuesta["accion"] == "renovar":
            credentials = backend.get_credentials(
                endpoint,
                credenciales_ldap["usuario"],
                credenciales_ldap["password"],
                int(respuesta["dias"]) * 86400,
            )
            if credentials is None:
                messagebox.showerror(
                    "Bad Credentials",
                    "Provided credentials are not correct, please try again or contact ITS",
                )
                sys.exit("Provided credentials are not correct.")
            backend.configure_rclone(
                credentials["AccessKeyId"],
                credentials["SecretAccessKey"],
                credentials["SessionToken"],
                endpoint,
                servidor_s3_rcloneconfig,
            )
        elif respuesta["accion"] == "mantener":
            print("User chose to keep the current credentials.")

        abrir_interfaz_copia(root, servidor_s3_rcloneconfig, mounts_activos)

    root.after(100, iniciar_aplicacion)
    root.mainloop()


if __name__ == "__main__":
    main()
