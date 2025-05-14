import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import minio_functions

# ------------------------------
# Función para la primera pantalla
# ------------------------------
def crear_ventana_rutas():
    ventana = tk.Tk()
    ventana.title("Rclone Check - Selección de rutas")

    ruta_origen = tk.StringVar()
    ruta_destino = tk.StringVar()

    ttk.Label(ventana, text="Ruta Origen:").pack(pady=(10, 0))
    ttk.Entry(ventana, textvariable=ruta_origen, width=50).pack(pady=(0, 10))

    ttk.Label(ventana, text="Ruta Destino:").pack(pady=(10, 0))
    ttk.Entry(ventana, textvariable=ruta_destino, width=50).pack(pady=(0, 10))

    # Botón Siguiente
    ttk.Button(
        ventana,
        text="Siguiente",
        command=lambda: avanzar_a_check(ventana, ruta_origen.get(), ruta_destino.get())
    ).pack(pady=(20, 10))

    ventana.mainloop()

# ------------------------------
# Función para avanzar a la segunda pantalla
# ------------------------------
def avanzar_a_check(ventana_actual, origen, destino):
    ventana_actual.destroy()  # Cerramos la ventana de rutas
    crear_ventana_check(origen, destino)  # Abrimos la ventana de rclone check

# ------------------------------
# Función para mostrar el progreso de rclone check
# ------------------------------
def crear_ventana_check(origen, destino):
    ventana_check = tk.Tk()
    ventana_check.title("Rclone Check - Progreso")

    # Texto para mostrar la salida de rclone
    text_output = scrolledtext.ScrolledText(ventana_check, width=100, height=30)
    text_output.pack(padx=10, pady=10)

    # Lanzamos rclone en otro hilo para no bloquear la ventana
    threading.Thread(target=ejecutar_rclone_check, args=(origen, destino, text_output)).start()

    ventana_check.mainloop()

# ------------------------------
# Función que ejecuta rclone check y muestra el resultado en tiempo real
# ------------------------------
def ejecutar_rclone_check(origen, destino, text_widget):
    # cmd = ["rclone", "check", origen, destino]
    cmd = [
        "rclone", "check",
        origen, destino,
        "--exclude", "**/.DS_Store",
        "--exclude", "**/Thumbs.db",
        "--exclude", ".snapshot/**",
        "--checkers", "8",
        "--checksum",
        "--copy-links",
    ]

    try:
        proceso = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        # Leer la salida línea por línea
        for linea in proceso.stdout:
            text_widget.insert(tk.END, linea)
            text_widget.see(tk.END)  # Scroll automático

        proceso.wait()

        # Cuando termine
        if proceso.returncode == 0:
            text_widget.insert(tk.END, "\n✅ Comprobación completada correctamente.\n")
        else:
            text_widget.insert(tk.END, f"\n⚠️ Comprobación finalizada con errores. Código de salida {proceso.returncode}\n")

    except Exception as e:
        text_widget.insert(tk.END, f"\n❌ Error ejecutando rclone check: {e}\n")

if __name__ == "__main__":
    minio_functions.check_version()
    crear_ventana_rutas()