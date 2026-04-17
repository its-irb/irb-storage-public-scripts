# BIFROST
**Herramientas de acceso al almacenamiento MinIO S3 — IRB Barcelona**

Este repositorio contiene dos aplicaciones de escritorio (Flet/Python) para interactuar con el servidor MinIO S3 de IRB Barcelona:

| App | Carpeta | Función |
|---|---|---|
| **bifrost-transfer** | `bifrost-transfer/` | Copia datos desde carpetas de red (SMB/CIFS) o local a buckets de MinIO S3, con verificación de integridad y etiquetado automático de metadatos. |
| **bifrost-mount** | `bifrost-mount/` | Monta carpetas de MinIO S3 como unidad local en el ordenador. |

Ambas aplicaciones comparten el backend definido en `shared/backend.py` (LDAP, rclone, SMB, S3).

---

## Requisitos

- **Estar conectado a la VPN de Nexica** (Forticlient)

**Dependencias binarias**

Las dependencias como el binario de `rclone` o el framework `fuse-t` (este último solo en macOS, usado por `bifrost-mount`) se empaquetan dentro del ejecutable y no es necesario tenerlas instaladas en el equipo.

---

## Estructura del repositorio

```
bifrost-mount/          # App de montado de buckets S3
  src/
    main.py             # Interfaz gráfica (Flet). Punto de entrada.
    pip-requirements.txt
    version.py
    assets/bin/         # Binarios empaquetados (rclone, etc.)
    frameworks/         # fuse-t framework (macOS)
  pyproject.toml        # Configuración de flet build
  installer.iss         # Inno Setup (instalador Windows)

bifrost-transfer/       # App de transferencia de datos a S3
  src/
    main.py             # Interfaz gráfica (Flet). Punto de entrada.
    pip-requirements.txt
    version.py
    assets/bin/         # Binarios empaquetados (rclone, etc.)
    frameworks/
    storage/            # Datos temporales de transferencia
  pyproject.toml        # Configuración de flet build
  installer.iss         # Inno Setup (instalador Windows)
  build.sh              # Script de build

shared/
  backend.py            # Lógica de negocio compartida (LDAP, rclone, SMB, S3)
  linux-assets-downloader.sh
  macos-assets-downloader.sh
  macos-rclone-downloader.sh
  windows-assets-downloader.sh

old/
  minio-sts-credentials-request.py  # Script legacy para generar credenciales STS
```

---

## Cómo ejecutar (desarrollo)

Los pasos son los mismos para ambas apps. Ejecutar desde la carpeta de la app (`bifrost-mount/` o `bifrost-transfer/`).

La primera vez, crear el virtual environment:
```bash
python -m venv venv
source venv/bin/activate          # macOS / Linux
# .\venv\Scripts\Activate.ps1     # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install -r ./src/pip-requirements.txt
```

Cada vez que se quiera ejecutar, cargar el virtual environment y lanzar:
```bash
source venv/bin/activate
flet run
```

Opciones adicionales (disponibles en ambas apps):
```bash
flet run --customuser   # Iniciar sesión con un usuario distinto al del sistema
flet run --update       # Forzar la auto-actualización
```

`bifrost-transfer` también soporta modo web (Open OnDemand / cluster Linux):
```bash
python src/main.py --web
# o bien:
BIFROST_DEV=1 flet run   # Simular modo web en desarrollo
```

Para simular el modo Linux cluster en `bifrost-mount`:
```bash
BIFROST_LINUX=1 flet run
```

---

## Empaquetar

`flet build` utiliza los parámetros definidos en `pyproject.toml` de cada app.

Si se actualizan los paquetes del virtual environment, regenerar `pip-requirements.txt` e importarlo al `pyproject.toml`:
```bash
python -m pip freeze > src/pip-requirements.txt
uv add -r pip-requirements.txt
```

Para generar un instalador de Windows se utiliza **Inno Setup**, que empaqueta toda la carpeta generada por `flet build` en un único `.exe` instalable. El archivo de configuración es `installer.iss` en la raíz de cada app.
