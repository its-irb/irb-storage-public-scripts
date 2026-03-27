# BIFROST
**Herramienta de transferencia de datos a MinIO S3 — IRB Barcelona**

---

## Qué hace

BIFROST te permite:
- Copiar datos desde carpetas de red (SMB/CIFS) o desde local a buckets de MinIO S3, con verificación de integridad y etiquetado automático de metadatos en cada objeto transferido
- Montar carpetas de MinIO S3 como unidad local en tu ordenador

---

## Requisitos

**Dependencias**

Las dependencias como el binario de rclone o fuse-t (este segundo en el caso de Mac OS) se empaquetan dentro del ejecutable, y no es necesario tenerlas instaladas en el equipo.

Durante el desarrollo, estas dependencias se buscan en `src/assets/bin` y `src/frameworks` respectivamente. Si no se encuentran entonces el programa hace fallback a las versiones instaladas en el equipo. Para descargar las versiones recomendadas de las dependencias se pueden ejecutar los scripts`{platform}-assets-downloader.sh` dentro de `src`.

El framework de fuse-t se copia a posteriori dentro del .app para que flet no rompa los enlaces simbólicos.

**Estar conectado a la VPN de Nexica** (Forticlient)

---

## Archivos

| Archivo | Función |
|---|---|
| `src/main.py` | Interfaz gráfica. Punto de entrada. |
| `src/backend.py` | Toda la lógica de negocio (LDAP, rclone, SMB, S3). |
| `minio-sts-credentials-request.py` | Genera credenciales temporales de acceso al servidor de Minio de IRB Barcelona.|

---

## Cómo ejecutar

La primera vez se ha de crear el virtual environment:
```bash
python -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r ./src/pip-requirements.txt
```

Y cada vez que se quiera ejecutar se ha de cargar el virtual envoironment:
```bash
source venv/bin/activate
```

```bash
flet run
```

Para iniciar sesión con un usuario distinto al del sistema:
```bash
flet run --customuser
```

Para lanzar forzar la auto-actualización:
```bash
flet run --update
```

## Preparar el entorno para empaquetar.

Flet build utiliza los parámetros definidos en `pyproject.toml`.

Si se actualizan los paquetes del virtual environment se ha de regenerar el archivo `pip-requirements.txt` y luego importarlo al `pyproject.toml`:

```bash
python -m pip freeze > src/pip-requirements.txt
uv add -r pip-requirements.txt
```

Para generar un instalador para windows se ha utilizado Inno Setup, que empaqueta toda la carpeta generada popr flet en un solo .exe que después puede instalarse de la forma habitual. En este caso el archivo de configuración es `installer.iss`.
