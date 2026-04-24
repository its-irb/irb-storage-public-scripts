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

Para generar un instalador para windows se ha utilizado Inno Setup, que empaqueta toda la carpeta generada popr flet en un solo .exe que después puede instalarse de la forma habitual. En este caso el archivo de configuración es `installer.iss`.

---

## BIFROST OOD — Modo web (OpenOnDemand)

Esta sección documenta la arquitectura del modo web, que es el que se usa en el clúster a través de OpenOnDemand. Es sustancialmente diferente al modo desktop y tiene su propia gestión de sesiones, threading y resiliencia de WebSocket.

---

### Cómo se lanza en OOD

OpenOnDemand arranca BIFROST como un proceso Python estándar al que le pasa el archivo `main.py` como módulo ASGI. Flet detecta que se está importando (no ejecutado como `__main__`) y activa el modo web automáticamente.

La condición en el código es:

```python
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or DEV_WEB
```

Esto significa:
- Si OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → `IS_WEB = True`
- Si se lanza manualmente con `flet run --web` → `"--web" in sys.argv` → `IS_WEB = True`
- Si se activa `BIFROST_DEV=1` en el entorno → `DEV_WEB = True` → `IS_WEB = True`

El servidor ASGI que usa Flet para el modo web es **Hypercorn**, que corre un event loop asyncio único para toda la aplicación. Cada pestaña del navegador abre un WebSocket independiente con su propia instancia de `page`.

Para desarrollo local en modo web:

```bash
BIFROST_DEV=1 flet run
# o equivalentemente:
flet run --web
```

Para forzar el modo cluster (con flujo CIFS):

```bash
BIFROST_CLUSTER=1 BIFROST_DEV=1 flet run
```

---

### Arquitectura de sesiones (`_WEB_SESSIONS`)

En modo desktop, cuando el usuario cierra la ventana el proceso muere. En modo web el proceso Hypercorn sigue vivo y el usuario puede cerrar la pestaña, la conexión WebSocket se rompe y Flet destruye el objeto `page` — pero el proceso de rclone que estaba corriendo **sigue vivo**.

Para manejar esto existe `_WEB_SESSIONS`, un diccionario global en memoria indexado por `username`:

```python
_WEB_SESSIONS: dict[str, dict] = {}
```

El TTL de una sesión es la vida del proceso Hypercorn (es decir, la vida del job de OOD). La contraseña LDAP **nunca** se guarda aquí.

Cada entrada contiene:

| Campo | Tipo | Descripción |
|---|---|---|
| `servidor_minio` | `str` | Nombre del servidor MinIO seleccionado |
| `perfil_rclone` | `str` | Perfil rclone correspondiente |
| `endpoint` | `str` | URL del endpoint S3 |
| `extra_config` | `dict\|None` | Config extra de rclone (si aplica) |
| `copy_log_buffer` | `list[str]` | Todas las líneas de log desde el inicio de la copia |
| `copy_status` | `str` | `"idle"` \| `"running"` \| `"done"` \| `"error"` |
| `copy_origen` | `str` | Path origen de la última copia |
| `copy_destino` | `str` | Path destino de la última copia |
| `copy_proceso` | `dict` | `{"proc": Popen \| None}` — el subproceso de rclone vivo |
| `copy_log_callbacks` | `list[Callable]` | Funciones `log()` de las páginas suscritas actualmente |

#### Funciones de gestión de sesión

- `_ws_save(usuario, state)` — guarda/actualiza la sesión al navegar a la vista de copia
- `_ws_load(usuario)` → `dict | None` — devuelve la sesión si es suficientemente completa para restaurar (tiene `perfil_rclone` y `endpoint`)
- `_ws_clear(usuario)` — elimina la sesión al hacer logout; también cancela el timer de throttle pendiente y limpia los callbacks para no disparar sobre páginas muertas

---

### Flujo de reconexión

Cuando el usuario cierra y reabre la pestaña:

1. Flet asigna una nueva `page` con un nuevo WebSocket
2. `main(page)` se vuelve a ejecutar desde cero para esa página
3. Al llegar al login, `go_login()` comprueba si existe sesión para `_LAST_WEB_USER[0]`
4. Si existe, muestra el login con el `username` pre-rellenado y el callback `on_login_success_with_restore`
5. El usuario solo introduce la **contraseña** (LDAP re-auth), sin pasar por la selección de servidor MinIO ni la descarga de shares
6. Si la contraseña es correcta, se salta directamente a la vista de copia (`_build_copy_content`)
7. `_build_copy_content` detecta la sesión activa y lanza el hilo `_replay`

El hilo `_replay`:
- Espera 200 ms para que el árbol de controles se estabilice
- Muestra un banner de reconexión con el estado actual
- Reproduce las últimas 200 líneas del buffer (el resto está en `~/bifrost-logs/`)
- Si `_active_proceso["proc"]` sigue vivo (`proc.poll() is None`), restaura el botón Cancel y lanza `_watch_proc_end` para detectar cuando termine
- Si el proceso ya acabó (carrera entre `copy_status` y el vaciado de `proc`), ajusta el estado a `"done"` o `"error"`

---

### Log dispatcher y throttle (`_dispatch_log`)

El problema: rclone con 8 transferencias paralelas genera >15 líneas de log por segundo. Sin throttle, cada línea haría un `page.update()` individual, saturando el event loop de Hypercorn e impidiendo que nuevas conexiones WebSocket pudieran establecerse (el síntoma era que reconectar durante una copia se quedaba eternamente en "checking for updates").

La solución es un dispatcher con throttle de 150 ms:

```
_dispatch_log(msg)
    │
    ├── Append a copy_log_buffer (capped a 5000 entradas)
    ├── Append a _dispatch_pending
    │
    ├── Si han pasado ≥ 150 ms desde el último flush → flush inmediato
    └── Si no → armar threading.Timer(0.2s) si no hay uno ya pendiente
                        │
                        └── _flush_log_callbacks()
                                │
                                └── Itera copy_log_callbacks → cb(combined_lines)
                                        │
                                        └── log(msg) → ui_call(page, _add) → page.update()
```

`copy_log_callbacks` permite que **múltiples páginas** (p.ej. dos pestañas del mismo usuario) reciban el mismo log simultaneamente. Los callbacks que fallen (página muerta) se eliminan automáticamente.

El lock `_dispatch_lock` protege el acceso a `_dispatch_pending` y `_dispatch_last` contra condiciones de carrera entre el hilo del timer y el hilo de rclone que también llama `_dispatch_log`.

---

### El bug `IndexError: list index out of range` — qué era y por qué está resuelto

#### El síntoma

```
Unhandled error in 'on_app_lifecycle_state_change' handler
...
File "object_patch.py", line 889, in _compare_lists
    target_key = dst_keys[i]
                 ~~~~~~~~^^^
IndexError: list index out of range
```

Ocurría al enfocar/desenfocar la pestaña del navegador mientras había una copia en marcha, y de forma especialmente frecuente al iniciar una copia (el botón Copy dispara el browser refresh del destino).

#### La causa raíz

Flet mantiene un "snapshot" del árbol de controles anterior y, en cada evento, calcula un diff (`ObjectPatch.from_diff`) para enviar solo los cambios al cliente. Ese diff recorre las listas de controles (`controls`) **en el thread del event loop asyncio**, sin ningún lock.

El código original usaba `page.run_thread(fn)` para todas las actualizaciones de UI desde hilos de background (log callbacks, browser de carpetas, etc.). `run_thread` lanza `fn()` en un `ThreadPoolExecutor` que corre **en paralelo real** al event loop asyncio.

La colisión:

```
Event loop asyncio (diff walker):   counts controls: 0, 1, 2, 3, 4...
ThreadPoolExecutor worker:                                  ← controls.clear()
Event loop asyncio (diff walker):                    ...5? → CRASH (list is empty)
```

El GIL de Python no ayuda aquí porque la iteración del diff y el `.clear()` abarcan múltiples opcodes de bytecode entre los que el GIL puede cambiar de thread.

#### La solución

Se cambió `page.run_thread(fn)` por `page.run_task(async_wrapper)` en `ui_call`:

```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    async def _wrapper():
        fn()
    page.run_task(_wrapper)
```

`page.run_task` usa `asyncio.run_coroutine_threadsafe(coro, loop)`, que encola la coroutine en el **mismo event loop single-threaded** donde corre el diff walker. Asyncio es cooperative: una coroutine solo cede el control en un `await`. Como `_compare_lists` no contiene ningún `await`, nunca puede ser interrumpida por una coroutine enqueuada — el diff siempre ve una lista estable.

Adicionalmente se corrigieron los dos `threading.Timer` que llamaban directamente a funciones de navegación de carpetas sin pasar por `ui_call`:

```python
# Antes (incorrecto — timer thread muta controls directamente):
threading.Timer(0.1, dest_browser_refresh).start()
threading.Timer(0.1, refresh_fn).start()

# Después (correcto — encolado en asyncio):
threading.Timer(0.1, lambda: ui_call(page, dest_browser_refresh)).start()
threading.Timer(0.1, lambda: ui_call(page, refresh_fn)).start()
```

#### Regla general

> **Toda mutación de `control.controls` o llamada a `page.update()` desde fuera del event loop de Flet debe ir envuelta en `ui_call(page, fn)`.**

Los únicos sitios donde se puede llamar `page.update()` directamente sin `ui_call` son los event handlers de Flet (botones, dialogs, etc.) porque Flet los ejecuta ya como tareas asyncio.

---

### Autosave de logs

Al terminar cada copia o check (éxito o error), `_autosave_log()` guarda el contenido del buffer en:

```
~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log
```

Esto es especialmente importante en modo web porque:
- El buffer en memoria se trunca a las últimas 5000 líneas
- En reconexión solo se reproducen las últimas 200 líneas en pantalla
- El log completo siempre está disponible en el sistema de ficheros del servidor OOD

---

### Variables de entorno

| Variable | Valor | Efecto |
|---|---|---|
| `BIFROST_DEV` | `1` | Activa `IS_WEB` y `DEV_WEB` para desarrollo local |
| `BIFROST_CLUSTER` | `1` | Activa `IS_LINUX_CLUSTER` (incluye flujo CIFS/shares) |
