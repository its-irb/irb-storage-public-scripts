# Frontend — apps Flet (`bifrost-mount` / `bifrost-transfer`)

## Estructura por app

Ambas apps son idénticas en layout:

```text
<app>/
  pyproject-template.toml  # Plantilla versionada; el pyproject.toml efectivo es local
  installer.iss            # Inno Setup (Windows)
  build-macos.sh
  src/
    main.py                # GUI Flet — punto de entrada
    config.py              # APP_INFO = {"flavour": ..., "name": ..., "description": ...}
    version.py             # __version__ — generado por CI/build local
    assets/
      bin/                 # rclone(.exe) — descargado con los downloaders (no versionado)
    frameworks/            # fuse_t.framework (mount, macOS) — idem
    storage/               # (solo transfer) datos temporales
```

Tamaños actuales: `bifrost-mount/src/main.py` ≈ 1414 líneas;
`bifrost-transfer/src/main.py` ≈ 4577 líneas (modo web + Tag Manager);
`bifrost-transfer/src/meta_fields.py` ≈ 645 líneas.

## Cómo se inicializa la app

Cada `main.py` empieza con:

```python
from bifrost_backend import backend
from bifrost_frontend.frontend import *      # paleta + componentes
from config import APP_INFO                  # {"flavour": "mount"|"transfer", ...}
```

A continuación:

1. Detecta el modo de ejecución (`IS_WEB`, …).
2. Reenvuelve `sys.stdout`/`sys.stderr` en UTF-8 (consola Windows). No tocar.
3. Configura el log persistente: `~/bifrost-mount-logs/` en `bifrost-mount`
   y `~/bifrost-logs/` en `bifrost-transfer`.
4. Define `main(page: ft.Page)`, arma el flujo de vistas y lo arranca con
   `ft.app(target=main, ...)`.

## Flujo de vistas

```text
bifrost-mount (desktop puro):
  view_update → view_login → view_minio → view_credentials (auto) → view_mount

bifrost-transfer (Mac/Windows/desktop):
  view_update → view_login → view_minio → view_credentials (auto) → view_copy

bifrost-transfer (Linux cluster, BIFROST_CLUSTER=1):
  view_update → view_login → view_shares → view_minio → view_credentials → view_copy
```

`view_copy` contiene un navegador de carpetas rclone para elegir destino
(`build_rclone_browser`), un selector de origen (share SMB, carpeta local o
SFTP efímero), opciones de copia y un panel de log en vivo (`ft.ListView` con
`auto_scroll=True`).

Las secciones METADATA, botones de acción y LOG OUTPUT (`bottom_col`) quedan
ocultos (`visible=False`) hasta que el usuario selecciona un bucket destino;
el toggle está en `on_browser_select` (`path` no vacío → visible; raíz →
oculto).

## Credenciales STS — auto-renovación

Constantes en cada `main.py`:

```python
STS_RENEWAL_THRESHOLD_DAYS = 3
STS_AUTO_RENEWAL_DAYS = 7
```

- Si quedan **>3 días** de validez en las credenciales STS, se reutilizan y se
  salta `view_credentials`.
- Si quedan **<3 días** o no existen, se renuevan automáticamente por 7 días
  mostrando progreso.
- No hay botón manual de renovación en el flujo normal.

## `meta_fields.py` (solo bifrost-transfer)

Fuente canónica de los perfiles y campos de metadatos, compartida por el
formulario de copia y el Tag Manager:

- `FieldType` — tipos de campo del formulario.
- `TAG_PROFILES` — definición de perfiles (IRB Standard, Histopathology) y
  sus campos.
- `build_meta_fields(..., prefill_values: dict[str, str] | None)` — construye
  los controles del formulario; `prefill_values` pre-rellena controles con
  valores existentes (usado por el Tag Manager).
- `LAB_ACRONYMS` — acrónimos de laboratorio; deben coincidir con el tag
  `acronym` real de los buckets MinIO (los consume el filtro por lab).
- `build_lab_filter_widget(...)` — widget "Filter by lab…": filtra el listado
  de buckets leyendo el tag `acronym` de cada bucket con
  `backend.get_bucket_tags` en paralelo (`ThreadPoolExecutor`); se oculta al
  navegar dentro de un bucket y reaparece en la raíz. Solo aplica a nivel root.
- `detect_profile(tags: dict[str, str])` — detecta qué perfil encaja con un
  dict de tags (lo usa el Tag Manager para pre-cargar el editor).

Regla: cualquier cambio de campos, perfiles o labs se hace **solo** en
`meta_fields.py`, nunca en `main.py`.

## Modo web (`bifrost-transfer` — Open OnDemand)

### Detección

```python
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → modo web.
- `flet run --web` activa el modo web en desarrollo local.
- `BIFROST_CLUSTER=1` fuerza el modo web completo (flujo CIFS/shares del
  cluster Linux).

El servidor ASGI es **Hypercorn** con un único event loop asyncio para toda la
aplicación. Cada pestaña del navegador abre su propio WebSocket con su propio
objeto `page`.

### Por qué existe el modo web

En modo desktop, cerrar la ventana mata el proceso. En web, el proceso
Hypercorn vive mientras dure el job de OOD: el usuario puede cerrar la
pestaña (se rompe el WebSocket, Flet destruye la `page`) y **el proceso rclone
sigue corriendo**. Todo lo que sigue existe para gestionar esa supervivencia.

### Persistencia de sesión: `_WEB_SESSIONS`

Diccionario global en memoria indexado por `username`; TTL = vida del proceso
Hypercorn (= vida del job OOD). **La contraseña LDAP nunca se guarda aquí.**

| Campo | Tipo | Descripción |
|---|---|---|
| `servidor_minio` | `str` | Servidor MinIO seleccionado |
| `perfil_rclone` | `str` | Perfil rclone correspondiente |
| `endpoint` | `str` | URL endpoint S3 |
| `extra_config` | `dict\|None` | Config extra rclone |
| `copy_log_buffer` | `list[str]` | Líneas de log desde el inicio (cap 5000) |
| `copy_status` | `str` | `"idle"\|"running"\|"done"\|"error"` |
| `copy_origen` / `copy_destino` | `str` | Paths |
| `copy_proceso` | `dict` | `{"proc": Popen \| None}` |
| `copy_log_callbacks` | `list[Callable]` | Funciones `log()` de las páginas suscritas |

Gestión: `_ws_save(usuario, state)` (guarda al navegar a la vista de copia),
`_ws_load(usuario)` (devuelve la sesión si tiene al menos `perfil_rclone` y
`endpoint`), `_ws_clear(usuario)` (logout; cancela el timer de throttle
pendiente y vacía los callbacks para no dispararlos en páginas muertas).

### Flujo de reconexión (pestaña cerrada y reabierta)

1. Flet asigna una `page` nueva con un WebSocket nuevo.
2. `main(page)` se re-ejecuta desde cero para esa página.
3. `go_login()` consulta `_LAST_WEB_USER[0]` y pre-rellena el username si hay
   sesión.
4. El usuario introduce **solo la contraseña** (re-autenticación LDAP); no
   vuelve a pasar por selección de servidor MinIO ni descarga de shares.
5. Si la contraseña es válida, salta directamente a `_build_copy_content`.
6. `_build_copy_content` detecta la sesión activa y lanza el hilo `_replay`.

`_replay`:

- Espera 200 ms para que se estabilice el árbol de controles.
- Muestra un banner de reconexión con el estado actual.
- Reproduce las últimas **200 líneas** del buffer (el resto vive en
  `~/bifrost-logs/`).
- Si `proc.poll() is None` → restaura el botón Cancel y lanza
  `_watch_proc_end` para detectar el final.
- Si el proceso ya terminó (carrera entre `copy_status` y el teardown de
  `proc`) → ajusta `copy_status` a `"done"` o `"error"`.

### Log dispatcher con throttle (`_dispatch_log`)

rclone con 8 transferencias paralelas genera >15 líneas/s. Sin throttle, cada
línea haría un `page.update()` y saturaría el event loop de Hypercorn
(síntoma histórico: reconectar se quedaba eternamente en "checking for
updates"). Solución: throttle de **150 ms**.

```text
_dispatch_log(msg)
  ├── append a copy_log_buffer (cap 5000)
  ├── append a _dispatch_pending
  ├── si han pasado ≥150 ms desde el último flush → flush inmediato
  └── si no → armar threading.Timer(0.2s) si no hay uno pendiente
                   └── _flush_log_callbacks()
                         └── itera copy_log_callbacks → cb(combined_lines)
                               └── log(msg) → ui_call(page, _add) → page.update()
```

`copy_log_callbacks` permite que **varias pestañas** del mismo usuario reciban
el mismo log; los callbacks que fallan (página muerta) se eliminan
automáticamente. El lock `_dispatch_lock` protege `_dispatch_pending` y
`_dispatch_last` de carreras entre el timer y el hilo de rclone.

### Autosave de logs

Al terminar cada copy/check (éxito o error), `_autosave_log()` vuelca el
buffer a:

```text
~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log
```

Crítico en modo web: el buffer en memoria está capeado a 5000 líneas y solo se
replayean 200 en pantalla; el log completo solo existe en el disco del servidor
OOD.

## El bug `IndexError: list index out of range`

### Síntoma

```text
File "object_patch.py", line 889, in _compare_lists
    target_key = dst_keys[i]
IndexError: list index out of range
```

Ocurría al cambiar el foco de la pestaña durante una copia o al iniciarla (el
botón Copy dispara un refresco del browser destino).

### Causa raíz

Flet calcula un diff (`ObjectPatch.from_diff`) sobre el árbol de controles **en
el thread del event loop asyncio, sin lock**. El código original usaba
`page.run_thread(fn)` para actualizar UI desde hilos de background;
`run_thread` ejecuta en un `ThreadPoolExecutor` **en paralelo real** al event
loop:

```text
event loop (diff):  cuenta controls 0,1,2,3,4…
worker thread:                              ← controls.clear()
event loop (diff):                          …5? → CRASH
```

El GIL no ayuda porque el diff y `.clear()` abarcan múltiples opcodes entre
los que puede producirse el cambio de thread.

### Solución

Sustituir `page.run_thread(fn)` por `page.run_task(async_wrapper)` —
encolado en el **mismo event loop single-threaded** mediante
`asyncio.run_coroutine_threadsafe` (ver `backend.ui_call`). También se
corrigieron los `threading.Timer` que llamaban funciones de navegación sin
pasar por `ui_call`:

```python
# Mal:
threading.Timer(0.1, dest_browser_refresh).start()
# Bien:
threading.Timer(0.1, lambda: ui_call(page, dest_browser_refresh)).start()
```

### Regla general

> **Toda mutación de `control.controls` o llamada a `page.update()` desde
> fuera del event loop de Flet debe envolverse en `ui_call(page, fn)`.**

Los únicos sitios donde `page.update()` puede llamarse directamente son los
event handlers de Flet (botones, dialogs), porque Flet los ejecuta ya como
tareas asyncio.

## Variables de entorno del frontend

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Fuerza `IS_WEB=True` (flujo CIFS/shares del cluster Linux) |
| `FLET_ASSETS_DIR` | ambas | La setea Flet en runtime; el backend la usa para localizar `rclone` |

## Convenciones de UI

- **Todo en español** — labels, mensajes, comentarios, nombres de controles
  (`btn_aceptar`, `lbl_estado`, …). Excepción: mensajes del flujo WinFsp en
  `bifrost-mount`, en inglés.
- **Colores** — solo constantes de `bifrost_frontend.frontend`
  (`C_PRIMARY`, `C_ERROR`, …); no hardcodear hex.
- **Botones** — preferir `btn_primary` / `btn_secondary` sobre `ft.Button`
  crudo.
- **Threads** — `backend.safe_thread(page, target)` en lugar de
  `threading.Thread`; con `threading.Timer`, envolver el callback en
  `lambda: ui_call(page, fn)`.
- **Diálogos de error** — `show_dialog(page, "Error", msg, color=C_ERROR)`.
- **Logs de copia** — siempre por `_dispatch_log` (transfer/web); nunca
  `log_list.controls.append(...)` directo desde un hilo.

## Empaquetado por app

| Plataforma | Genera |
|---|---|
| macOS | `dist/<app>.app` |
| Windows | `dist/<app>/…` + `.exe` instalador (Inno Setup) |
| Linux (clúster) | Sin empaquetado: `bifrost-transfer` corre desde código en modo web (Open OnDemand) |

```bash
# macOS (vía build-macos.sh)
flet build macos
```

```powershell
# Windows (vía build-windows.ps1; el instalador aparte con Inno Setup)
flet build windows
```

Antes de `flet build` hay que generar el paquete `bifrost-shared` y reescribir
`__BUILDPATH__` en el `pyproject.toml` de la app (los scripts de build lo
hacen). Detalle completo en [build-and-ci.md](build-and-ci.md).
