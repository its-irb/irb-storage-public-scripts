# Modo web — `bifrost-transfer` (Open OnDemand)

El modo web de `bifrost-transfer` se ejecuta en el cluster Linux vía Open OnDemand. Es **crítico**: la mayoría de bugs históricos de Bifrost han salido de aquí. Esta página documenta la arquitectura de sesión, el dispatcher de logs, la reconexión y el autosave.

## Detección

```python
# bifrost-transfer/src/main.py
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → `IS_WEB=True`.
- `flet run --web` activa modo web en desarrollo local.
- `BIFROST_CLUSTER=1` activa `IS_WEB=True` y el flujo CIFS/shares del cluster Linux.
- Dentro de `main(page)`: `IS_WEB = IS_WEB or page.web`.

Servidor ASGI bajo modo web: **Hypercorn** (event loop asyncio único). Cada pestaña del navegador abre su propio WebSocket con su propio objeto `page`.

## Lanzamiento en OOD

OpenOnDemand arranca BIFROST como un proceso Python estándar, pasando `main.py` como módulo ASGI. Flet detecta que se importa (no se ejecuta como `__main__`) y activa web mode. El bloque ASGI al final de `main.py`:

```python
if os.environ.get("BIFROST_CLUSTER") == "1":
    from flet.fastapi import FletApp, app_manager
    from fastapi import FastAPI, WebSocket
    import asyncio

    WEBSOCKET_ENDPOINT = os.environ.get("FLET_WEBSOCKET_HANDLER_ENDPOINT")
    WEBPATH = os.environ.get("WEBPATH")
    SECRET_TOKEN = os.environ.get("password") or ""

    app = FastAPI()
    flet_asgi_app = ft.app(main, export_asgi_app=True)
    app.mount(WEBPATH, flet_asgi_app)

    @app.websocket(WEBSOCKET_ENDPOINT)
    async def flet_app(websocket: WebSocket):
        if "--web" not in sys.argv:
            token = websocket.cookies.get("bifrost_auth_token")
            if not SECRET_TOKEN or token != SECRET_TOKEN:
                await websocket.close(code=1008)
                return
        await FletApp(loop=asyncio.get_running_loop(), executor=app_manager.executor, main=main).handle(websocket)
```

Variables de entorno OOD: `FLET_WEBSOCKET_HANDLER_ENDPOINT`, `WEBPATH`, `password` (token de auth del WebSocket, leído de la cookie `bifrost_auth_token`).

## Persistencia de sesión: `_WEB_SESSIONS`

En desktop, cerrar la ventana mata el proceso. En web, el proceso Hypercorn **sigue vivo**: el usuario puede cerrar la pestaña, el WebSocket se rompe y Flet destruye el objeto `page`, pero el proceso rclone que estaba corriendo **sigue ejecutándose**.

`_WEB_SESSIONS` es un diccionario global en memoria, indexado por `username`:

```python
_WEB_SESSIONS: dict[str, dict] = {}
_LAST_WEB_USER: list[str] = [None]   # lista de 1 elemento para mutación en closures
```

TTL = vida del proceso Hypercorn (= vida del job OOD). **La contraseña LDAP nunca se guarda aquí.**

Campos por sesión:

| Campo | Tipo | Descripción |
|---|---|---|
| `servidor_minio` | `str` | Servidor MinIO seleccionado |
| `perfil_rclone` | `str` | Perfil rclone correspondiente |
| `endpoint` | `str` | URL endpoint S3 |
| `extra_config` | `dict\|None` | Config extra rclone (de `MINIO_SERVERS[...]["IRB"]["extra_rclone_config"]`) |
| `copy_log_buffer` | `list[str]` | Líneas de log desde el inicio (cap 5000) |
| `copy_status` | `str` | `"idle"` \| `"running"` \| `"done"` \| `"error"` |
| `copy_origen` | `str` | Path origen de la última copia |
| `copy_destino` | `str` | Path destino de la última copia |
| `copy_proceso` | `dict` | `{"proc": Popen \| None}` — el subprocess rclone vivo |
| `copy_log_callbacks` | `list[Callable]` | Funciones `log()` de páginas suscritas |

### Funciones de gestión

- `_ws_save(usuario, state)` — guarda/actualiza la sesión al navegar a la vista de copia. Hereda `copy_*` de la sesión existente si ya existía (para que una copia en curso sobreviva reconexión).
- `_ws_load(usuario) → dict | None` — devuelve la sesión si tiene al menos `perfil_rclone` y `endpoint` (suficiente para restaurar); `None` si no.
- `_ws_clear(usuario)` — borra la sesión al hacer logout; cancela el timer throttle pendiente y vacía `copy_log_callbacks` para no dispararlos sobre páginas muertas.

## Flujo de reconexión (pestaña cerrada y reabierta)

1. Flet asigna una `page` nueva con un WebSocket nuevo.
2. `main(page)` se re-ejecuta **desde cero** para esa página.
3. Al llegar a login, `go_login()` consulta `_LAST_WEB_USER[0]` y pre-rellena el username si hay sesión.
4. El usuario introduce **solo la contraseña** (LDAP re-auth); no repite selección de servidor MinIO ni descarga de shares.
5. Si la contraseña es correcta, salta directamente a `_build_copy_content`.
6. `_build_copy_content` detecta la sesión activa y lanza el hilo `_replay`.

### Hilo `_replay`

- Espera 200 ms para que se estabilice el árbol de controles.
- Muestra un banner de reconexión con el estado actual (`copy_status`).
- Reproduce las últimas **200 líneas** del buffer (el resto está en `~/bifrost-logs/`).
- Si `_active_proceso["proc"]` sigue vivo (`proc.poll() is None`) → restaura el botón Cancel y lanza `_watch_proc_end` para detectar cuándo termina.
- Si el proceso ya terminó (carrera entre `copy_status` y el teardown de `proc`) → ajusta `copy_status` a `"done"` o `"error"`.

## Log dispatcher con throttle (`_dispatch_log`)

### Problema

rclone con 8 transferencias paralelas genera >15 líneas de log por segundo. Sin throttling, cada línea dispararía un `page.update()` individual, saturando el event loop de Hypercorn e impidiendo nuevas conexiones WebSocket. El síntoma era que reconectar durante una copia se quedaba colgado para siempre en "checking for updates".

### Solución: throttle de 150 ms

```
_dispatch_log(msg)
    │
    ├── Append a copy_log_buffer (cap 5000)
    ├── Append a _dispatch_pending
    │
    ├── If ≥ 150 ms desde último flush → flush inmediato
    └── If no → armar threading.Timer(0.2s) si no hay uno pendiente
                        │
                        └── _flush_log_callbacks()
                                │
                                └── Iterar copy_log_callbacks → cb(combined_lines)
                                        │
                                        └── log(msg) → ui_call(page, _add) → page.update()
```

- `copy_log_callbacks` permite que **múltiples páginas** (ej. dos pestañas del mismo usuario) reciban el mismo log simultáneamente. Las callbacks que fallan (página muerta) se eliminan automáticamente.
- El lock `_dispatch_lock` protege `_dispatch_pending` y `_dispatch_last` de carreras entre el hilo del timer y el hilo de rclone que también llama `_dispatch_log`.
- El buffer se capea a 5000 entradas para no crecer indefinidamente en copias largas.

## Autosave de logs

Al terminar cada copy/check (éxito o error), `_autosave_log()` vuelca el contenido del buffer a:

```
~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log
```

Crítico en modo web porque:
- El buffer en memoria está capeado a 5000 líneas.
- En reconexión solo se replayean 200 líneas en pantalla.
- El log completo solo existe en disco.

## Diferencias clave desktop vs web

| Aspecto | Desktop | Web (OOD) |
|---|---|---|
| Servidor | `ft.run(main)` local | Hypercorn ASGI en cluster |
| `page` | una por ventana | una por pestaña WebSocket |
| Cierre | mata el proceso | el proceso sigue; rclone sigue corriendo |
| Sesión | no persiste | `_WEB_SESSIONS` por username |
| Login | completo cada vez | pre-rellena username, solo contraseña |
| Flujo CIFS | (Mac/Windows) | sí, con `view_shares` |
| Logs en vivo | directos | throttle 150 ms vía `_dispatch_log` |
| Buffer | sin tope | cap 5000, replay 200 |
| Autoupdate | al arrancar | desactivado (no hay binario que actualizar) |

## Depuración del modo web

- Para reproducir bugs de OOD en local: `BIFROST_CLUSTER=1 python src/main.py --web`. Abre el navegador, inicia una copia, cierra la pestaña y reábrela.
- El banner de reconexión y los mensajes `[ui_call] Skipping UI update — session disconnected` en consola indican flujos de reconexión.
- Si reconectar se cuelga, sospechar del dispatcher: verificar que `_dispatch_lock` se adquiere correctamente y que no se encolan callbacks sobre páginas muertas.
- `~/bifrost-logs/` en el cluster contiene el log completo de cada sesión.

## Reglas de oro del modo web

1. Toda mutación de UI desde background → `ui_call` (ver `thread-safety.md`). `ui_call` ya comprueba `page.session.connection` y salta si el WebSocket está cerrado.
2. Nunca `log_list.controls.append(...)` directo desde un hilo; pasar por `_dispatch_log`.
3. Al hacer logout, `_ws_clear` debe cancelar el timer throttle pendiente y vaciar callbacks.
4. La contraseña LDAP **nunca** se guarda en `_WEB_SESSIONS`.
5. El proceso rclone sobrevive al cierre de pestaña; al reconectar, `_replay` decide si restaurar Cancel (proceso vivo) o marcar done/error.
