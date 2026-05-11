# CLAUDE_FRONTEND.md — Apps Flet (`bifrost-mount` / `bifrost-transfer`)

Documenta la capa de UI: los dos `main.py`, el flujo de vistas, el modo web de `bifrost-transfer` y las reglas de thread-safety con Flet.

---

## Estructura por app

Ambas apps son idénticas en layout:

```
<app>/
  pyproject.toml       # config flet build + deps congeladas
  uv.lock
  installer.iss        # Inno Setup (Windows)
  build-macos.sh
  src/
    main.py            # GUI Flet — punto de entrada
    config.py          # APP_INFO = {"flavour": ..., "name": ..., "description": ...}
    version.py         # __version__ — generado por CI / build local
    assets/
      bin/             # rclone(.exe) empaquetado
    frameworks/        # fuse_t.framework (mount, macOS)
    storage/           # (solo transfer) datos temporales
```

`bifrost-mount/src/main.py` ≈ 1.5k LOC. `bifrost-transfer/src/main.py` ≈ 2.9k LOC (más grande por todo el código de modo web).

---

## Cómo se inicializa la app

Cada `main.py` empieza con:

```python
from bifrost_backend import backend
from bifrost_frontend.frontend import *      # paleta + componentes
from config import APP_INFO                  # {"flavour": "mount"|"transfer", ...}
```

A continuación:
1. Detecta modo de ejecución (`IS_WEB`, `IS_LINUX_CLUSTER`, `DEV_WEB`, …).
2. Reenvuelve `sys.stdout`/`sys.stderr` en UTF-8 (Windows console).
3. Configura el fichero de log persistente bajo `~/bifrost-<flavour>-logs/`.
4. Define `main(page: ft.Page)` que arma el flujo de vistas y lo arranca con `ft.app(target=main, ...)`.

---

## Flujo de vistas

### `bifrost-mount` (desktop puro)

```
view_update → view_login → view_minio → view_credentials (auto) → view_mount
```

En **Linux cluster** (`BIFROST_LINUX=1` o nombre de ejecutable contiene `_linux_cluster`), `view_mount` incluye sección CIFS con checkboxes para montar shares y un toggle opcional para usar credenciales de admin (`admin_<usuario>`).

### `bifrost-transfer` (desktop + web)

```
# Mac / Windows / Web:
view_update → view_login → view_minio → view_credentials (auto) → view_copy

# Linux cluster:
view_update → view_login → view_shares → view_minio → view_credentials → view_copy
```

`view_copy` contiene un **navegador de carpetas rclone** para elegir destino (`build_rclone_browser`), un selector de origen (local o share SMB), opciones de copia, y un panel de log en vivo (`ft.ListView` con `auto_scroll=True`).

### Credenciales STS — auto-renovación

Constantes en cada `main.py`:
```python
STS_RENEWAL_THRESHOLD_DAYS = 3
STS_AUTO_RENEWAL_DAYS = 7
```

Reglas:
- Si quedan **>3 días** en las credenciales STS → se saltan, va directo a `view_mount`/`view_copy`.
- Si quedan **<3 días** o no hay credenciales → renueva automáticamente por 7 días mostrando progreso.

No hay botón manual de renovación en el flujo normal.

---

## Modo web (`bifrost-transfer` — Open OnDemand)

Esta sección documenta lo que diferencia el modo web del desktop. Es **crítico**: la mayoría de bugs de Bifrost han salido de aquí.

### Detección

```python
DEV_WEB = os.environ.get("BIFROST_DEV") == "1"
IS_WEB  = ("--web" in sys.argv) or (__name__ != "__main__") or DEV_WEB
```

- OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → `IS_WEB=True`.
- `flet run --web` o `BIFROST_DEV=1 flet run` también activan modo web.

El servidor ASGI bajo modo web es **Hypercorn** (event loop asyncio único). Cada pestaña del navegador abre su propio WebSocket con su propio objeto `page`.

### Persistencia de sesión: `_WEB_SESSIONS`

Diccionario global en memoria, indexado por `username`. TTL = vida del proceso Hypercorn (= vida del job OOD). **La contraseña LDAP nunca se guarda aquí.**

Campos por sesión:
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
| `copy_log_callbacks` | `list[Callable]` | Funciones `log()` de páginas suscritas |

Funciones de gestión:
- `_ws_save(usuario, state)` — guarda al navegar a la vista de copia
- `_ws_load(usuario) → dict | None` — devuelve sesión si tiene al menos `perfil_rclone` y `endpoint`
- `_ws_clear(usuario)` — limpia al logout; cancela timer pendiente y vacía callbacks

### Flujo de reconexión (pestaña cerrada y reabierta)

1. Flet asigna una `page` nueva con un WebSocket nuevo.
2. `main(page)` se re-ejecuta desde cero para esa página.
3. `go_login()` consulta `_LAST_WEB_USER[0]` y pre-rellena el username si hay sesión.
4. Usuario introduce **solo la contraseña** (LDAP re-auth); no vuelve a pasar por selección de servidor MinIO ni descarga de shares.
5. Si la contraseña vale, salta directamente a `_build_copy_content`.
6. `_build_copy_content` detecta sesión activa y lanza el hilo `_replay`.

`_replay`:
- Espera 200 ms para que se estabilice el árbol de controles.
- Muestra banner de reconexión con el estado actual.
- Reproduce las últimas **200 líneas** del buffer (el resto está en `~/bifrost-logs/`).
- Si `proc.poll() is None` → restaura el botón Cancel y lanza `_watch_proc_end`.
- Si el proceso ya terminó → ajusta `copy_status` a `"done"` o `"error"`.

### Log dispatcher con throttle (`_dispatch_log`)

rclone con 8 transferencias paralelas genera >15 líneas/s. Sin throttle, cada línea haría un `page.update()` y saturaría el event loop de Hypercorn (síntoma: reconectar se queda eternamente en "checking for updates").

Solución: throttle de **150 ms**.

```
_dispatch_log(msg)
  ├── append a copy_log_buffer (cap 5000)
  ├── append a _dispatch_pending
  ├── si han pasado ≥150 ms desde último flush → flush inmediato
  └── si no → armar threading.Timer(0.2s) si no hay uno pendiente
                  └── _flush_log_callbacks()
                        └── itera copy_log_callbacks → cb(combined_lines)
                              └── log(msg) → ui_call(page, _add) → page.update()
```

`copy_log_callbacks` permite que múltiples pestañas del mismo usuario reciban el mismo log. Callbacks que fallen (página muerta) se eliminan automáticamente. El lock `_dispatch_lock` protege `_dispatch_pending` y `_dispatch_last` de carreras entre el timer y el hilo de rclone.

### Autosave de logs

Al terminar cada copy/check, `_autosave_log()` vuelca el buffer a:
```
~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log
```

Crítico en modo web: el buffer en memoria está capeado a 5000 líneas y solo se replayean 200 en pantalla; el log completo solo existe en disco.

---

## El bug `IndexError: list index out of range` — regla absoluta

### Síntoma
```
File "object_patch.py", line 889, in _compare_lists
    target_key = dst_keys[i]
IndexError: list index out of range
```

Ocurría al cambiar foco de la pestaña durante una copia, o al iniciar una copia.

### Causa raíz

Flet calcula un diff (`ObjectPatch.from_diff`) sobre el árbol de controles **en el thread del event loop asyncio**, sin lock. El código original usaba `page.run_thread(fn)` para actualizar UI desde hilos de background — `run_thread` ejecuta en un `ThreadPoolExecutor` **en paralelo real** al event loop.

```
event loop (diff):  cuenta controls 0,1,2,3,4…
worker thread:                                ← controls.clear()
event loop (diff):                            …5? → CRASH
```

El GIL no ayuda porque el diff y `.clear()` abarcan múltiples opcodes.

### Solución

Cambiar `page.run_thread(fn)` por `page.run_task(async_wrapper)` — esto encola la coroutine en el **mismo event loop single-threaded** mediante `asyncio.run_coroutine_threadsafe`. Asyncio es cooperativo: como `_compare_lists` no tiene ningún `await`, no puede ser interrumpido por la coroutine encolada.

Implementado en `backend.ui_call`:
```python
def ui_call(page: ft.Page, fn: Callable) -> None:
    async def _wrapper():
        fn()
    page.run_task(_wrapper)
```

También se corrigieron los `threading.Timer` que llamaban directamente funciones de navegación de carpetas:
```python
# Mal:
threading.Timer(0.1, dest_browser_refresh).start()
# Bien:
threading.Timer(0.1, lambda: ui_call(page, dest_browser_refresh)).start()
```

### Regla general

> **Toda mutación de `control.controls` o llamada a `page.update()` desde fuera del event loop de Flet debe envolverse en `ui_call(page, fn)`.**

Los únicos sitios donde se puede llamar `page.update()` directamente son los event handlers de Flet (botones, dialogs, …) porque Flet los ejecuta ya como tareas asyncio.

---

## Variables de entorno relevantes para el frontend

| Variable | Aplica a | Efecto |
|---|---|---|
| `BIFROST_DEV=1` | transfer | Fuerza `IS_WEB=True` y `DEV_WEB=True` (simula modo web en local) |
| `BIFROST_CLUSTER=1` | transfer | Fuerza `IS_LINUX_CLUSTER=True` (flujo CIFS/shares) |
| `BIFROST_LINUX=1` | mount | Fuerza `IS_LINUX_CLUSTER=True` en bifrost-mount |
| `FLET_ASSETS_DIR` | ambas | Lo setea Flet runtime; usado por el backend para localizar `rclone` |

---

## Convenciones de UI

- **Todo en español** — labels, mensajes, comentarios, nombres de variables de UI (`btn_aceptar`, `lbl_estado`, …).
- **Colores** — usar siempre las constantes de `bifrost_frontend.frontend` (`C_PRIMARY`, `C_ERROR`, …). No hardcodear hex.
- **Botones** — preferir `btn_primary` / `btn_secondary` sobre `ft.Button` crudo para mantener estilo consistente.
- **Threads** — `backend.safe_thread(page, target)` en lugar de `threading.Thread`. Si necesitas un `threading.Timer`, envuelve el callback en `lambda: ui_call(page, fn)`.
- **Diálogos de error** — `show_dialog(page, "Error", msg, color=C_ERROR)`.
- **Logs de copia** — pasar siempre por `_dispatch_log` (en transfer/web). Nunca llamar `log_list.controls.append(...)` directamente desde un hilo.

---

## Empaquetado por app

| Plataforma | Comando | Genera |
|---|---|---|
| macOS | `flet build macos` (vía `build-macos.sh`) | `dist/<app>.app` |
| Windows | `flet build windows` + Inno Setup (`installer.iss`) | `dist/<app>/...` + `.exe` instalador |
| Linux | `flet build linux` (CI) | binario para cluster |

Antes de `flet build` hay que generar el wheel `bifrost-shared` y reescribir `__BUILDPATH__` en el `pyproject.toml` de la app. `build-local.ps1` automatiza esto en Windows; CI (`.github/workflows/main.yml`) lo hace para macOS/Windows en cada push a `main`/`release`/`develop`/`feature/**`.
