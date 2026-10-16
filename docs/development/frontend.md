# Frontend — apps Flet (`bifrost-mount` / `bifrost-transfer`) y `shared/bifrost_frontend`

## Estructura por app

Ambas apps comparten el layout base:

```text
<app>/
  pyproject-template.toml  # Plantilla versionada; el pyproject.toml efectivo es local
  installer.iss            # Inno Setup (Windows)
  build-macos.sh
  frameworks/              # fuse_t.framework (mount, macOS) — descargado (no versionado)
  src/
    main.py                # GUI Flet — punto de entrada
    config.py              # APP_INFO = {"flavour": ..., "name": ..., "description": ...}
    version.py             # __version__ — generado por CI/build local
    assets/
      bin/                 # rclone(.exe) — descargado con los downloaders (no versionado)
    views/                 # vistas propias de la app
    storage/               # (solo transfer) datos temporales
```

Cada `main.py` se limita al arranque, la navegación entre vistas y la limpieza
al salir; el resto vive en módulos propios:

| App | Módulos de `src/` además de `main.py` |
|---|---|
| `bifrost-mount` | `session_log.py` (log de sesión: `_write_to_log_file`, `_log_event` → `~/bifrost-mount-logs/`), `views/mount.py` (`build_rclone_browser`, que aquí es una lista de buckets, y `_build_mount_bucket`, la vista de montaje). |
| `bifrost-transfer` | `web_session.py` (sesiones del modo web), `meta_fields.py`, `views/shares.py` (`_build_shares_content`), `views/rclone_browser.py` (`build_rclone_browser`, navegador de carpetas del destino), `views/local_fs.py` (`build_local_fs_browser`, `show_local_fs_modal`), `views/copy.py` (`_build_copy_content`), `views/tag_manager.py` (`_build_tag_manager_content`). |

`build_rclone_browser` se llama igual en las dos apps pero son funciones
distintas.

## `shared/bifrost_frontend`: tema, componentes y vistas comunes

`frontend.py` es una fachada que reexporta `theme.py` (paleta `C_*`, fuentes,
`apply_theme`), `components.py` (`btn_primary`, `btn_secondary`, `card`,
`section_title`, `field_label`, `styled_field`, `status_badge`,
`show_dialog`, `show_confirm`, `build_header`) y las vistas de `views/`. Las
vistas comunes existen una sola vez y lo que cambia entre apps se pasa como
parámetro:

| Vista | Firma | Qué hace |
|---|---|---|
| `views/update.py` | `build_update_content(page, on_continue)` | Primera pantalla: comprueba releases en GitHub e instala la actualización. |
| `views/login.py` | `build_login_content(page, on_success, prefill_user="", *, no_ldap, is_web=False, log_event=print)` | Login LDAP. Mientras valida bloquea el botón y los dos campos (`_set_busy`), así no se puede lanzar una segunda validación con clic + Enter. El mensaje de error depende del motivo de `validar_credenciales_ldap` (`_LDAP_ERROR_MESSAGES`); si falta un campo dice cuál ("Username is required." / "Password is required."). La contraseña no se recorta con `strip()`. `log_event` recibe `LOGIN attempt`, `LOGIN bypass LDAP`, `LOGIN success` y `LOGIN failed — reason: <motivo>` (mount pasa `_log_event`, que escribe en el fichero; transfer usa `print`). `prefill_user` (modo web) rellena el usuario y muestra el aviso "Resuming previous session". |
| `views/minio.py` | `build_minio_content(page, on_continue, *, no_ldap, is_web=False)` | Selección de servidor MinIO. |
| `views/credentials.py` | `build_credentials_content(page, perfil_rclone, endpoint, credenciales_ldap, on_continue, extra_config=None, duracion_dias=None, on_back=None, *, no_ldap, is_web=False, done_message, write_log=None)` | Renovación STS con log en pantalla. `write_log` escribe además cada línea en un fichero (mount pasa `_write_to_log_file`); `done_message` es la última línea ("Loading mount interface…" en mount, "Continuing to copy interface…" en transfer). |

Un arreglo en estas vistas se hace aquí, una vez para las dos apps; no hay que
volver a copiarlas en las apps.

## Cómo se inicializa la app

Cada `main.py` empieza con:

```python
from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *      # tema + componentes + vistas comunes
```

A continuación:

1. (Transfer) calcula el modo de ejecución (`IS_WEB`) y llama a
   `_propagar_is_web()` (ver «Modo web»).
2. Reenvuelve `sys.stdout`/`sys.stderr` en UTF-8 (consola Windows). No tocar.
3. Configura el log persistente: en `bifrost-mount`, `session_log.py` escribe
   en `~/bifrost-mount-logs/`; en `bifrost-transfer`, toda la salida de consola
   se duplica en `~/bifrost-logs/bifrost-console-*.log` (se conservan los 50
   ficheros más recientes).
4. Define `main(page: ft.Page)`, arma el flujo de vistas y lo arranca con
   `ft.run(main)`. En modo clúster, transfer además crea la app ASGI con
   `ft.app(main, export_asgi_app=True)`.

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

## Credenciales STS — renovación automática y manual

Constantes en `bifrost_backend.common.constants` (las dos apps las importan de
ahí):

```python
STS_RENEWAL_THRESHOLD_DAYS = 3
STS_AUTO_RENEWAL_DAYS = 7
```

Al elegir servidor, `main.py` consulta `backend.get_session_info(perfil)`:

- Si quedan **más de 3 días** de validez y el token es del usuario que ha
  iniciado sesión, se reutilizan las credenciales y se salta
  `view_credentials`.
- Si no hay token, no se puede leer, es de otro usuario o le quedan **3 días o
  menos** (`needs_renewal(usuario, STS_RENEWAL_THRESHOLD_DAYS)`), se renuevan
  automáticamente por 7 días mostrando progreso (`build_credentials_content`).

Además, la vista de montaje y la de copia muestran un badge con el tiempo
restante (`🔑 Credentials expire in 6d 23h`; rojo con menos de 1 día, ámbar
hasta 3 días) y un botón **"🔑 Renew credentials"** que abre un diálogo para
renovar a mano entre 1 y 30 días (7 por defecto). Al terminar se vuelve a la
vista de origen.

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
`meta_fields.py`, nunca en las vistas ni en `main.py`.

## Modo web (`bifrost-transfer` — Open OnDemand)

### Detección

```python
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

- OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → modo web.
- `flet run --web` activa el modo web en desarrollo local (con Flet 0.84 puede
  fallar; ver la alternativa con `FLET_FORCE_WEB_SERVER` en
  [build-and-ci.md](build-and-ci.md)).
- `BIFROST_CLUSTER=1` fuerza el modo web completo (flujo CIFS/shares del
  cluster Linux).
- Además, `main(page)` hace `IS_WEB = IS_WEB or page.web`: si Flet sirve la
  página por web, el modo web se activa aunque no se haya pasado `--web`.

`IS_WEB` solo existe de verdad en `main.py`, porque depende de `__name__`. Los
módulos que se sacaron de `main.py` y lo leen (`web_session`, `views.shares`,
`views.copy`, `views.tag_manager`) declaran `IS_WEB = False`, y
`_propagar_is_web()` les copia el valor real al importar y justo después de la
línea de `main()` que lo actualiza. Las funciones leen la variable de su
módulo al ejecutarse, por eso basta con actualizarla. Si un módulo nuevo lee
`IS_WEB`, hay que añadirlo a la tupla de `_propagar_is_web()`; si no, se
comportará siempre como escritorio sin dar ningún error.

El servidor ASGI es **Hypercorn** con un único event loop asyncio para toda la
aplicación. Cada pestaña del navegador abre su propio WebSocket con su propio
objeto `page`.

### Por qué existe el modo web

En modo desktop, cerrar la ventana mata el proceso. En web, el proceso
Hypercorn vive mientras dure el job de OOD: el usuario puede cerrar la
pestaña (se rompe el WebSocket, Flet destruye la `page`) y **el proceso rclone
sigue corriendo**. Todo lo que sigue existe para gestionar esa supervivencia.

### Persistencia de sesión: `_WEB_SESSIONS`

Diccionario global en memoria indexado por `username`, definido en
`bifrost-transfer/src/web_session.py` junto con `_LAST_WEB_USER` y las
funciones de gestión; `main.py` los importa (es el mismo objeto, nadie los
reasigna). TTL = vida del proceso Hypercorn (= vida del job OOD). **La
contraseña LDAP nunca se guarda aquí.**

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
`endpoint`), `_ws_clear(usuario)` (borra la sesión; cancela el timer de
throttle pendiente y vacía los callbacks para no dispararlos en páginas
muertas). No hay logout: `_ws_clear` se usa cuando, al restaurar una sesión
previa, el usuario escribe un username distinto; entonces se descarta la
sesión antigua y se sigue el flujo normal.

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
| `BIFROST_NO_LDAP=1` | ambas | Salta la validación LDAP en el login (`NO_LDAP`, en `bifrost_backend.common.constants`); el badge muestra `DESKTOP (NO LDAP)` |
| `FLET_ASSETS_DIR` | ambas | La setea Flet en runtime; el backend la usa para localizar `rclone` y, en mount/macOS en desarrollo, `fuse_t.framework` |
| `FLET_FORCE_WEB_SERVER=true` | transfer (desarrollo) | Hace que `ft.run(main)` sirva la app por web (puerto 8000) en lugar de abrir una ventana; alternativa a `flet run --web` (ver [build-and-ci.md](build-and-ci.md)) |

## Convenciones de UI

- **Idioma** — seguir el código de alrededor: los textos de la UI (botones,
  etiquetas, mensajes) están en inglés ("Authenticate", "Continue →",
  "▶  Copy data"…), y los nombres de funciones, comentarios y docstrings,
  mayoritariamente en español. Los mensajes del flujo WinFsp en
  `bifrost-mount` también están en inglés.
- **Colores** — solo constantes de `bifrost_frontend.frontend`
  (`C_PRIMARY`, `C_ERROR`, …); no hardcodear hex.
- **Botones** — preferir `btn_primary` / `btn_secondary` sobre `ft.Button`
  crudo.
- **Threads** — `backend.safe_thread(page, target)` en lugar de
  `threading.Thread`; con `threading.Timer`, envolver el callback en
  `lambda: ui_call(page, fn)`.
- **Diálogos de error** — `show_dialog(page, "Error", msg, color=C_ERROR)`.
- **Confirmaciones** — `show_confirm(page, title, message, on_yes, on_no=None)`.
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
