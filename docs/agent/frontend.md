# Frontend — `main.py` (ambas apps)

Capa de UI Flet. `bifrost-mount/src/main.py` ≈ 1398 LOC (desktop puro). `bifrost-transfer/src/main.py` ≈ 4130 LOC (desktop + web + Tag Manager).

## Inicialización

Cada `main.py`:
1. Importa `backend`, `frontend.*`, `APP_INFO`, `__version__` (transfer además `meta_fields`).
2. Detecta modo: `IS_WEB` (transfer), `NO_LDAP = BIFROST_NO_LDAP=="1"`.
3. Reenvuelve `sys.stdout`/`sys.stderr` en UTF-8 (Windows console) — **no tocar**.
4. Configura log persistente: mount → `~/bifrost-mount-logs/`; transfer → `~/bifrost-logs/` (mismo dir en desktop y web).
5. `ft.run(main)` al final (`if __name__ == "__main__"`).

`bifrost-transfer` además, si `BIFROST_CLUSTER=1`, monta un bloque ASGI (FastAPI + `ft.app(main, export_asgi_app=True)`) al final del fichero para OOD.

## Detección modo web (transfer)

```python
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")
```

OOD importa `main.py` como módulo ASGI → `__name__ != "__main__"` → `IS_WEB=True`. Servidor ASGI: **Hypercorn** (event loop asyncio único). Cada pestaña = WebSocket independiente con su `page`.

## Flujo de vistas (ver `architecture.md`)

`view_credentials` es automático (STS >3 días → skip; <3 días → renueva 7 días). En `view_copy` (transfer): navegador de carpetas rclone para destino (`build_rclone_browser`), selector de origen (local o share SMB), opciones de copia, log en vivo (`ft.ListView auto_scroll=True`).

## Tag Manager (solo transfer)

`_build_tag_manager_content` en `main.py`: navega buckets/carpetas/ficheros S3, aplica tagsets masivamente **sin re-subida**. Al seleccionar un fichero, si sus tags encajan un perfil → `detect_profile()` cambia al perfil con valores pre-rellenados (`build_meta_fields(..., prefill_values=tags)`). Botón "Ver tags raw" vuelve a la vista clave/valor. Usa las 6 funciones boto3 del backend. Ver `meta-fields.md`.

## Visibilidad condicional en el formulario de copia

En `_build_copy_content`, las secciones METADATA, botones de acción y LOG OUTPUT están ocultas (`bottom_col.visible=False`) hasta que se selecciona un bucket en el browser de destino. Toggle en `on_browser_select`: path no-vacío → visible; vuelve a root → oculto.

## Filtro de laboratorio en browsers de buckets

Browser de destino (copy) y browser del Tag Manager incluyen "Filter by lab…" (`build_lab_filter_widget` de `meta_fields.py`). Lee el tag `acronym` de cada bucket con `backend.get_bucket_tags` en paralelo (`ThreadPoolExecutor`). Se oculta al navegar dentro de un bucket y reaparece al volver al root. **Solo filtra en nivel de buckets (root)**; dentro de un bucket no hay filtrado. Ver `meta-fields.md`.

## Thread-safety — regla absoluta

> Toda mutación de `control.controls` o llamada a `page.update()` desde fuera del event loop de Flet debe envolverse en `backend.ui_call(page, fn)`.

Origen: bug `IndexError: list index out of range` en `object_patch.py:_compare_lists`. El diff walker de Flet recorre `controls` en el thread asyncio sin lock; `page.run_thread(fn)` ejecuta en ThreadPoolExecutor en paralelo real → `.clear()`/`.extend()` desde el worker choca con el diff → crash. `ui_call` usa `page.run_task` (asyncio cooperivo, sin `await` en `_compare_lists` → no hay preempt). Ver `backend.md`.

Únicos sitios donde `page.update()` va directo: event handlers de Flet (botones, diálogos) — ya son tareas asyncio.

`threading.Timer` que mute UI: envolver callback en `lambda: ui_call(page, fn)`.

## Modo web (transfer) — internals

### `_WEB_SESSIONS` (global, indexado por username)

TTL = vida del proceso Hypercorn (= vida del job OOD). **La contraseña LDAP nunca se guarda.** Campos: `servidor_minio`, `perfil_rclone`, `endpoint`, `extra_config`, `copy_log_buffer` (cap 5000), `copy_status` (`idle|running|done|error`), `copy_origen`, `copy_destino`, `copy_proceso` (`{"proc": Popen|None}`), `copy_log_callbacks` (funciones `log()` de páginas suscritas).

Gestión: `_ws_save(usuario, state)`, `_ws_load(usuario) → dict|None` (devuelve sesión si tiene `perfil_rclone` y `endpoint`), `_ws_clear(usuario)` (logout; cancela timer throttle pendiente y vacía callbacks). `_LAST_WEB_USER = [None]` (lista de 1 elemento para mutación en closures).

### Reconexión (pestaña cerrada y reabierta)

1. Flet asigna `page` nueva con WebSocket nuevo.
2. `main(page)` re-ejecuta desde cero.
3. `go_login()` consulta `_LAST_WEB_USER[0]`; pre-rellena username si hay sesión.
4. Usuario introduce **solo la contraseña** (LDAP re-auth); no repite selección MinIO ni descarga shares.
5. Si OK → `_build_copy_content` detecta sesión activa y lanza hilo `_replay`.
6. `_replay`: espera 200 ms, muestra banner de reconexión, reproduce últimas **200 líneas** del buffer (el resto en `~/bifrost-logs/`), restaura botón Cancel si `proc.poll() is None` y lanza `_watch_proc_end`, o ajusta `copy_status` a `done`/`error` si ya terminó.

### Log dispatcher con throttle (`_dispatch_log`)

rclone con 8 transfers paralelas >15 líneas/s. Sin throttle, cada línea haría `page.update()` y saturaría Hypercorn (síntoma: reconectar se cuelga en "checking for updates"). Solución: throttle **150 ms**.

```
_dispatch_log(msg)
  ├── append a copy_log_buffer (cap 5000)
  ├── append a _dispatch_pending
  ├── si ≥150 ms desde último flush → flush inmediato
  └── si no → armar threading.Timer(0.2s) si no hay uno pendiente
          └── _flush_log_callbacks()
                └── itera copy_log_callbacks → cb(combined_lines)
                      └── log(msg) → ui_call(page, _add) → page.update()
```

`copy_log_callbacks` permite múltiples pestañas del mismo usuario recibiendo el mismo log. Callbacks que fallen (página muerta) se eliminan. `_dispatch_lock` protege `_dispatch_pending` y `_dispatch_last` de carreras timer↔rclone.

### Autosave de logs

Al terminar cada copy/check, `_autosave_log()` vuelca el buffer a `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log`. Crítico en web: buffer cap 5000, solo se replayean 200 en pantalla; el log completo solo existe en disco.

## Autoupdate

`build_update_content` (en `frontend.py`, compartido) pregunta al usuario si actualizar. `check_update_version()` consulta la release más reciente del repo GitHub; `download_new_binary("bifrost-<flavour>")` descarga el binario nuevo. En Windows lanza un `.bat` que instala el Inno Setup silenciosamente y reabre la app; en macOS usa `osascript` con `ditto` para reemplazar el `.app` en `/Applications`; en Linux `os.replace` sobre `sys.argv[0]`. Ver `build-release.md`.

## Convenciones de UI

- **Idioma**: labels/mensajes/comentarios en español; excepción: flujo WinFsp de `bifrost-mount` en inglés (alineado con esa UI). UI de transfer mezcla inglés y español.
- **Colores**: constantes de `bifrost_frontend.frontend` (`C_PRIMARY`, `C_ERROR`, …). No hardcodear hex.
- **Botones**: `btn_primary` / `btn_secondary` sobre `ft.Button` crudo.
- **Diálogos de error**: `show_dialog(page, "Error", msg, color=C_ERROR)`.
- **Logs de copia**: siempre por `_dispatch_log` (transfer/web). Nunca `log_list.controls.append(...)` directo desde un hilo.
- **Header**: `build_header(subtitle, IS_WEB, no_ldap)` muestra badge `WEB` / `DESKTOP` / `DESKTOP (NO LDAP)`.
