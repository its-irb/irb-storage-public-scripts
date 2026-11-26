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
    version.py             # __version__ — 0.0.0.dev en el repositorio; CI escribe la real
    assets/
      bin/                 # rclone(.exe) — descargado con los downloaders (no versionado)
    views/                 # vistas propias de la app
    storage/               # (solo transfer) datos temporales
```

Cada `main.py` se limita al arranque, la navegación entre vistas y la limpieza
al salir; el resto vive en módulos propios:

| App | Módulos de `src/` además de `main.py` |
|---|---|
| `bifrost-mount` | `views/servers.py` (`build_servers_content`: una tarjeta por servidor MinIO; lo monta, lo abre o lo desmonta en un hilo y pregunta su estado al backend, `active_mount_point`, en vez de guardarlo), `views/server_card.py` (`ServerCard`: nombre, dirección, caducidad de las credenciales, dónde está montado, Mount/Open, Unmount y Renew credentials; doble clic = Mount; no llama al backend), `views/winfsp_dialog.py` (`prompt_install_winfsp`). El diálogo Renew es común (`show_renew_dialog`, ver abajo). |
| `bifrost-transfer` | `web_session.py` (sesiones del modo web), `meta_fields.py`, `views/shares.py` (`_build_shares_content`), `views/rclone_browser.py` (`build_rclone_browser`, navegador de carpetas del destino), `views/local_fs.py` (`build_local_fs_browser`, `show_local_fs_modal`), `views/copy.py` (`_build_copy_content`), `views/tag_manager.py` (`_build_tag_manager_content`). |

`build_rclone_browser` solo existe en transfer (navegador de carpetas).

## `shared/bifrost_frontend`: tema, componentes y vistas comunes

`frontend.py` es una fachada que reexporta `theme.py` (paleta `C_*`, fuentes,
`apply_theme`, `tint`), `components.py` y las vistas de `views/`.

Componentes de `components.py`:

| Componente | Qué es |
|---|---|
| `btn_primary(text, on_click=None, width=None, disabled=False, icon=None)`, `btn_secondary(text, on_click=None, width=None, icon=None)` | Botones; `icon` es un icono de Material (`ft.Icons.*`). |
| `btn_nav(text, on_click=None, icon=ft.Icons.ARROW_BACK)` | Botón discreto de navegación ("Back to login"). |
| `nav_bar(back_text=None, on_back=None, *, usuario=None)` | Fila de arriba de cada pantalla: volver a la izquierda (solo con `on_back`) y "Signed in as <usuario>" a la derecha. |
| `icon_tile(icon, color, size=44)` | Icono sobre un cuadrado redondeado de su color, translúcido (cabecera de tarjetas y diálogos). |
| `expiry_label(session) -> (texto, color)`, `expiry_chip(session)` | Texto y color de la caducidad de las credenciales (rojo con menos de 1 día, ámbar hasta 3) y su etiqueta con icono de llave. |
| `card`, `section_title`, `field_label`, `styled_field`, `status_badge`, `build_header`, `log_text` | Como antes. |
| `open_dialog(page, *, title, color, icon, body, actions, subtitle="")` | Diálogo modal con el aspecto común: icono, título, subtítulo opcional, cuerpo y botones a la derecha. |
| `show_dialog`, `show_issue`, `show_confirm` | Avisos, errores del programa y Sí/No (ver «Convenciones de UI»). |
| `tip_box(text)`, `error_code_row(page, ref)` | Recuadro "What you can do" y fila del código de error con botón para copiarlo. |
| `ErrorBanner(value="", visible=…)` | Error dentro de una pantalla o diálogo (recuadro rojo con icono). Se usa igual que el `ft.Text` rojo al que sustituye: se cambian `value` y `visible`, así que la lógica de cada pantalla no cambia; quita un "⚠️"/"❌" inicial porque ya lleva icono. |

Las vistas comunes existen una sola vez y lo que cambia entre apps se pasa como
parámetro:

| Vista | Firma | Qué hace |
|---|---|---|
| `views/update.py` | `build_update_content(page, on_continue)` | Primera pantalla: comprueba releases en GitHub e instala la actualización. |
| `views/login.py` | `build_login_content(page, on_success, prefill_user="", *, no_ldap, is_web=False)` | Login LDAP. Mientras valida bloquea el botón y los dos campos (`_set_busy`), así no se puede lanzar una segunda validación con clic + Enter. El mensaje de error depende del motivo de `validar_credenciales_ldap` (`_LDAP_ERROR_MESSAGES`); si falta un campo dice cuál ("Username is required." / "Password is required."). La contraseña no se recorta con `strip()`. Deja en el log técnico (logger `bifrost.login`) `LOGIN attempt`, `LOGIN bypass LDAP` y `LOGIN success`, con `— user: <usuario>`, y `LOGIN failed — user: <usuario> — reason: <motivo>`; igual en las dos apps. `prefill_user` (modo web) rellena el usuario y muestra el aviso "Resuming previous session". |
| `views/minio.py` | `build_minio_content(page, on_continue, *, no_ldap, is_web=False, on_back=None, usuario=None)` | Selección de servidor MinIO (transfer): una tarjeta por servidor con la caducidad de sus credenciales; clic = elegir, doble clic o "Continue" = seguir. `on_back` vuelve al login; `usuario` se muestra arriba a la derecha. |
| `views/credentials.py` | `build_credentials_content(page, perfil_rclone, endpoint, credenciales_ldap, on_continue, extra_config=None, duracion_dias=None, on_back=None, *, no_ldap, is_web=False, done_message, on_cancel=None, cancel_label="Back")` | Renovación STS: tarjeta de estado (renovando / error / renovadas) y log en pantalla. Si falla, dice qué hacer (`tip_box`), el código (`error_code_row`) y ofrece "Try again", salvo con contraseña incorrecta sin LDAP (`on_back`): ahí sale "Back to login", porque reintentar repetiría la misma contraseña. Una excepción inesperada durante la renovación también acaba en el estado de error, no deja la pantalla colgada. Con `on_cancel`, un botón de `nav_bar` (`cancel_label`) sale en cualquier momento; desde entonces el hilo que siga en marcha no toca la pantalla ni navega (si no, al terminar llevaría al usuario a otra pantalla). Al log técnico (logger `bifrost.auth`) no va el texto de la pantalla, sino una línea por paso (`credentials: renewing …`, `credentials: renewed …`, `credentials: retrying …` y los fallos de la petición a MinIO); `done_message` es la última línea ("Loading servers…" en mount, "Continuing to copy interface…" en transfer). |
| `views/renew_dialog.py` | `show_renew_dialog(page, *, perfil, usuario, on_renew)` | Diálogo "Renew MinIO credentials" (1-30 días, 7 por defecto; Enter confirma) que llama a `on_renew(días)`. Lo usan las tarjetas de mount y la vista de copia de transfer; antes estaba duplicado en las dos apps. |

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
3. Configura el log técnico con `backend.setup_logging(...)` (ver
   [operations.md](operations.md#logs)) y registra el cierre con
   `backend.register_shutdown(...)`. `main()` llama a `install_window_close(page)`: al cerrar la ventana,
   `backend.request_shutdown("window")`, destruir la ventana y salir.
4. Define `main(page: ft.Page)`, arma el flujo de vistas y lo arranca con
   `ft.run(main)`. En modo clúster, transfer además crea la app ASGI con
   `ft.app(main, export_asgi_app=True)`.

## Flujo de vistas

```text
bifrost-mount (desktop puro):
  view_update → view_login ⇄ view_servers ⇄ view_credentials
  (view_servers: una tarjeta por servidor; cada servidor se monta entero, con sus
  buckets como carpetas. view_credentials sale al montar si hay que renovar, y
  vuelve a view_servers y monta; o desde "Renew credentials".)

bifrost-transfer (escritorio y web; en web no hay view_update, empieza en view_login):
  view_update → view_login ⇄ view_minio ⇄ view_credentials (auto) → view_copy
  view_copy ⇄ view_credentials (manual), view_copy ⇄ Tag Manager, view_copy ⇄ shares NetApp (web)
```

Todas las pantallas empiezan con un `nav_bar`: volver (arriba a la izquierda) y
"Signed in as <usuario>" (arriba a la derecha). A dónde vuelve cada una:
servidores/minio → login; renovación → servidores (automática) o copia (manual,
transfer); copia → minio; Tag Manager y NetApp → copia. El objetivo es que
ninguna pantalla sea un callejón sin salida: antes, si la renovación fallaba
(por ejemplo, sin VPN), la única salida era cerrar la app. En mount, volver al
login no desmonta nada: view_servers pregunta al backend qué está montado cada
vez que se construye. En transfer, los shares de NetApp (web) no son un paso
del flujo: se abren desde el botón "Mount NetApp" de la copia (`go_cifs`).

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

Al elegir servidor (transfer) o al montar uno (mount, `views/servers.py`), la app llama a
`backend.hay_que_renovar_credenciales(perfil, usuario)`, que deja la
decisión en una línea del log técnico:

- Si quedan **más de 3 días** de validez y el token es del usuario que ha
  iniciado sesión, se reutilizan las credenciales y se salta
  `view_credentials`.
- Si no hay token, no se puede leer, es de otro usuario o le quedan **3 días o
  menos** (`needs_renewal(usuario, STS_RENEWAL_THRESHOLD_DAYS)`), se renuevan
  automáticamente por 7 días mostrando progreso (`build_credentials_content`).

Además, cada tarjeta de servidor de mount, cada tarjeta de la selección de
servidor de transfer y la tarjeta del servidor de la vista de copia muestran una
etiqueta con el tiempo restante (`expiry_chip`: icono de llave y "Credentials
expire in 6d 23h"; rojo con menos de 1 día, ámbar hasta 3 días). Las tarjetas de
mount y la vista de copia tienen un botón **"Renew credentials"** que abre
`show_renew_dialog` para renovar a mano entre 1 y 30 días (7 por defecto). Al
terminar se vuelve a la vista de origen; con "Back to servers" / "Back to copy"
se vuelve sin esperar.

## `meta_fields.py` (solo bifrost-transfer)

Fuente canónica de los perfiles y campos de metadatos, compartida por el
formulario de copia y el Tag Manager:

- `FieldType` — tipos de campo del formulario.
- `TAG_PROFILES` — definición de perfiles (`IRB Standard`, `Histopathology IRB
  Core Facility`, `Advanced Genomic Technologies IRB Core Facility`) y sus
  campos. Cada campo es `(label, key, FieldType, allow_custom, options,
  helper[, required])`; con `required` el label se muestra con ` *`. **El nombre
  del perfil es el valor del tag `provider`**: así se identifica sin ambigüedad
  qué perfil se usó, y también es el criterio de detección. `provider` no se
  declara en `TAG_PROFILES`, lo añade `profile_fields`.
- `profile_fields(name)` — campos del perfil con el Provider primero, bloqueado
  (su única opción es el nombre del perfil).
- `apply_provider(name, values)` — devuelve `values` con `provider` forzado al
  nombre del perfil. Se aplica al pre-rellenar para que un objeto con un
  provider antiguo o ajeno no se reescriba tal cual: al guardar queda corregido.
- `missing_required(name, values)` — labels de los campos obligatorios vacíos
  (interna).
- `validate_profile_tagset(name, tags)` — **única** validación que llaman las
  vistas en Copy, Aplicar y Guardar fichero: caracteres y longitud
  (`validate_tagset`) más `Missing required fields: ...`, en un solo diálogo
  "Invalid tags". La longitud no se bloquea al teclear en los selectores
  múltiples; se valida aquí. Importa porque `application` y `library_kit` se
  unen con `:` y la suma puede superar los 256 caracteres.
- `check_tag_value(text, max_len=TAG_VALUE_MAX)`, `validate_tagset`,
  `TAG_KEY_MAX` (128) y `TAG_VALUE_MAX` (256) — límites de los tags de S3 y
  caracteres permitidos (`^[\w\s.:/=+\-@]*$`). Los valores de las opciones están
  saneados (sin `'` ni paréntesis) porque MinIO los rechaza.
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
  dict de tags (lo usa el Tag Manager para pre-cargar el editor). Primero por
  `provider` (== nombre del perfil) siempre que todas las keys del objeto sean
  del perfil; si hay keys ajenas devuelve `None` y el editor abre en modo raw,
  porque guardar en modo perfil las borraría sin aviso. Si el objeto no tiene
  `provider` o no coincide con ningún perfil (objetos antiguos), por subconjunto
  de keys.

Regla: cualquier cambio de campos, perfiles o labs se hace **solo** en
`meta_fields.py`, nunca en las vistas ni en `main.py`.

Restricciones a preservar:

- **10 tags por objeto como máximo** (incluido `provider`): IRB Standard usa 8,
  Genomics 9 e Histopathology 10, así que Histopathology no admite otro campo
  sin quitar uno.
- **Renombrar un perfil** cambia el valor de `provider` en los objetos nuevos;
  los ya etiquetados con el nombre anterior se detectan por keys.
- Las vistas no validan por su cuenta: todo pasa por `validate_profile_tagset`.

Tests: `bifrost-transfer/tests/test_meta_fields.py` cubre la validación, el
provider y los perfiles; `tests/conftest.py` añade `src` al `sys.path`. Se
ejecutan desde `bifrost-transfer/` con
`uv run --no-sync --with pytest python -m pytest tests -q` (pytest no es una
dependencia declarada del proyecto).

## Modo web (`bifrost-transfer` — Open OnDemand)

### Detección

```python
IS_CLUSTER = os.environ.get("BIFROST_CLUSTER") == "1"
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or IS_CLUSTER
```

**Por qué hay dos variables.** `IS_WEB` responde a «¿hay navegador?» e
`IS_CLUSTER` a «¿me sirve Hypercorn en OOD?». No son lo mismo:

| Cómo se arranca | `IS_WEB` | `IS_CLUSTER` |
|---|---|---|
| Escritorio (`python main.py`) | False | False |
| Desarrollo web local (`flet run --web`, `python main.py --web`) | True | False |
| Cluster OOD (Hypercorn; `script.sh.erb` exporta `BIFROST_CLUSTER=1`) | True | True |

`IS_CLUSTER` controla lo que solo debe pasar en el cluster:

- El bloque `if IS_CLUSTER:` del final de `main.py`, que crea la app `FastAPI`,
  monta Flet y define el endpoint WebSocket con token (la `app` que Hypercorn
  carga como `main:app`). Con `IS_WEB` se ejecutaría también en desarrollo web
  local, donde Flet arranca su propio servidor, y chocarían.
- `register_shutdown(..., server_managed=IS_CLUSTER)`: en el cluster el cierre
  lo gestiona el servidor; en local, el propio proceso.

`IS_WEB` no puede sustituirla: bajo Hypercorn ya es True (`__name__ !=
"__main__"`), pero también lo es con `flet run`, así que no distingue el
cluster. **No quites `export BIFROST_CLUSTER=1`** de
`ood-app-bifrost/template/script.sh.erb`: sin él no existe `main:app` y
Hypercorn falla al arrancar. Historia: se intentó en la simplificación de
junio de 2026 (una sola `IS_WEB`, spec en `docs/superpowers/specs/`) y se
revirtió al día siguiente (`5e6246b`).

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
`views.copy`, `views.tag_manager`, `views.rclone_browser`) declaran `IS_WEB = False`, y
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
| `copy_origen` / `copy_destino` | `str` | Paths |
| `copy_proceso` | `dict` | `{"proc": Popen \| None, "cancelled": bool, "status": "running" \| outcome}`; se comparte por referencia entre páginas (el `status` de la última operación vive aquí) |
| `copy_log_callbacks` | `list[Callable]` | Funciones `log()` de las páginas suscritas |

Gestión: `_ws_save(usuario, state)` (guarda al navegar a la vista de copia),
`_ws_load(usuario)` (devuelve la sesión si tiene al menos `perfil_rclone` y
`endpoint`), `_ws_clear(usuario)` (borra la sesión; cancela el timer de
throttle pendiente y vacía los callbacks para no dispararlos en páginas
muertas). No hay logout: `_ws_clear` se usa cuando entra un username distinto
del último, tanto al restaurar una sesión previa como en un login normal;
entonces se descarta la sesión antigua y se sigue el flujo normal.

### Flujo de reconexión (pestaña cerrada y reabierta)

1. Flet asigna una `page` nueva con un WebSocket nuevo.
2. `main(page)` se re-ejecuta desde cero para esa página.
3. `go_login()` (con `resume=True`, el valor por defecto) consulta
   `_LAST_WEB_USER[0]` y pre-rellena el username si hay sesión.
4. El usuario introduce **solo la contraseña** (re-autenticación LDAP); no
   vuelve a pasar por selección de servidor MinIO ni descarga de shares.
5. Si la contraseña es válida, salta directamente a `_build_copy_content`.
6. `_build_copy_content` detecta la sesión activa y lanza el hilo `_replay`.

Esta restauración solo debe ocurrir al reabrir la pestaña. El botón "Back to
login" de la selección de servidor llama a `go_login(resume=False)`: un login
normal (`_on_login_fresh`) que lleva a la selección de servidor. Si usara la
restauración, al volver a entrar se saltaría la elección de servidor y volvería
a la copia con el servidor anterior. La sesión no se borra si entra el mismo
usuario, así que una copia en marcha sigue enlazada cuando se elige de nuevo
ese servidor (`_ws_save` conserva `copy_proceso`); si entra otro usuario, se
descarta con `_ws_clear`.

`_replay`:

- Espera 200 ms para que se estabilice el árbol de controles.
- Muestra un banner de reconexión con el estado actual.
- Reproduce las últimas **200 líneas** del buffer (el log completo de cada
  operación está en su informe, ver «Informe de cada operación»).
- Lee `copy_proceso["status"]`: si es `"running"` (desde el clic hasta
  `on_finish`, también mientras rclone aún no ha arrancado o se está
  parando) → arranca el ticker de progreso de la página (ver abajo), que
  restaura los botones. Si no, contiene el `outcome` del `RunSummary` (`ok`,
  `partial`, `differences`, `failed`, `cancelled`…) y se muestra un texto para
  cada caso.

### Bloque de progreso (`_start_progress_ticker`)

Encima de LOG OUTPUT, mientras `copy_proceso["status"] == "running"`. Un hilo
por página lee `RunSummary.progress_snapshot()` una vez por segundo (el hilo
de rclone solo guarda el último `stats`; la interfaz nunca lo frena) y pinta
texto, barra y hasta `MAX_CURRENT` ficheros en curso. También fija los
botones (Cancel visible salvo si `copy_proceso["cancelled"]`; Copy/Check
deshabilitados) y los restaura al terminar.

- Lo arrancan `do_copy`/`do_check`, `_replay` y `log()` si la operación está
  en marcha (así lo ve también otra pestaña de la misma sesión web).
- Solo tiene ticker la última vista de copia construida en la página: se
  registra en `page.session.store["copy_progress_ticker"]` y el de una vista
  anterior se para.
- Con la pestaña cerrada no envía nada (`ui_call` devuelve `False`) y sigue
  esperando por si Flet reconecta la misma sesión; si la operación termina
  mientras tanto, oculta el bloque sin `page.update()` y la reconexión ya lo
  recibe oculto. Si Flet destruye la sesión, el ticker se para.

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

### Informe de cada operación

Cada copy/check crea su propia lista de líneas (`_new_operation` → `op_log`, que
también llama a `_dispatch_log`). Al terminar, `ejecutar_rclone_copy/check`
llama siempre a `on_finish(summary)` y la vista escribe el informe con
`_write_report` en `backend.report_path("copy"|"check")`: exactamente las líneas
que vio el usuario en esa operación (inicio, origen y destino, todas las
etiquetas del perfil y resumen) y, debajo, `summary.problem_lines()`: los ficheros con
problemas, hasta 100. El panel solo da recuentos (ver «Logs» en
`operations.md`). No se usa
el buffer web (mezcla operaciones y está capeado a 5000 líneas) ni los
controles del panel. Cancel pone `_active_proceso["cancelled"] = True` antes de
terminar rclone; el resumen lo usa para decir "cancelled".

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
| `BIFROST_CLUSTER=1` | transfer | Activa `IS_CLUSTER` e `IS_WEB` (app FastAPI/Hypercorn y flujo CIFS/shares del cluster Linux); ver «Por qué hay dos variables» |
| `BIFROST_NO_LDAP=1` | ambas | Salta la validación LDAP en el login (`NO_LDAP`, en `bifrost_backend.common.constants`); el badge muestra `DESKTOP (NO LDAP)` |
| `FLET_ASSETS_DIR` | ambas | La setea Flet en runtime; el backend la usa para localizar `rclone` y, en mount/macOS en desarrollo, `fuse_t.framework` |
| `FLET_FORCE_WEB_SERVER=true` | transfer (desarrollo) | Hace que `ft.run(main)` sirva la app por web (puerto 8000) en lugar de abrir una ventana; alternativa a `flet run --web` (ver [build-and-ci.md](build-and-ci.md)) |

## Convenciones de UI

- **Idioma** — seguir el código de alrededor: los textos de la UI (botones,
  etiquetas, mensajes) están en inglés ("Authenticate", "Continue",
  "Copy data"…), y los nombres de funciones, comentarios y docstrings,
  mayoritariamente en español. Los mensajes del flujo WinFsp en
  `bifrost-mount` también están en inglés.
- **Colores** — solo constantes de `bifrost_frontend.frontend`
  (`C_PRIMARY`, `C_ERROR`, …); no hardcodear hex. Para fondos y bordes
  translúcidos, `tint(color, opacidad)` y nunca `f"{C_X}22"`: Flet lee
  `#RRGGBBAA` como `#AARRGGBB` y sale otro color (la etiqueta ámbar DESKTOP se
  veía roja y algunos fondos verdes, marrones).
- **Botones** — preferir `btn_primary` / `btn_secondary` sobre `ft.Button`
  crudo. El icono va en `icon=` (icono de Material), no como emoji en el texto:
  los emojis salen como cuadros en algunos sistemas.
- **Navegación** — cada pantalla empieza con `nav_bar(texto_volver, on_back,
  usuario=…)`; ninguna pantalla debe quedarse sin salida.
- **Threads** — `backend.safe_thread(page, target)` en lugar de
  `threading.Thread`; con `threading.Timer`, envolver el callback en
  `lambda: ui_call(page, fn)`.
- **Diálogos de error** — avisos sobre lo que escribe el usuario: `show_dialog(page, título, msg,
  color=C_ERROR)`. Errores del programa (`UserIssue`): `show_issue(page, issue, *, is_web, title=None,
  context="", screen=…, buttons=[(texto, acción), …], ref=None) -> str`: cabecera con icono y título, y debajo
  el contexto (el bucket, un fichero o un recuento; nunca listas ni rutas de logs); después qué ha pasado, el
  recuadro "What you can do" (`tip_box`) y el código ("MNT101-1103-141526") en su propia fila con un botón para
  copiarlo (`error_code_row`), que es lo que el usuario pasa a ITS; cada botón cierra el diálogo y ejecuta su
  acción. `screen` (`mount`, `netapp`, `copy`, `check`, `tags`, `app`) da el principio del código y la pista;
  con `ref` se reutiliza un código (el de una operación o el de la primera vez que se mostró) y devuelve el
  código. Para un error en lugar de una lista: `issue_line(issue, *, is_web, screen)` (texto de una línea con
  su código), que se muestra en un `ErrorBanner`. Las dos escriben `issue shown: ref=… code=… screen=…` en el
  log técnico con `issue_reference(issue, screen, ref=None)`, que la pantalla de credenciales (`CRD`) y el login
  (`LGN`) llaman directamente; el login solo anota la línea y no enseña el código (en esa pantalla sería
  ruido). Un diálogo nuevo usa `open_dialog` para tener el mismo aspecto.
- **Errores dentro de una pantalla o diálogo** — `ErrorBanner`, no un `ft.Text` rojo. La validación de un solo
  campo (metadatos, filas de tags) sigue siendo un texto rojo pequeño debajo del campo: un recuadro por campo
  cargaría demasiado el formulario.
- **Cabecera** — `build_header(subtitle, IS_WEB, no_ldap, page=None)`; con `page`, en escritorio, el botón
  "Export logs…" (confirmación y `backend.export_logs_zip()`). Todas las pantallas pasan `page`.
- **Líneas de los paneles de log** — `log_text(line)` (color según el emoji inicial; lo usan copy y el Tag
  Manager).
- **Confirmaciones** — `show_confirm(page, title, message, on_yes, on_no=None)` (misma cabecera, icono de pregunta).
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
