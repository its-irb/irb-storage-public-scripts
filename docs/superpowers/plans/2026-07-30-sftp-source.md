# SFTP Source for bifrost-transfer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir un tercer origen "🌐 SFTP" en la vista de copia de `bifrost-transfer`, junto a File/Folder, que permita conectar a un servidor SFTP (usuario/contraseña) y navegar sus carpetas para elegir el origen de la copia.

**Architecture:** El backend gana funciones para crear/borrar perfiles rclone tipo SFTP en `rclone.conf` (mismo patrón que los perfiles SMB existentes) y validar la conexión reutilizando `rclone_lsd`. El frontend añade un diálogo de conexión y reutiliza `build_rclone_browser` (ya genérico para cualquier perfil rclone) para navegar el servidor remoto. Al confirmar una carpeta, `origen_tf.value` queda como `"perfil:/path"` — el mismo formato que ya acepta hoy el campo, así que `do_copy`/`do_check` no cambian. El perfil rclone es efímero: se borra al desconectar, al salir de la vista de copy, y se barren huérfanos de sesiones anteriores al hacer login.

**Tech Stack:** Flet, rclone (backend `sftp`), `configparser`, `subprocess`

## Global Constraints

- Autenticación SFTP: solo usuario/contraseña (no clave privada) — spec `docs/superpowers/specs/2026-07-30-sftp-source-design.md`.
- El perfil rclone SFTP nunca sobrevive más allá de la sesión actual (o, en el peor caso de crash, hasta el siguiente login) — sección "Decisión de seguridad" del spec.
- Cero cambios en `do_copy`/`do_check`/`preparar_origen_para_check`/`traducir_a_ruta_local_montada`: el origen sigue siendo `"perfil:/path"`.
- No hay suite de tests automatizada en este repo (`CLAUDE.md`); toda verificación es manual (`python -c "import ..."` + `flet run`).
- Toda la UI nueva (botones, títulos, etiquetas) y todos los mensajes de error mostrados al usuario van en inglés, consistente con el resto de `bifrost-transfer` (campo "Source path", etc.). Los docstrings/comentarios internos del código siguen en español, igual que en el resto del archivo.
- Los commits de este repo se hacen con `npm run commit` (Commitizen interactivo), nunca con `git commit -m` directo — cada Step de commit indica qué responder en cada pregunta.

---

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `shared/bifrost_backend/backend.py` | `import uuid`; nueva sección "GESTIÓN SFTP (ORIGEN EFÍMERO)": `crear_perfil_rclone_sftp`, `eliminar_perfil_rclone`, `limpiar_perfiles_rclone_con_prefijo`, `generar_nombre_perfil_sftp`, `validar_conexion_sftp` |
| `bifrost-transfer/src/main.py` | Botón "🌐 SFTP", diálogo de conexión, modal de browser reutilizando `build_rclone_browser`, etiqueta "Connected" + Disconnect, hooks de cleanup en Back y en login |
| `CLAUDE.md` | Nuevo gotcha documentando el patrón de perfil rclone efímero SFTP |
| `README.md` | Mención de SFTP como origen soportado en la descripción de `bifrost-transfer` |

---

## Task 1: Backend — perfiles SFTP efímeros en `backend.py`

**Files:**
- Modify: `shared/bifrost_backend/backend.py`

**Interfaces:**
- Produces: `crear_perfil_rclone_sftp(nombre_perfil: str, host: str, port: str, username: str, password: str) -> None`, `eliminar_perfil_rclone(nombre_perfil: str, rclone_config_path: str | None = None) -> None`, `limpiar_perfiles_rclone_con_prefijo(prefijo: str, rclone_config_path: str | None = None) -> None`, `generar_nombre_perfil_sftp() -> str`, `validar_conexion_sftp(nombre_perfil: str, timeout: int = 15) -> tuple[bool, str | None]` (motivo ∈ `{"unreachable", "auth", "timeout", "other"}` cuando `False`)

- [ ] **Step 1: Añadir `import uuid`**

En `shared/bifrost_backend/backend.py`, línea 39 (`import tempfile`), añadir justo debajo:

```python
import uuid
```

- [ ] **Step 2: Añadir la nueva sección de funciones SFTP**

Busca el final de `actualizar_password_perfiles_rclone` (línea 1183-1185):

```python
        print(f"⚠️ No profiles '{usuario}-smbmount-*' found in rclone.conf")


# ============================================================================
# MONTAJE / DESMONTAJE DE SHARES
# ============================================================================
```

Cambiar a (inserta la nueva sección **entre** el final de la función y el header de montaje):

```python
        print(f"⚠️ No profiles '{usuario}-smbmount-*' found in rclone.conf")


# ============================================================================
# GESTIÓN SFTP (ORIGEN EFÍMERO)
# ============================================================================

def crear_perfil_rclone_sftp(
    nombre_perfil: str,
    host: str,
    port: str,
    username: str,
    password: str,
) -> None:
    """Crea (o reemplaza) un perfil SFTP temporal en rclone.conf."""
    rclone = get_rclone_executable()
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
    config[nombre_perfil] = {
        "type": "sftp",
        "host": host,
        "port": port,
        "user": username,
        "pass": subprocess.check_output(
            [rclone, "obscure", password],
            text=True,
            **_subprocess_kwargs(),
        ).strip(),
    }
    with open(config_path, "w") as f:
        config.write(f)


def eliminar_perfil_rclone(
    nombre_perfil: str,
    rclone_config_path: str | None = None,
) -> None:
    """Borra una sección de rclone.conf si existe."""
    config_path = rclone_config_path or obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    if nombre_perfil in config:
        config.remove_section(nombre_perfil)
        with open(config_path, "w") as f:
            config.write(f)


def limpiar_perfiles_rclone_con_prefijo(
    prefijo: str,
    rclone_config_path: str | None = None,
) -> None:
    """Borra todas las secciones cuyo nombre empiece por *prefijo* (barrido de huérfanos)."""
    config_path = rclone_config_path or obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    for nombre in [s for s in config.sections() if s.startswith(prefijo)]:
        eliminar_perfil_rclone(nombre, config_path)


def generar_nombre_perfil_sftp() -> str:
    """Genera un nombre de perfil rclone único para una conexión SFTP efímera."""
    return f"sftp-src-{uuid.uuid4().hex[:8]}"


def validar_conexion_sftp(nombre_perfil: str, timeout: int = 15) -> tuple[bool, str | None]:
    """
    Valida que el perfil SFTP recién creado conecta correctamente, listando la raíz.

    Returns:
        (True, None) si conecta.
        (False, motivo) si falla — motivo ∈ {"unreachable", "auth", "timeout", "other"}.
    """
    try:
        rclone_lsd(nombre_perfil, "", timeout=timeout)
        return True, None
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except RuntimeError as e:
        mensaje = str(e).lower()
        if "auth" in mensaje or "permission denied" in mensaje:
            return False, "auth"
        if (
            "no such host" in mensaje
            or "connection refused" in mensaje
            or "i/o timeout" in mensaje
            or "network is unreachable" in mensaje
        ):
            return False, "unreachable"
        return False, "other"


# ============================================================================
# MONTAJE / DESMONTAJE DE SHARES
# ============================================================================
```

Nota: `rclone_lsd` está definido más abajo en el mismo archivo (línea ~1670) pero eso no es un problema — en Python las funciones a nivel de módulo se resuelven en tiempo de llamada, no en tiempo de definición.

- [ ] **Step 3: Verificar que el módulo importa sin errores**

Desde `bifrost-transfer/` con el venv activo:

```
python -c "from bifrost_backend.backend import crear_perfil_rclone_sftp, eliminar_perfil_rclone, limpiar_perfiles_rclone_con_prefijo, generar_nombre_perfil_sftp, validar_conexion_sftp; print('OK', generar_nombre_perfil_sftp())"
```

Esperado: `OK sftp-src-<8 caracteres hex>`

- [ ] **Step 4: Verificar creación/borrado real contra un `rclone.conf` de prueba (sin necesitar un servidor SFTP)**

Todas las funciones de la Task 1 aceptan `rclone_config_path` (o lo derivan de `obtener_ruta_rclone_conf()`), así que se puede probar el ciclo completo de escritura/borrado apuntando a un fichero temporal, sin conectar a ningún servidor real:

```
python -c "
import configparser
from bifrost_backend import backend

backend.crear_perfil_rclone_sftp('sftp-src-test1', 'example.com', '22', 'user', 'pass')
config_path = backend.obtener_ruta_rclone_conf()

# Simula un huérfano añadiendo una segunda sección con el mismo prefijo
config = configparser.ConfigParser()
config.read(config_path)
config['sftp-src-test2'] = {'type': 'sftp', 'host': 'x', 'port': '22', 'user': 'y', 'pass': 'z'}
with open(config_path, 'w') as f:
    config.write(f)

config2 = configparser.ConfigParser(); config2.read(config_path)
assert 'sftp-src-test1' in config2 and 'sftp-src-test2' in config2, 'setup falló'

backend.eliminar_perfil_rclone('sftp-src-test1')
config3 = configparser.ConfigParser(); config3.read(config_path)
assert 'sftp-src-test1' not in config3 and 'sftp-src-test2' in config3, 'eliminar_perfil_rclone falló'

backend.limpiar_perfiles_rclone_con_prefijo('sftp-src-')
config4 = configparser.ConfigParser(); config4.read(config_path)
assert 'sftp-src-test2' not in config4, 'limpiar_perfiles_rclone_con_prefijo falló'

print('OK: crear/eliminar/limpiar funcionan correctamente')
"
```

Esperado: `OK: crear/eliminar/limpiar funcionan correctamente`. **Importante:** este test escribe sobre el `rclone.conf` real del entorno de desarrollo (no hay forma sencilla de aislarlo, ya que `crear_perfil_rclone_sftp` usa `obtener_ruta_rclone_conf()` internamente) — verificar después con `rclone config file` + abrir el fichero que no haya quedado ninguna sección `sftp-src-test*` residual, y que los perfiles reales (SMB, S3) no se hayan tocado.

- [ ] **Step 5: Commit**

Este repo commitea con `npm run commit` (Commitizen, interactivo) en vez de `git commit -m`. Ejecuta:

```bash
git add shared/bifrost_backend/backend.py
npm run commit
```

Responde a las preguntas de Commitizen así:

| Pregunta | Respuesta |
|---|---|
| Type of change | `feat` |
| Scope | `backend` |
| Short description | `add ephemeral SFTP rclone profile management` |
| Longer description | `Adds crear_perfil_rclone_sftp, eliminar_perfil_rclone, limpiar_perfiles_rclone_con_prefijo, generar_nombre_perfil_sftp and validar_conexion_sftp — same pattern as the existing SMB profile helpers, used to browse/copy from an SFTP source.` |
| Breaking changes | `N` |
| Affected open issues | `N` |

---

## Task 2: Frontend — botón SFTP, diálogo de conexión y browser modal

**Files:**
- Modify: `bifrost-transfer/src/main.py`

**Interfaces:**
- Consumes: `backend.crear_perfil_rclone_sftp`, `backend.eliminar_perfil_rclone`, `backend.generar_nombre_perfil_sftp`, `backend.validar_conexion_sftp` (Task 1); `build_rclone_browser(page, perfil_rclone, on_select, initial_path="", lab_filter_enabled=False, endpoint=None) -> tuple[ft.Column, Callable]` (ya existente); `styled_field`, `btn_primary`, `btn_secondary`, `backend.safe_thread`, `backend.ui_call` (ya existentes en el archivo)
- Produces (usado por Task 3): `sftp_state: dict` (claves `"perfil"`, `"host"`, `"user"`), `_sftp_disconnect(clear_origen: bool = True) -> None`

- [ ] **Step 1: Añadir estado, diálogo de conexión y botón SFTP**

Busca en `_build_copy_content`, justo después de `cancel_btn.on_click = do_cancel` (línea 2258):

```python
    cancel_btn.on_click = do_cancel

    # ── FilePicker (solo desktop) ──────────────────────────────────────────
```

Cambiar a (inserta el bloque SFTP completo entre ambas líneas):

```python
    cancel_btn.on_click = do_cancel

    # ── Origen SFTP (perfil rclone efímero) ─────────────────────────────────
    sftp_state: dict = {"perfil": None, "host": None, "user": None}

    sftp_status_label = ft.Text("", size=12, color=C_ACCENT, font_family=FONT_MONO)
    sftp_disconnect_btn = ft.IconButton(
        icon=ft.Icons.CLOSE,
        icon_color=C_TEXT_DIM,
        icon_size=16,
        tooltip="Disconnect SFTP",
        on_click=lambda e: _sftp_disconnect(),
    )
    sftp_status_row = ft.Row(
        [sftp_status_label, sftp_disconnect_btn],
        spacing=4,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        visible=False,
    )

    def _sftp_disconnect(clear_origen: bool = True) -> None:
        perfil = sftp_state["perfil"]
        if not perfil:
            return

        def _bg():
            backend.eliminar_perfil_rclone(perfil)

        backend.safe_thread(page, _bg).start()
        sftp_state["perfil"] = None
        sftp_state["host"]   = None
        sftp_state["user"]   = None
        sftp_status_row.visible = False
        if clear_origen:
            origen_tf.value = ""
        page.update()

    def _open_sftp_browser_modal() -> None:
        _sftp_dest_path = {"value": ""}

        def _on_sftp_select(path: str) -> None:
            _sftp_dest_path["value"] = path

        browser_widget, browser_refresh = build_rclone_browser(
            page, sftp_state["perfil"], on_select=_on_sftp_select, lab_filter_enabled=False,
        )

        def confirm(e):
            path = _sftp_dest_path["value"]
            origen_tf.value = f"{sftp_state['perfil']}:{path}"
            page.pop_dialog()
            page.update()

        def cancel(e):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text(
                f"SFTP — {sftp_state['user']}@{sftp_state['host']}",
                color=C_TEXT, size=15, weight=ft.FontWeight.W_600,
            ),
            content=ft.Column([browser_widget], spacing=6, tight=True, width=520),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                btn_primary("Select this folder", on_click=confirm),
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()
        threading.Timer(0.1, lambda: backend.ui_call(page, browser_refresh)).start()

    def _open_sftp_dialog(e) -> None:
        if sftp_state["perfil"]:
            _open_sftp_browser_modal()
            return

        host_tf, host_col = styled_field("Host")
        port_tf, port_col = styled_field("Port", value="22")
        user_tf, user_col = styled_field("Username")
        pass_tf, pass_col = styled_field("Password", password=True)
        err = ft.Text("", color=C_ERROR, size=12, visible=False)
        loading_indicator = ft.ProgressRing(
            width=16, height=16, stroke_width=2, color=C_PRIMARY, visible=False
        )
        confirm_btn = btn_primary("Connect")

        def connect(ev):
            host = (host_tf.value or "").strip()
            port = (port_tf.value or "").strip() or "22"
            user = (user_tf.value or "").strip()
            pwd  = (pass_tf.value or "").strip()
            if not host or not user or not pwd:
                err.value   = "Host, username and password are required."
                err.visible = True
                page.update()
                return

            confirm_btn.disabled      = True
            loading_indicator.visible = True
            err.visible               = False
            page.update()

            def _validate():
                perfil = backend.generar_nombre_perfil_sftp()
                backend.crear_perfil_rclone_sftp(perfil, host, port, user, pwd)
                ok, motivo = backend.validar_conexion_sftp(perfil)
                if ok:
                    sftp_state["perfil"] = perfil
                    sftp_state["host"]   = host
                    sftp_state["user"]   = user

                    def _success():
                        page.pop_dialog()
                        sftp_status_label.value = f"🌐 Connected to {user}@{host}"
                        sftp_status_row.visible = True
                        page.update()
                        _open_sftp_browser_modal()

                    backend.ui_call(page, _success)
                else:
                    backend.eliminar_perfil_rclone(perfil)
                    mensajes = {
                        "auth":        "Incorrect username or password.",
                        "unreachable": f"Could not connect to {host}:{port}. Check the address and make sure the server is reachable from your network.",
                        "timeout":     f"Connection to {host}:{port} timed out.",
                    }
                    msg = mensajes.get(motivo, "Could not connect. Check the details and try again.")

                    def _fail():
                        err.value                 = msg
                        err.visible               = True
                        confirm_btn.disabled      = False
                        loading_indicator.visible = False
                        page.update()

                    backend.ui_call(page, _fail)

            backend.safe_thread(page, _validate).start()

        confirm_btn.on_click = connect

        def cancel(ev):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Connect to SFTP", color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
            content=ft.Column(
                [
                    host_col, port_col, user_col, pass_col, err,
                    ft.Row([loading_indicator], alignment=ft.MainAxisAlignment.CENTER),
                ],
                spacing=6, tight=True, width=320,
            ),
            actions=[btn_secondary("Cancel", on_click=cancel), confirm_btn],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()

    sftp_btn = btn_secondary("🌐 SFTP", on_click=_open_sftp_dialog)

    # ── FilePicker (solo desktop) ──────────────────────────────────────────
```

- [ ] **Step 2: Añadir `sftp_btn` al `pick_row` de desktop**

Busca (línea 2309):

```python
        pick_row = ft.Row([pick_file_btn, pick_folder_btn], spacing=8)
```

Cambiar a:

```python
        pick_row = ft.Row([pick_file_btn, pick_folder_btn, sftp_btn], spacing=8)
```

- [ ] **Step 3: Añadir `sftp_btn` al `pick_row` de web**

Busca (líneas 2326-2332):

```python
        pick_row    = ft.Row(
            [
                btn_secondary("📁 Folder", on_click=_open_folder_browser),
                btn_secondary("📄 File",   on_click=_open_file_browser),
            ],
            spacing=8,
        )
        save_picker = None
```

Cambiar a:

```python
        pick_row    = ft.Row(
            [
                btn_secondary("📁 Folder", on_click=_open_folder_browser),
                btn_secondary("📄 File",   on_click=_open_file_browser),
                sftp_btn,
            ],
            spacing=8,
        )
        save_picker = None
```

- [ ] **Step 4: Insertar `sftp_status_row` en el layout, justo debajo de `pick_row`**

Busca (líneas 2645-2657):

```python
                        card(
                            ft.Column(
                                [
                                    origen_col,
                                    ft.Container(height=4),
                                    pick_row,
                                    ft.Container(height=12),
                                    dest_browser_col,
```

Cambiar a:

```python
                        card(
                            ft.Column(
                                [
                                    origen_col,
                                    ft.Container(height=4),
                                    pick_row,
                                    sftp_status_row,
                                    ft.Container(height=12),
                                    dest_browser_col,
```

- [ ] **Step 5: Verificar que el módulo importa sin errores**

Desde `bifrost-transfer/` con el venv activo:

```
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read()); print('OK syntax')"
```

Esperado: `OK syntax`

- [ ] **Step 6: Verificar en la app (requiere un servidor SFTP real accesible por VPN Nexica)**

```
flet run
```

1. Login → llegar a la vista de copia.
2. Pulsar "🌐 SFTP" → aparece el diálogo con Host/Port/Username/Password.
3. Probar con credenciales incorrectas → mensaje "Incorrect username or password.", el diálogo no se cierra, se puede reintentar.
4. Abrir `rclone.conf` (ruta: `rclone config file`) y confirmar que **no** quedó ninguna sección `sftp-src-*` tras el fallo.
5. Probar con host inalcanzable → mensaje "Could not connect to host:port...".
6. Conectar con credenciales correctas → el diálogo se cierra y se abre automáticamente el browser de carpetas remoto.
7. Navegar a una carpeta y pulsar "Select this folder" → el campo "Source path" queda como `sftp-src-XXXXXXXX:/ruta/elegida`, aparece la etiqueta "🌐 Connected to user@host" bajo los botones.
8. Pulsar "🌐 SFTP" de nuevo (ya conectado) → reabre el browser directamente, sin pedir credenciales otra vez.
9. Pulsar el ✕ de "Connected to..." → la etiqueta desaparece, el campo "Source path" se vacía, y `rclone.conf` ya no tiene la sección `sftp-src-*`.
10. Repetir los pasos 2, 6, 7, 9 en modo web (`flet run --web` o `BIFROST_CLUSTER=1 python src/main.py --web`).

- [ ] **Step 7: Commit**

```bash
git add bifrost-transfer/src/main.py
npm run commit
```

Responde a las preguntas de Commitizen así:

| Pregunta | Respuesta |
|---|---|
| Type of change | `feat` |
| Scope | `transfer` |
| Short description | `add SFTP source with connection dialog and folder browser` |
| Longer description | `Adds a "SFTP" button next to File/Folder in the copy view. Connects via host/port/username/password, creates an ephemeral rclone profile, and reuses build_rclone_browser to pick the remote source folder — origen_tf ends up as "profile:/path", same format the field already accepted, so do_copy/do_check need no changes.` |
| Breaking changes | `N` |
| Affected open issues | `N` |

---

## Task 3: Frontend — limpieza del perfil SFTP (Back y barrido al login)

**Files:**
- Modify: `bifrost-transfer/src/main.py`

**Interfaces:**
- Consumes: `sftp_state`, `_sftp_disconnect(clear_origen: bool = True)` (Task 2); `backend.limpiar_perfiles_rclone_con_prefijo` (Task 1)

- [ ] **Step 1: Limpiar el perfil SFTP al pulsar "← Back" en la vista de copia**

Busca (línea 1969):

```python
    back_btn  = btn_secondary("← Back", on_click=lambda e: on_back()) if on_back else None
```

Cambiar a:

```python
    def _back_with_sftp_cleanup(e):
        _sftp_disconnect(clear_origen=False)
        on_back()

    back_btn  = btn_secondary("← Back", on_click=_back_with_sftp_cleanup) if on_back else None
```

Nota: `_sftp_disconnect` se define más abajo en el cuerpo de la misma función (`_build_copy_content`, Task 2, Step 1) — funciona porque Python resuelve el closure en tiempo de llamada (cuando el usuario pulsa el botón), no en tiempo de definición. `clear_origen=False` porque al salir de la vista no tiene sentido tocar `origen_tf` (la vista se destruye igualmente); solo interesa borrar la sección de `rclone.conf`.

- [ ] **Step 2: Barrido de huérfanos al hacer login (flujo normal)**

Busca (líneas 4031-4033):

```python
    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds
        go_minio()
```

Cambiar a:

```python
    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds

        def _sweep_sftp_huerfanos():
            try:
                backend.limpiar_perfiles_rclone_con_prefijo("sftp-src-")
            except Exception as ex:
                print(f"[sftp] cleanup sweep failed (non-fatal): {ex}")

        backend.safe_thread(page, _sweep_sftp_huerfanos).start()
        go_minio()
```

- [ ] **Step 3: Barrido de huérfanos al restaurar una sesión web**

Busca (líneas 4005-4019), dentro de `on_login_success_with_restore`:

```python
        usuario = creds["usuario"]
        # If the user typed a different username, discard the old session
        # and run the normal fresh flow instead.
        if usuario != _LAST_WEB_USER[0]:
            print(f"[session] Username changed ({_LAST_WEB_USER[0]!r} → {usuario!r}), discarding old session")
            _ws_clear(_LAST_WEB_USER[0] or "")
            on_login_success(creds)
            return
```

No requiere cambio — esta rama ya delega en `on_login_success(creds)`, que a partir del Step 2 incluye el barrido. Para la rama de continuación normal (sesión restaurada con el mismo usuario), busca justo después (líneas 4021-4029):

```python
        print(f"[session] Restoring session for {usuario!r} → cluster={session['servidor_minio']!r} ({session['endpoint']})")
        state["credenciales_ldap"] = creds
        state["servidor_minio"]    = session["servidor_minio"]
        state["perfil_rclone"]     = session["perfil_rclone"]
        state["endpoint"]          = session["endpoint"]
        # mounts_activos stays [] — OOD web mode has no CIFS shares

        # Jump straight to credentials-check → copy view
        _go_credentials_or_copy()
```

Cambiar a:

```python
        print(f"[session] Restoring session for {usuario!r} → cluster={session['servidor_minio']!r} ({session['endpoint']})")
        state["credenciales_ldap"] = creds
        state["servidor_minio"]    = session["servidor_minio"]
        state["perfil_rclone"]     = session["perfil_rclone"]
        state["endpoint"]          = session["endpoint"]
        # mounts_activos stays [] — OOD web mode has no CIFS shares

        def _sweep_sftp_huerfanos():
            try:
                backend.limpiar_perfiles_rclone_con_prefijo("sftp-src-")
            except Exception as ex:
                print(f"[sftp] cleanup sweep failed (non-fatal): {ex}")

        backend.safe_thread(page, _sweep_sftp_huerfanos).start()

        # Jump straight to credentials-check → copy view
        _go_credentials_or_copy()
```

- [ ] **Step 4: Verificar que el módulo importa sin errores**

```
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read()); print('OK syntax')"
```

Esperado: `OK syntax`

- [ ] **Step 5: Verificar en la app**

```
flet run
```

1. Conectar SFTP y seleccionar carpeta (como en Task 2, Step 6).
2. Pulsar "← Back" (sin desconectar manualmente) → confirmar en `rclone.conf` que la sección `sftp-src-*` ya no existe.
3. Simular un "crash": conectar SFTP, y sin desconectar ni pulsar Back, matar el proceso de la app (cerrar la ventana a la fuerza / Ctrl+C en la terminal).
4. Confirmar que la sección `sftp-src-*` quedó en `rclone.conf`.
5. Reabrir la app y hacer login → confirmar que la sección huérfana desaparece de `rclone.conf` justo después del login.

- [ ] **Step 6: Commit**

```bash
git add bifrost-transfer/src/main.py
npm run commit
```

Responde a las preguntas de Commitizen así:

| Pregunta | Respuesta |
|---|---|
| Type of change | `fix` |
| Scope | `transfer` |
| Short description | `clean up ephemeral SFTP profile on back and login` |
| Longer description | `Deletes the ephemeral SFTP rclone profile when leaving the copy view (Back) and sweeps any orphaned sftp-src-* profile left over from a crashed session right after every login, so credentials never outlive the session that created them.` |
| Breaking changes | `N` |
| Affected open issues | `N` |

---

## Task 4: Documentación — `CLAUDE.md` y `README.md`

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Añadir gotcha #12 en `CLAUDE.md`**

Busca el final del punto 11 y el inicio de la siguiente sección (líneas 169-173):

```
[Omitted long matching line]

---

## Wiki del proyecto
```

Busca el texto exacto del punto 11 completo (empieza con `11. **Filtro de laboratorio...`) y añade, justo después de su párrafo y antes de la línea `---` que precede a `## Wiki del proyecto`, un nuevo punto:

```markdown
12. **Origen SFTP efímero (`bifrost-transfer`)**: el botón "🌐 SFTP" de la vista de copia crea un perfil rclone temporal (`sftp-src-<random>`, tipo `sftp`, contraseña ofuscada con `rclone obscure`) en `rclone.conf` para poder reutilizar `build_rclone_browser`/`rclone_lsd` sin tocar el parsing existente de `origen` (que asume nombres de perfil simples, sin `:`/`,`). Por seguridad, ese perfil **no debe sobrevivir** más allá de la sesión: se borra al pulsar Disconnect (✕), al salir de la vista de copia (`on_back`), y además se barre cualquier `sftp-src-*` huérfano de una sesión anterior justo después de cada login (`backend.limpiar_perfiles_rclone_con_prefijo`), por si la app se cerró de forma abrupta con un perfil activo. Ver `docs/superpowers/specs/2026-07-30-sftp-source-design.md` para el razonamiento completo detrás de esta decisión.
```

- [ ] **Step 2: Actualizar la descripción de `bifrost-transfer` en `README.md`**

Busca (línea 8):

```
| **bifrost-transfer** | `bifrost-transfer/` | Upload data from network shares (SMB/CIFS) or local folders to MinIO S3 buckets, with integrity verification and metadata tagging by profile. Includes a **Tag Manager** to browse and edit S3 object tags without re-uploading. |
```

Cambiar a:

```
| **bifrost-transfer** | `bifrost-transfer/` | Upload data from network shares (SMB/CIFS), SFTP servers, or local folders to MinIO S3 buckets, with integrity verification and metadata tagging by profile. Includes a **Tag Manager** to browse and edit S3 object tags without re-uploading. |
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md
npm run commit
```

Responde a las preguntas de Commitizen así:

| Pregunta | Respuesta |
|---|---|
| Type of change | `docs` |
| Scope | (dejar en blanco) |
| Short description | `document SFTP source support in bifrost-transfer` |
| Longer description | (dejar en blanco) |
| Breaking changes | `N` |
| Affected open issues | `N` |

---

## Recordatorio post-implementación

- Confirmar con un servidor SFTP real (accesible por VPN Nexica) los 10 casos del Step 6 de la Task 2 y los 5 casos del Step 5 de la Task 3 antes de dar la feature por cerrada.
- Si en el futuro se decide soportar autenticación por clave privada, revisar primero el spec (`docs/superpowers/specs/2026-07-30-sftp-source-design.md`, sección de decisiones) — es una extensión, no un cambio de esta implementación.
