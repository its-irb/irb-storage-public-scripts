# CIFS On-Demand desde Vista de Copia — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mover la selección de shares CIFS del flujo de arranque a un botón opcional en la vista de copia, con doble-click para montar y botón de admin para usuarios ITS.

**Architecture:** Un único fichero (`bifrost-transfer/src/main.py`) se modifica en 5 tareas secuenciales. El flujo de arranque se simplifica (login → minio → copy). La carga de grupos/shares CIFS pasa a ser lazy via `go_cifs()`. `_build_shares_content` se reescribe con filas interactivas (GestureDetector) en lugar de checkboxes.

**Tech Stack:** Python, Flet (`ft`), `bifrost_backend.backend`, threading.

---

## Mapa de archivos

| Archivo | Cambios |
|---|---|
| `bifrost-transfer/src/main.py` | Único archivo modificado |

Funciones que se **eliminan**: `_ask_admin_creds()`, `_after_privileges()` (lógica movida a `go_cifs()` y al diálogo de admin en `_build_shares_content`).

Funciones que se **añaden**: `_load_and_show_shares()`, `go_cifs()`, `on_admin_activated()` (todas dentro de `main()`).

Funciones que se **modifican**: `on_login_success()`, `go_copy()`, `_build_copy_content()`, `_build_shares_content()`.

---

## Task 1: Simplificar `on_login_success` — eliminar CIFS del arranque

**Files:**
- Modify: `bifrost-transfer/src/main.py` (~líneas 3875–3994)

- [ ] **Step 1: Reemplazar el cuerpo de `on_login_success`**

Busca la función `on_login_success` (empieza en `def on_login_success(creds: dict):`) y reemplaza todo su cuerpo por:

```python
def on_login_success(creds: dict):
    state["credenciales_ldap"] = creds
    go_minio()
```

- [ ] **Step 2: Eliminar `_ask_admin_creds` y `_after_privileges`**

Borra las dos funciones completas que siguen a `on_login_success` (desde `def _ask_admin_creds():` hasta el final de `def _after_privileges():`, incluyendo `_load_shares` anidado). Estas funciones son internas de `main()` y solo eran usadas desde el arranque.

- [ ] **Step 3: Verificar que el arranque funciona**

```bash
cd bifrost-transfer
flet run
```

Esperado: la app arranca, el login funciona y llega directamente a la selección de servidor MinIO (sin pedir shares). En modo web:

```bash
flet run --web
```

Esperado: mismo comportamiento, sin loading de grupos LDAP.

- [ ] **Step 4: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "refactor(transfer): eliminar selección CIFS del flujo de arranque"
```

---

## Task 2: Añadir `go_cifs()`, `_load_and_show_shares()` y `on_admin_activated()` a `main()`

**Files:**
- Modify: `bifrost-transfer/src/main.py` (~línea 4058, justo antes de `go_copy()`)

- [ ] **Step 1: Insertar las tres funciones antes de `go_copy()`**

Localiza la función `go_copy()` y añade justo antes de ella:

```python
def _load_and_show_shares(skip_groups: bool = False) -> None:
    """Carga grupos LDAP + credentials SMB + shares en background y muestra la vista."""
    creds_ldap = state["credenciales_ldap"]

    show_loading("Loading accessible shares...")

    def _bg():
        if not skip_groups:
            grupos = backend.get_ldap_groups(creds_ldap["usuario"])
            state["grupos_ldap"] = grupos

        try:
            state["credenciales_smb"] = backend.construir_credenciales_smb(
                creds_ldap,
                state["usar_privilegios"],
                state["credenciales_admin"],
            )
        except ValueError as ex:
            backend.ui_call(page, lambda: show_dialog(page, "Error", str(ex), C_ERROR))
            return

        shares = backend.obtener_shares_accesibles(
            state["grupos_ldap"],
            creds_ldap["usuario"],
            creds_ldap["password"],
            state["credenciales_smb"]["usuario"],
            backend.EXCEPCION_FILERS,
            state["usar_privilegios"],
        )
        perfiles = backend.configurar_perfiles_smb_si_faltan(
            shares,
            state["credenciales_smb"],
            backend.obtener_perfiles_rclone_config(),
        )
        state["shares_accesibles"]     = shares
        state["perfiles_configurados"] = perfiles

        def _show():
            show_screen(_build_shares_content(
                page,
                shares=shares,
                usuario_actual=state["credenciales_smb"]["usuario"],
                mounts_activos=state["mounts_activos"],
                grupos_ldap=state["grupos_ldap"],
                credenciales_ldap=creds_ldap,
                on_back=go_copy,
                on_admin_activated=on_admin_activated,
            ))
        backend.ui_call(page, _show)

    backend.safe_thread(page, _bg).start()


def go_cifs() -> None:
    """Navega a la vista de CIFS shares. Carga lazy en el primer acceso."""
    if state["credenciales_smb"] is not None:
        creds_ldap = state["credenciales_ldap"]
        show_screen(_build_shares_content(
            page,
            shares=state["shares_accesibles"],
            usuario_actual=state["credenciales_smb"]["usuario"],
            mounts_activos=state["mounts_activos"],
            grupos_ldap=state["grupos_ldap"],
            credenciales_ldap=creds_ldap,
            on_back=go_copy,
            on_admin_activated=on_admin_activated,
        ))
        return
    _load_and_show_shares(skip_groups=False)


def on_admin_activated(credenciales_admin: dict) -> None:
    """Callback llamado desde la vista CIFS al confirmar credenciales de admin ITS."""
    state["usar_privilegios"]   = True
    state["credenciales_admin"] = credenciales_admin
    _load_and_show_shares(skip_groups=True)

```

- [ ] **Step 2: Añadir `"usar_privilegios"` y `"credenciales_admin"` al `state` inicial**

Localiza el dict `state = {...}` al inicio de `main()` y añade las dos claves que faltarán ahora que `_after_privileges` ya no existe:

```python
state = {
    "credenciales_ldap":     None,
    "grupos_ldap":           [],
    "usar_privilegios":      False,   # ← asegúrate de que existe
    "credenciales_admin":    None,    # ← asegúrate de que existe
    "credenciales_smb":      None,
    "shares_accesibles":     [],
    "perfiles_configurados": [],
    "mounts_activos":        [],
    "servidor_minio":        None,
    "perfil_rclone":         None,
    "endpoint":              None,
}
```

(Probablemente ya existen; solo confirmar que están.)

- [ ] **Step 3: Verificar que no hay errores de importación/sintaxis**

```bash
cd bifrost-transfer
python -c "import sys; sys.argv=['main']; exec(open('src/main.py').read())" 2>&1 | head -20
```

Esperado: sin `SyntaxError` ni `NameError`. (Puede haber errores de ejecución al no tener Flet page — son ignorables.)

- [ ] **Step 4: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): añadir go_cifs() con carga lazy de shares CIFS"
```

---

## Task 3: Añadir botón "Mount CIFS" a `_build_copy_content` y wirear en `go_copy()`

**Files:**
- Modify: `bifrost-transfer/src/main.py` (función `_build_copy_content` ~línea 1622 y `go_copy()` ~línea 4059)

- [ ] **Step 1: Añadir parámetro `on_cifs` a `_build_copy_content`**

Localiza la firma de `_build_copy_content` y añade el parámetro al final:

```python
def _build_copy_content(
    page: ft.Page,
    perfil_rclone: str,
    mounts_activos: list,
    on_close: Callable,
    endpoint: str,
    credenciales_ldap: dict,
    extra_config: dict | None,
    on_renew_complete: Callable,
    show_screen: Callable,
    web_session: dict | None = None,
    on_back: Callable | None = None,
    on_tags: Callable | None = None,
    on_cifs: Callable | None = None,   # ← nuevo
) -> ft.Control:
```

- [ ] **Step 2: Crear el botón `cifs_btn`**

Justo después de donde se definen `back_btn` y `tags_btn` (busca `back_btn  = btn_secondary(...)`), añade:

```python
cifs_btn = (
    btn_secondary("⊞  Mount CIFS", on_click=lambda e: on_cifs())
    if IS_WEB and on_cifs is not None
    else None
)
```

- [ ] **Step 3: Incluir `cifs_btn` en la barra superior**

Localiza la línea que construye la `ft.Row` de la barra superior (contiene `back_btn`, `tags_btn`, `expiry_badge`, `renew_btn`) y añade `cifs_btn`:

```python
ft.Container(
    content=ft.Row(
        [c for c in [back_btn, tags_btn, cifs_btn, expiry_badge, ft.Container(expand=True), renew_btn] if c is not None],
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    ),
    padding=ft.Padding.symmetric(horizontal=24, vertical=8),
    margin=ft.Margin.only(bottom=4),
),
```

- [ ] **Step 4: Pasar `on_cifs=go_cifs` desde `go_copy()`**

Localiza `go_copy()` y añade el argumento:

```python
def go_copy():
    servidor     = state["servidor_minio"]
    extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")
    usuario      = (state.get("credenciales_ldap") or {}).get("usuario")
    if IS_WEB and usuario:
        _ws_save(usuario, state)
    session = _ws_load(usuario) if (IS_WEB and usuario) else None
    show_screen(_build_copy_content(
        page,
        perfil_rclone=state["perfil_rclone"],
        mounts_activos=state["mounts_activos"],
        on_close=do_close,
        endpoint=state["endpoint"],
        credenciales_ldap=state["credenciales_ldap"],
        extra_config=extra_config,
        on_renew_complete=go_copy,
        show_screen=show_screen,
        web_session=session,
        on_back=go_minio,
        on_tags=go_tags,
        on_cifs=go_cifs,          # ← nuevo
    ))
```

- [ ] **Step 5: Verificar botón visible en modo web**

```bash
cd bifrost-transfer
flet run --web
```

Navega hasta la vista de copia. Esperado: aparece el botón "⊞ Mount CIFS" en la barra superior. Al pulsarlo, aparece el loading "Loading accessible shares..." (o un error de red si no hay VPN, que es correcto).

En modo desktop (`flet run`): el botón NO debe aparecer.

- [ ] **Step 6: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): botón 'Mount CIFS' en vista de copia"
```

---

## Task 4: Reescribir `_build_shares_content` — filas interactivas y botón Back

**Files:**
- Modify: `bifrost-transfer/src/main.py` (función `_build_shares_content` ~línea 411)

- [ ] **Step 1: Actualizar la firma de `_build_shares_content`**

Reemplaza la firma actual:

```python
def _build_shares_content(
    page: ft.Page,
    shares: list,
    usuario_actual: str,
    mounts_activos: list,
    es_admin_its: bool,
    credenciales_ldap: dict,
    on_continue: Callable,
) -> ft.Control:
```

Por:

```python
def _build_shares_content(
    page: ft.Page,
    shares: list,
    usuario_actual: str,
    mounts_activos: list,
    grupos_ldap: list,
    credenciales_ldap: dict,
    on_back: Callable,
    on_admin_activated: Callable,
) -> ft.Control:
```

- [ ] **Step 2: Actualizar la línea `recursos_cifs_dict` y el bloque de "no shares"**

La primera línea del cuerpo llama a `backend.construir_recursos_cifs_dict`. Mantenla igual. En el bloque de "no shares", reemplaza el botón `btn_primary("Continue without shares →", ...)` por:

```python
btn_primary("← Back", on_click=lambda e: on_back(), width=200),
```

- [ ] **Step 3: Reemplazar checkboxes por filas GestureDetector**

Elimina el bloque que crea `checkboxes`, `checkbox_controls` y `columns`. Sustitúyelo por:

```python
_selected:         dict = {"name": None}
_row_containers:   dict[str, ft.Container] = {}
_status_spinners:  dict[str, ft.ProgressRing] = {}
_status_texts:     dict[str, ft.Text] = {}
_mounted_badges:   dict[str, ft.Container] = {}

def _select_share(name: str) -> None:
    if _selected["name"]:
        prev = _row_containers.get(_selected["name"])
        if prev:
            prev.border = ft.Border.all(1, C_BORDER)
    _selected["name"] = name
    _row_containers[name].border = ft.Border.all(2, C_PRIMARY)
    page.update()

def _mount_share(name: str) -> None:
    if _mounted_badges.get(name) and _mounted_badges[name].visible:
        return  # ya montado
    spinner    = _status_spinners[name]
    status_txt = _status_texts[name]
    badge      = _mounted_badges[name]
    spinner.visible    = True
    status_txt.value   = "Mounting..."
    status_txt.color   = C_TEXT_DIM
    status_txt.visible = True
    page.update()

    def _do():
        fallidos = backend.montar_shares_seleccionados(
            [name], recursos_cifs_dict, mounts_activos
        )
        def _after():
            spinner.visible = False
            if fallidos:
                status_txt.value = f"Error"
                status_txt.color = C_ERROR
            else:
                status_txt.visible = False
                badge.visible      = True
            page.update()
        backend.ui_call(page, _after)

    backend.safe_thread(page, _do).start()

def _make_row(share_name: str) -> ft.GestureDetector:
    spinner = ft.ProgressRing(
        width=14, height=14, stroke_width=2, color=C_PRIMARY, visible=False
    )
    status_txt = ft.Text("", size=11, color=C_TEXT_DIM, visible=False)
    badge = ft.Container(
        content=ft.Row(
            [
                ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=14),
                ft.Text("Mounted", size=11, color=C_ACCENT,
                        weight=ft.FontWeight.W_600),
            ],
            spacing=4,
            tight=True,
        ),
        visible=False,
    )
    _status_spinners[share_name] = spinner
    _status_texts[share_name]    = status_txt
    _mounted_badges[share_name]  = badge

    c = ft.Container(
        content=ft.Row(
            [
                ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
                ft.Text(share_name, size=13, color=C_TEXT, expand=True),
                spinner,
                status_txt,
                badge,
            ],
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE,
        border=ft.Border.all(1, C_BORDER),
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=12, vertical=8),
    )
    _row_containers[share_name] = c
    return ft.GestureDetector(
        content=c,
        on_tap=lambda e, s=share_name: _select_share(s),
        on_double_tap=lambda e, s=share_name: _mount_share(s),
    )

rows = [_make_row(s["name"]) for s in shares]
```

- [ ] **Step 4: Reemplazar el layout de la vista**

Elimina todo el bloque de `loading_spin`, `loading_text`, `error_text`, `continue_btn`, `do_continue`, `update_smb_creds`, y el `content = ft.Column(...)` original. Sustitúyelo por:

```python
back_btn_widget = btn_secondary("← Back", on_click=lambda e: on_back())

def _update_smb_creds(e):
    es_admin_its = "its" in grupos_ldap
    _show_smb_cred_dialog(page, usuario_actual, es_admin_its, credenciales_ldap)

hint = ft.Text(
    "Double-click a share to mount it.",
    size=11,
    color=C_TEXT_DIM,
    italic=True,
)

shares_list = ft.Container(
    content=ft.Column(
        rows,
        scroll=ft.ScrollMode.AUTO,
        spacing=4,
        tight=True,
    ),
    bgcolor=C_SURFACE,
    border=ft.Border.all(1, C_BORDER),
    border_radius=10,
    padding=16,
    height=min(400, max(120, len(rows) * 48)),
)

content = ft.Column(
    [
        build_header(subtitle=f"CIFS Shares — {usuario_actual}", IS_WEB=IS_WEB),
        ft.Container(
            content=ft.Column(
                [
                    section_title("MOUNT SHARES"),
                    ft.Container(height=8),
                    hint,
                    ft.Container(height=10),
                    shares_list,
                    ft.Container(height=16),
                    ft.Row(
                        [
                            btn_secondary("Update SMB credentials",
                                          on_click=_update_smb_creds),
                            ft.Container(expand=True),
                            back_btn_widget,
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    ft.Container(height=16),
                ],
                spacing=0,
                tight=True,
            ),
            padding=ft.Padding.symmetric(horizontal=24, vertical=8),
        ),
    ],
    spacing=0,
    tight=True,
)

return content
```

- [ ] **Step 5: Verificar doble-click y Back**

```bash
cd bifrost-transfer
flet run --web
```

1. Pulsa "⊞ Mount CIFS" en la vista de copia → aparece la lista de shares.
2. Doble-click en un share → spinner → "Mounted" badge (o error si no hay VPN).
3. Pulsa "← Back" → vuelve a la vista de copia.

- [ ] **Step 6: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): shares CIFS con filas interactivas y doble-click para montar"
```

---

## Task 5: Añadir botón "Admin credentials" (solo usuarios ITS)

**Files:**
- Modify: `bifrost-transfer/src/main.py` (dentro de `_build_shares_content`)

- [ ] **Step 1: Crear el diálogo de admin y el botón**

En `_build_shares_content`, justo antes de construir `content`, añade:

```python
es_admin_its = "its" in grupos_ldap

def _show_admin_cred_dialog(e):
    admin_user = "admin_" + usuario_actual
    pass_tf, pass_col = styled_field("Admin password", password=True)
    err = ft.Text("", color=C_ERROR, size=12, visible=False)

    def confirm(ev):
        pwd = (pass_tf.value or "").strip()
        if not pwd:
            err.value   = "Password required."
            err.visible = True
            page.update()
            return
        creds = {"usuario": admin_user, "password": pwd}
        ok, motivo = backend.validar_credenciales_ldap(creds)
        if not ok:
            err.value = (
                "⚠️ Cannot reach the IRB network. Are you connected to the VPN?"
                if motivo == "vpn"
                else "Invalid credentials."
            )
            err.visible = True
            page.update()
            return
        page.pop_dialog()
        on_admin_activated({"usuario": admin_user, "password": pwd})

    def cancel(ev):
        page.pop_dialog()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text("Admin Credentials", color=C_TEXT, size=15,
                      weight=ft.FontWeight.W_600),
        content=ft.Column(
            [
                ft.Text(f"Username: {admin_user}", color=C_TEXT_DIM, size=12),
                ft.Container(height=10),
                pass_col,
                err,
            ],
            spacing=6,
            tight=True,
            width=300,
        ),
        actions=[
            btn_secondary("Cancel", on_click=cancel),
            btn_primary("Confirm",  on_click=confirm),
        ],
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.show_dialog(dlg)
    page.update()

admin_btn = btn_secondary("🔑 Admin credentials",
                          on_click=_show_admin_cred_dialog)
admin_btn.visible = es_admin_its
```

- [ ] **Step 2: Añadir `admin_btn` a la fila de botones**

En el `ft.Row` de botones del layout (donde está "Update SMB credentials" y "← Back"), añade `admin_btn`:

```python
ft.Row(
    [
        btn_secondary("Update SMB credentials", on_click=_update_smb_creds),
        admin_btn,
        ft.Container(expand=True),
        back_btn_widget,
    ],
    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
    vertical_alignment=ft.CrossAxisAlignment.CENTER,
),
```

- [ ] **Step 3: Verificar con usuario ITS y sin ITS**

**Con usuario ITS:** en la vista CIFS debe aparecer el botón "🔑 Admin credentials". Al pulsarlo y confirmar credenciales correctas, la vista recarga con más shares visibles.

**Con usuario normal:** el botón NO debe aparecer.

- [ ] **Step 4: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): botón admin credentials en vista CIFS (solo ITS)"
```

---

## Self-Review

**Spec coverage:**
- [x] Eliminar CIFS del arranque → Task 1
- [x] `go_cifs()` con lazy loading → Task 2
- [x] Botón "Mount CIFS" solo IS_WEB → Task 3
- [x] Doble-click monta el share → Task 4
- [x] Botón "← Back" → Task 4
- [x] "Admin credentials" solo ITS → Task 5
- [x] Reload de shares al activar admin → `on_admin_activated` en Task 2 + Task 5
- [x] Cierre desmonta CIFS → sin cambios, ya funciona con `state["mounts_activos"]`
- [x] Caché de `credenciales_smb` (segunda entrada sin reload) → `go_cifs()` Task 2

**Consistencia de tipos:**
- `on_admin_activated(credenciales_admin: dict)` — definido en Task 2, referenciado en Task 4 y 5 ✓
- `grupos_ldap: list` — pasado desde `_load_and_show_shares` en Task 2, recibido en Task 4 ✓
- `on_back: Callable` — pasado desde `go_cifs()` en Task 2, usado en Task 4 ✓
- `_show_smb_cred_dialog(page, usuario_actual, es_admin_its, credenciales_ldap)` — firma existente, `es_admin_its` se computa localmente en Task 4 ✓
