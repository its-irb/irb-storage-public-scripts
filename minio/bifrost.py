from __future__ import annotations

"""
IRB MinIO Rclone Data Transfer Tool — FRONTEND (Flet)
=====================================================

Migración de tkinter a Flet.
Soporta modo desktop y modo web (--web).

Uso:
    python bifrost_flet.py          # desktop
    python bifrost_flet.py --web    # Open OnDemand / cluster (Rocky Linux)

Flujo de vistas:
    view_update → view_login → view_shares → view_minio
    → view_credentials → view_copy

Fixes aplicados respecto al piloto inicial:
  - Thread-safety: toda modificación de UI desde hilos usa ui_call(page, fn)
  - Import circular eliminado (check_rclone_installation_flet se llama directamente)
  - Cierre por X registra on_window_event para desmontar shares
  - Spinner de carga entre login y vista de shares
  - FilePicker instanciado una sola vez (no se acumula en overlay)
  - Log usa ft.ListView con auto_scroll=True en lugar de TextField
  - ft.Ref[str] reemplazado por dict simple
  - Vista de shares vacíos muestra mensaje explicativo
  - atexit eliminado; el cierre limpio se gestiona via on_window_event y do_close()
  - Sin hint de asteriscos en campos password
  - Espaciado (margin bottom) entre header y contenido de cada vista
  - safe_thread: todos los hilos capturan excepciones y las muestran en diálogo
"""

import os
import sys
import stat
import getpass
import tempfile
import subprocess
import threading
import traceback
from datetime import datetime
from typing import Callable

import flet as ft

import backend

# ============================================================================
# MODO DE EJECUCIÓN
# ============================================================================

IS_WEB = "--web" in sys.argv

# ============================================================================
# HELPER THREAD-SAFE PARA ACTUALIZAR UI
# ============================================================================

def ui_call(page: ft.Page, fn: Callable) -> None:
    fn()
    page.update()


# ============================================================================
# WRAPPER SEGURO PARA HILOS — captura excepciones y las muestra en diálogo
# ============================================================================

def safe_thread(page: ft.Page, target: Callable, daemon: bool = True) -> threading.Thread:
    """
    Crea un Thread que captura cualquier excepción no controlada y la muestra
    en un diálogo de error en lugar de matar el proceso silenciosamente.
    Esto evita que el ejecutable compilado se cierre sin explicación.
    """
    def _wrapper():
        try:
            target()
        except Exception as exc:
            tb = traceback.format_exc()
            print(f"[safe_thread] Unhandled exception:\n{tb}")
            def _show():
                show_dialog(
                    page,
                    "Unexpected error",
                    f"{type(exc).__name__}: {exc}\n\nCheck console or contact ITS.",
                    C_ERROR,
                )
            ui_call(page, _show)

    t = threading.Thread(target=_wrapper, daemon=daemon)
    return t


# ============================================================================
# PALETA DE COLORES Y HELPERS DE ESTILO
# ============================================================================

C_BG       = "#0D1117"
C_SURFACE  = "#161B22"
C_SURFACE2 = "#21262D"
C_BORDER   = "#30363D"
C_PRIMARY  = "#58A6FF"
C_ACCENT   = "#3FB950"
C_WARNING  = "#D29922"
C_ERROR    = "#F85149"
C_TEXT     = "#E6EDF3"
C_TEXT_DIM = "#8B949E"
C_OVERLAY  = "#1C2128"
FONT_MONO  = "Courier New"

# Logo IRB Barcelona embebido en base64
IRB_LOGO_B64 = (
    "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"
)



def btn_primary(text: str, on_click=None, width=None, disabled=False) -> ft.ElevatedButton:
    return ft.ElevatedButton(
        text=text,
        on_click=on_click,
        disabled=disabled,
        width=width,
        style=ft.ButtonStyle(
            bgcolor={
                ft.ControlState.DEFAULT:  C_PRIMARY,
                ft.ControlState.HOVERED:  "#79B8FF",
                ft.ControlState.DISABLED: C_BORDER,
            },
            color={
                ft.ControlState.DEFAULT:  "#0D1117",
                ft.ControlState.DISABLED: C_TEXT_DIM,
            },
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.padding.symmetric(horizontal=20, vertical=12),
        ),
    )


def btn_secondary(text: str, on_click=None, width=None) -> ft.OutlinedButton:
    return ft.OutlinedButton(
        text=text,
        on_click=on_click,
        width=width,
        style=ft.ButtonStyle(
            color=C_TEXT,
            side=ft.BorderSide(1, C_BORDER),
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.padding.symmetric(horizontal=20, vertical=12),
        ),
    )


def card(content: ft.Control, padding=20) -> ft.Container:
    return ft.Container(
        content=content,
        bgcolor=C_SURFACE,
        border=ft.border.all(1, C_BORDER),
        border_radius=10,
        padding=padding,
    )


def section_title(text: str) -> ft.Text:
    return ft.Text(
        text,
        size=11,
        weight=ft.FontWeight.W_600,
        color=C_TEXT_DIM,
        font_family=FONT_MONO,
    )


def field_label(text: str) -> ft.Text:
    return ft.Text(text, size=12, color=C_TEXT_DIM, weight=ft.FontWeight.W_500)


def styled_field(
    label: str,
    password: bool = False,
    value: str = "",
    disabled: bool = False,
    hint: str = "",
    on_change=None,
    multiline: bool = False,
    min_lines: int = 1,
    max_lines: int = 1,
) -> tuple[ft.TextField, ft.Column]:
    tf = ft.TextField(
        value=value,
        password=password,
        can_reveal_password=password,
        disabled=disabled,
        hint_text=hint,
        on_change=on_change,
        multiline=multiline,
        min_lines=min_lines,
        max_lines=max_lines,
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        hint_style=ft.TextStyle(color=C_TEXT_DIM),
        border_radius=6,
        content_padding=ft.padding.symmetric(horizontal=12, vertical=10),
        text_size=13,
    )
    col = ft.Column([field_label(label), tf], spacing=4, tight=True)
    return tf, col


def status_badge(text: str, color: str) -> ft.Container:
    return ft.Container(
        content=ft.Text(text, size=11, color=color, weight=ft.FontWeight.W_600),
        bgcolor=f"{color}22",
        border=ft.border.all(1, f"{color}55"),
        border_radius=20,
        padding=ft.padding.symmetric(horizontal=10, vertical=4),
    )


def divider() -> ft.Divider:
    return ft.Divider(height=1, color=C_BORDER)


# ============================================================================
# HEADER COMÚN
# FIX: margin=ft.margin.only(bottom=24) añade espacio entre header y contenido
# ============================================================================

def build_header(subtitle: str = "") -> ft.Container:
    version_str = f"v{backend.__version__}" if hasattr(backend, "__version__") else ""
    return ft.Container(
        content=ft.Row(
            [
                # Logo IRB Barcelona a la izquierda
                ft.Container(
                    content=ft.Image(
                        src_base64=IRB_LOGO_B64,
                        width=40,
                        height=40,
                        fit=ft.ImageFit.CONTAIN,
                    ),
                    margin=ft.margin.only(right=14),
                ),
                # Titulo BIFROST + subtitulo
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(
                                    "BIFROST",
                                    size=22,
                                    weight=ft.FontWeight.W_700,
                                    color=C_PRIMARY,
                                    font_family=FONT_MONO,
                                ),
                                ft.Container(width=8),
                                status_badge("WEB" if IS_WEB else "DESKTOP", C_WARNING),
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Text(subtitle or "IRB Data Transfer Tool", size=12, color=C_TEXT_DIM),
                    ],
                    spacing=2,
                    expand=True,
                ),
                # Version
                ft.Text(version_str, size=11, color=C_TEXT_DIM, font_family=FONT_MONO),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE,
        border=ft.border.only(bottom=ft.BorderSide(1, C_BORDER)),
        padding=ft.padding.symmetric(horizontal=24, vertical=14),
        margin=ft.margin.only(bottom=24),
    )


# ============================================================================
# DIÁLOGOS GENÉRICOS
# ============================================================================

def show_dialog(
    page: ft.Page,
    title: str,
    message: str,
    color: str = C_TEXT,
    actions: list | None = None,
):
    def close(e=None):
        dlg.open = False
        page.update()

    if not actions:
        actions = [btn_primary("OK", on_click=close)]

    icon = (
        ft.Icons.CHECK_CIRCLE_OUTLINE   if color == C_ACCENT  else
        ft.Icons.ERROR_OUTLINE          if color == C_ERROR   else
        ft.Icons.WARNING_AMBER_OUTLINED if color == C_WARNING else
        ft.Icons.INFO_OUTLINE
    )

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Row(
            [
                ft.Icon(icon, color=color, size=20),
                ft.Text(title, color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
            ],
            spacing=8,
        ),
        content=ft.Text(message, color=C_TEXT_DIM, size=13),
        actions=actions,
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.overlay.append(dlg)
    dlg.open = True
    page.update()


def show_confirm(
    page: ft.Page,
    title: str,
    message: str,
    on_yes: Callable,
    on_no: Callable | None = None,
):
    def yes(e):
        dlg.open = False
        page.update()
        on_yes()

    def no(e):
        dlg.open = False
        page.update()
        if on_no:
            on_no()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text(title, color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
        content=ft.Text(message, color=C_TEXT_DIM, size=13),
        actions=[btn_secondary("No", on_click=no), btn_primary("Yes", on_click=yes)],
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.overlay.append(dlg)
    dlg.open = True
    page.update()


# ============================================================================
# VISTA: ACTUALIZACIÓN
# ============================================================================

def _build_update_content(page: ft.Page, on_continue: Callable) -> ft.Control:
    status_text = ft.Text("Checking for updates...", color=C_TEXT_DIM, size=13)
    progress    = ft.ProgressBar(color=C_PRIMARY, bgcolor=C_SURFACE2, width=300)
    update_btn  = btn_primary("Update now")
    skip_btn    = btn_secondary("Continue anyway")
    update_btn.visible = False
    skip_btn.visible   = False

    def check():
        try:
            ultima = backend.check_update_version(force_update="--update" in sys.argv)
            if ultima:
                def _show_update():
                    status_text.value  = f"New version available: {ultima}"
                    status_text.color  = C_WARNING
                    progress.visible   = False
                    update_btn.visible = True
                    skip_btn.visible   = True
                ui_call(page, _show_update)
            else:
                def _show_ok():
                    status_text.value = "✓ You are using the latest version."
                    status_text.color = C_ACCENT
                    progress.visible  = False
                ui_call(page, _show_ok)
                import time; time.sleep(1)
                ui_call(page, on_continue)
        except Exception as e:
            def _show_err():
                status_text.value = f"Could not check updates: {e}"
                status_text.color = C_TEXT_DIM
                progress.visible  = False
            ui_call(page, _show_err)
            import time; time.sleep(0.5)
            ui_call(page, on_continue)

    def do_update(e):
        update_btn.disabled  = True
        progress.visible     = True
        status_text.value    = "Downloading update..."
        status_text.color    = C_TEXT_DIM
        page.update()

        def _download():
            try:
                nueva_ruta  = backend.download_new_binary("bifrost")
                ruta_actual = os.path.abspath(sys.argv[0])
                if sys.platform == "win32":
                    _escribir_y_lanzar_updater_windows(ruta_actual, nueva_ruta)
                else:
                    os.replace(nueva_ruta, ruta_actual)
                    os.chmod(ruta_actual, os.stat(ruta_actual).st_mode | stat.S_IEXEC)
                    ui_call(page, lambda: show_dialog(
                        page, "Updated",
                        "Restart the application to use the new version.",
                        C_ACCENT,
                    ))
            except Exception as ex:
                ui_call(page, lambda: show_dialog(page, "Update failed", str(ex), C_ERROR))

        safe_thread(page, _download).start()

    skip_btn.on_click   = lambda e: ui_call(page, on_continue)
    update_btn.on_click = do_update

    content = ft.Column(
        [
            build_header("Checking for updates"),
            ft.Container(expand=True),
            ft.Column(
                [
                    ft.Icon(ft.Icons.SYNC, color=C_PRIMARY, size=48),
                    ft.Text("BIFROST", size=32, weight=ft.FontWeight.W_700,
                            color=C_TEXT, font_family=FONT_MONO),
                    ft.Text("IRB Data Transfer Tool", size=14, color=C_TEXT_DIM),
                    ft.Container(height=24),
                    progress,
                    status_text,
                    ft.Container(height=16),
                    ft.Row([update_btn, skip_btn],
                           alignment=ft.MainAxisAlignment.CENTER, spacing=12),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8,
            ),
            ft.Container(expand=True),
        ],
        expand=True,
        spacing=0,
    )

    if backend.should_check_for_updates():
        safe_thread(page, check).start()
    else:
        def _skip():
            import time
            time.sleep(0.1)
            ui_call(page, on_continue)
        safe_thread(page, _skip).start()

    return content


# ============================================================================
# VISTA: LOGIN LDAP
# ============================================================================

def _build_login_content(
    page: ft.Page,
    on_success: Callable,
    allow_custom_user: bool = False,
) -> ft.Control:

    default_user = None if allow_custom_user else getpass.getuser()

    user_tf, user_col = styled_field(
        "Username",
        value=default_user or "",
        disabled=(not allow_custom_user and default_user is not None),
        hint="your.username",
    )
    # FIX: sin hint — evita los asteriscos flotantes cuando el campo está vacío
    pass_tf, pass_col = styled_field("Password", password=True)

    error_text = ft.Text("", color=C_ERROR, size=12, visible=False)
    loading    = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                  color=C_PRIMARY, visible=False)
    login_btn  = btn_primary("Authenticate", width=280)

    def do_login(e=None):
        user = (user_tf.value or "").strip()
        pwd  = (pass_tf.value or "").strip()
        if not user or not pwd:
            error_text.value   = "Username and password are required."
            error_text.visible = True
            page.update()
            return

        login_btn.disabled = True
        loading.visible    = True
        error_text.visible = False
        page.update()

        def _auth():
            creds = {"usuario": user, "password": pwd}
            ok    = backend.validar_credenciales_ldap(creds)
            if ok:
                ui_call(page, lambda: on_success(creds))
            else:
                def _fail():
                    error_text.value   = "Invalid credentials. Please try again."
                    error_text.visible = True
                    login_btn.disabled = False
                    loading.visible    = False
                ui_call(page, _fail)

        safe_thread(page, _auth).start()

    login_btn.on_click = do_login
    pass_tf.on_submit  = do_login
    user_tf.on_submit  = lambda e: pass_tf.focus()

    content = ft.Column(
        [
            build_header("Authentication"),
            ft.Container(expand=True),
            ft.Row(
                [
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Icon(ft.Icons.LOCK_OUTLINE, color=C_PRIMARY, size=32),
                                ft.Container(height=8),
                                ft.Text("LDAP Authentication", size=18,
                                        weight=ft.FontWeight.W_600, color=C_TEXT),
                                ft.Text("Use your IRB network credentials",
                                        size=12, color=C_TEXT_DIM),
                                ft.Container(height=24),
                                user_col,
                                ft.Container(height=12),
                                pass_col,
                                ft.Container(height=8),
                                error_text,
                                ft.Container(height=16),
                                ft.Row(
                                    [loading, login_btn],
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=12,
                                ),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=0,
                            width=360,
                        ),
                        bgcolor=C_SURFACE,
                        border=ft.border.all(1, C_BORDER),
                        border_radius=12,
                        padding=36,
                    )
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            ft.Container(expand=True),
        ],
        expand=True,
        spacing=0,
    )

    return content


# ============================================================================
# VISTA: SELECCIÓN DE SHARES CIFS
# ============================================================================

def _build_shares_content(
    page: ft.Page,
    shares: list,
    usuario_actual: str,
    mounts_activos: list,
    es_admin_its: bool,
    credenciales_ldap: dict,
    on_continue: Callable,
) -> ft.Control:

    recursos_cifs_dict = backend.construir_recursos_cifs_dict(shares, usuario_actual)

    # ── Sin shares ─────────────────────────────────────────────────────────
    if not shares:
        content = ft.Column(
            [
                build_header(f"CIFS Shares — {usuario_actual}"),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Container(expand=True),
                            ft.Column(
                                [
                                    ft.Icon(ft.Icons.FOLDER_OFF_OUTLINED,
                                            color=C_TEXT_DIM, size=48),
                                    ft.Text("No accessible shares found.",
                                            size=16, color=C_TEXT),
                                    ft.Text(
                                        "This may be due to network issues or lack of permissions.\n"
                                        "Contact ITS if you believe this is an error.",
                                        size=12, color=C_TEXT_DIM,
                                        text_align=ft.TextAlign.CENTER,
                                    ),
                                    ft.Container(height=24),
                                    btn_primary("Continue without shares →",
                                                on_click=lambda e: on_continue(),
                                                width=260),
                                ],
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                spacing=12,
                            ),
                            ft.Container(expand=True),
                        ],
                        expand=True,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    expand=True,
                    padding=ft.padding.symmetric(horizontal=24, vertical=16),
                ),
            ],
            expand=True,
            spacing=0,
        )
        return content

    # ── Con shares ─────────────────────────────────────────────────────────
    checkboxes: dict[str, ft.Checkbox] = {}
    checkbox_controls = []
    for share in shares:
        cb = ft.Checkbox(
            label=share["name"],
            value=False,
            active_color=C_PRIMARY,
            label_style=ft.TextStyle(color=C_TEXT, size=13),
        )
        checkboxes[share["name"]] = cb
        checkbox_controls.append(cb)

    col_size = 15
    columns  = []
    for i in range(0, len(checkbox_controls), col_size):
        columns.append(ft.Column(checkbox_controls[i:i + col_size], spacing=4, tight=True))

    loading_spin = ft.ProgressRing(width=16, height=16, stroke_width=2,
                                    color=C_PRIMARY, visible=False)
    loading_text = ft.Text("Mounting shares...", color=C_TEXT_DIM, size=12, visible=False)
    error_text   = ft.Text("", color=C_ERROR, size=12, visible=False)
    continue_btn = btn_primary("Continue →", width=200)

    def do_continue(e):
        seleccionados         = [n for n, cb in checkboxes.items() if cb.value]
        continue_btn.disabled = True
        loading_spin.visible  = True
        loading_text.visible  = True
        error_text.visible    = False
        page.update()

        def _mount():
            fallidos = backend.montar_shares_seleccionados(
                seleccionados, recursos_cifs_dict, mounts_activos
            )

            def _after():
                loading_spin.visible  = False
                loading_text.visible  = False
                continue_btn.disabled = False
                if fallidos:
                    error_text.value   = f"Could not mount: {', '.join(fallidos)}"
                    error_text.visible = True
                    page.update()
                else:
                    on_continue()

            ui_call(page, _after)

        safe_thread(page, _mount).start()

    continue_btn.on_click = do_continue

    def update_smb_creds(e):
        _show_smb_cred_dialog(page, usuario_actual, es_admin_its, credenciales_ldap)

    content = ft.Column(
        [
            build_header(f"CIFS Shares — {usuario_actual}"),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("SELECT SHARES TO MOUNT"),
                        ft.Container(height=12),
                        ft.Container(
                            content=ft.Column(
                                [ft.Row(columns, spacing=32, wrap=True)],
                                spacing=0,
                                tight=True,
                            ),
                            bgcolor=C_SURFACE,
                            border=ft.border.all(1, C_BORDER),
                            border_radius=10,
                            padding=16,
                        ),
                        ft.Container(height=16),
                        ft.Row(
                            [
                                btn_secondary("Update SMB credentials",
                                              on_click=update_smb_creds),
                                ft.Container(expand=True),
                                ft.Column(
                                    [
                                        error_text,
                                        ft.Row([loading_spin, loading_text], spacing=8),
                                        continue_btn,
                                    ],
                                    horizontal_alignment=ft.CrossAxisAlignment.END,
                                    spacing=8,
                                    tight=True,
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Container(height=16),
                    ],
                    spacing=0,
                    tight=True,
                ),
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        spacing=0,
        tight=True,
    )

    return content


def _show_smb_cred_dialog(
    page: ft.Page,
    usuario_actual: str,
    es_admin_its: bool,
    credenciales_ldap: dict,
) -> None:
    # FIX: sin hint en campo password
    pass_tf, pass_col = styled_field("New SMB Password", password=True)
    err = ft.Text("", color=C_ERROR, size=12, visible=False)

    def save(e):
        pwd = (pass_tf.value or "").strip()
        if not pwd:
            err.value   = "Password required."
            err.visible = True
            page.update()
            return
        creds = {"usuario": usuario_actual, "password": pwd}
        if not es_admin_its and not backend.validar_credenciales_ldap(creds):
            err.value   = "Invalid credentials."
            err.visible = True
            page.update()
            return
        try:
            backend.actualizar_password_perfiles_rclone(usuario_actual, pwd)
            dlg.open = False
            page.update()
            show_dialog(page, "Success",
                        f"Credentials updated for all profiles of {usuario_actual}.",
                        C_ACCENT)
        except Exception as ex:
            err.value   = str(ex)
            err.visible = True
            page.update()

    def cancel(e):
        dlg.open = False
        page.update()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text("Update SMB Credentials", color=C_TEXT, size=15,
                      weight=ft.FontWeight.W_600),
        content=ft.Column(
            [
                ft.Text(f"User: {usuario_actual}", color=C_TEXT_DIM, size=12),
                ft.Container(height=12),
                pass_col,
                err,
            ],
            spacing=6,
            tight=True,
            width=320,
        ),
        actions=[btn_secondary("Cancel", on_click=cancel), btn_primary("Save", on_click=save)],
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.overlay.append(dlg)
    dlg.open = True
    page.update()


# ============================================================================
# VISTA: SELECCIÓN DE SERVIDOR MINIO
# ============================================================================

def _build_minio_content(page: ft.Page, on_continue: Callable) -> ft.Control:
    servers  = list(backend.MINIO_SERVERS.keys())
    selected = {"current": servers[0]}

    server_cards: dict[str, ft.Container] = {}

    def make_server_card(srv_name: str) -> ft.Container:
        info   = backend.MINIO_SERVERS[srv_name]["IRB"]
        is_sel = srv_name == selected["current"]
        c = ft.Container(
            content=ft.Row(
                [
                    ft.Radio(value=srv_name, active_color=C_PRIMARY),
                    ft.Column(
                        [
                            ft.Text(srv_name, size=14, weight=ft.FontWeight.W_600,
                                    color=C_TEXT),
                            ft.Text(info["endpoint"], size=11, color=C_TEXT_DIM,
                                    font_family=FONT_MONO),
                        ],
                        spacing=2,
                        tight=True,
                        expand=True,
                    ),
                    ft.Icon(ft.Icons.STORAGE,
                            color=C_PRIMARY if is_sel else C_BORDER, size=20),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=12,
            ),
            bgcolor=C_SURFACE2 if is_sel else C_SURFACE,
            border=ft.border.all(2 if is_sel else 1,
                                  C_PRIMARY if is_sel else C_BORDER),
            border_radius=8,
            padding=ft.padding.symmetric(horizontal=16, vertical=12),
        )
        server_cards[srv_name] = c
        return c

    rg = ft.RadioGroup(
        content=ft.Column([make_server_card(s) for s in servers], spacing=8),
        value=servers[0],
    )

    def on_radio_change(e):
        selected["current"] = rg.value
        for srv, card_c in server_cards.items():
            is_sel = srv == selected["current"]
            card_c.bgcolor = C_SURFACE2 if is_sel else C_SURFACE
            card_c.border  = ft.border.all(2 if is_sel else 1,
                                             C_PRIMARY if is_sel else C_BORDER)
            card_c.content.controls[2].color = C_PRIMARY if is_sel else C_BORDER
        page.update()

    rg.on_change = on_radio_change

    def do_continue(e):
        srv = selected["current"]
        on_continue({
            "servidor": srv,
            "perfil":   backend.MINIO_SERVERS[srv]["IRB"]["profile"],
            "endpoint": backend.MINIO_SERVERS[srv]["IRB"]["endpoint"],
        })

    content = ft.Column(
        [
            build_header("MinIO Server"),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("SELECT DESTINATION SERVER"),
                        ft.Container(height=12),
                        card(rg, padding=16),
                        ft.Container(height=24),
                        ft.Row(
                            [btn_primary("Continue →", on_click=do_continue, width=200)],
                            alignment=ft.MainAxisAlignment.END,
                        ),
                    ],
                    spacing=0,
                ),
                expand=True,
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        expand=True,
        spacing=0,
    )

    return content


# ============================================================================
# VISTA: CREDENCIALES STS / RENOVACIÓN
# ============================================================================

def _build_credentials_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    credenciales_ldap: dict,
    on_continue: Callable,
) -> ft.Control:

    token_actual = backend.get_rclone_session_token(perfil_rclone)
    if token_actual:
        tiempo     = backend.get_expiration_from_session_token(token_actual)
        expiry_str = str(tiempo) if tiempo else "Unknown"
        has_token  = True
    else:
        expiry_str = "No credentials configured yet."
        has_token  = False

    dias_var = ft.Dropdown(
        options=[ft.dropdown.Option(str(i)) for i in range(1, 31)],
        value="7",
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        border_radius=6,
        width=100,
        text_size=13,
    )

    error_text   = ft.Text("", color=C_ERROR, size=12, visible=False)
    loading_spin = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                    color=C_PRIMARY, visible=False)
    renew_btn = btn_primary("Renew credentials", width=220)
    keep_btn  = btn_secondary("Keep current", width=180) if has_token else None

    def do_renew(e):
        renew_btn.disabled   = True
        loading_spin.visible = True
        error_text.visible   = False
        if keep_btn:
            keep_btn.disabled = True
        page.update()

        def _renew():
            dias  = int(dias_var.value) * 86400
            creds = backend.get_credentials(
                endpoint,
                credenciales_ldap["usuario"],
                credenciales_ldap["password"],
                dias,
            )
            if creds is None:
                def _fail():
                    loading_spin.visible = False
                    renew_btn.disabled   = False
                    if keep_btn:
                        keep_btn.disabled = False
                    error_text.value   = "Invalid credentials or server error. Contact ITS."
                    error_text.visible = True
                ui_call(page, _fail)
            else:
                backend.configure_rclone(
                    creds["AccessKeyId"],
                    creds["SecretAccessKey"],
                    creds["SessionToken"],
                    endpoint,
                    perfil_rclone,
                )
                ui_call(page, on_continue)

        safe_thread(page, _renew).start()

    def do_keep(e):
        on_continue()

    renew_btn.on_click = do_renew
    if keep_btn:
        keep_btn.on_click = do_keep

    if has_token:
        token_status = ft.Row(
            [
                ft.Icon(ft.Icons.ACCESS_TIME, color=C_WARNING, size=16),
                ft.Text("Current credentials expire in:", size=12, color=C_TEXT_DIM),
                ft.Text(expiry_str, size=12, color=C_WARNING,
                        weight=ft.FontWeight.W_600, font_family=FONT_MONO),
            ],
            spacing=8,
        )
    else:
        token_status = ft.Row(
            [
                ft.Icon(ft.Icons.WARNING_AMBER_OUTLINED, color=C_ERROR, size=16),
                ft.Text("No credentials configured. Renewal required.",
                        size=12, color=C_ERROR),
            ],
            spacing=8,
        )

    buttons_row_controls = [
        ft.Row([loading_spin, renew_btn],
               vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
    ]
    if keep_btn:
        buttons_row_controls.insert(0, keep_btn)

    content = ft.Column(
        [
            build_header("S3 Credentials"),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("STS CREDENTIALS — " + perfil_rclone.upper()),
                        ft.Container(height=12),
                        card(
                            ft.Column(
                                [
                                    token_status,
                                    ft.Container(height=16),
                                    divider(),
                                    ft.Container(height=16),
                                    ft.Row(
                                        [
                                            ft.Text("New credential lifespan:",
                                                    size=13, color=C_TEXT),
                                            dias_var,
                                            ft.Text("days", size=13, color=C_TEXT_DIM),
                                        ],
                                        spacing=12,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                ],
                                spacing=0,
                            ),
                        ),
                        ft.Container(height=8),
                        error_text,
                        ft.Container(height=16),
                        ft.Row(
                            buttons_row_controls,
                            alignment=ft.MainAxisAlignment.END,
                            spacing=12,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                    ],
                    spacing=0,
                ),
                expand=True,
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        expand=True,
        spacing=0,
    )

    return content


# ============================================================================
# VISTA: INTERFAZ PRINCIPAL DE COPIA
# ============================================================================

def _build_copy_content(
    page: ft.Page,
    perfil_rclone: str,
    mounts_activos: list,
    on_close: Callable,
) -> ft.Control:

    num_cores = backend.obtener_num_cpus()
    _, rclone_config_path, _ = backend.get_rclone_paths(perfil_rclone)

    # ── Campos de origen / destino ─────────────────────────────────────────
    origen_tf, origen_col = styled_field(
        "Source path" + (" (server path)" if IS_WEB else " (local path or rclone remote)"),
        hint="/path/to/data" if IS_WEB else "/local/path  or  profile:/path",
    )
    destino_tf, destino_col = styled_field(
        f"Destination path (bucket in {perfil_rclone})",
        hint="bucket-name/subpath",
    )
    flags_tf, flags_col = styled_field(
        "Additional rclone flags (advanced)",
        value=f"--transfers={num_cores} --checkers={num_cores} --s3-no-check-bucket",
    )

    ruta_label = ft.Text(
        "Destination: [incomplete]",
        size=12,
        color=C_TEXT_DIM,
        font_family=FONT_MONO,
    )

    # ── Metadatos ──────────────────────────────────────────────────────────
    meta_labels = [
        ("Project",          "project_name"),
        ("Host machine",     "compute_node"),
        ("Sample type",      "sample_type"),
        ("Input data type",  "input_data_type"),
        ("Output data type", "output_data_type"),
        ("Requested by",     "requested_by"),
        ("Research group",   "research_group"),
    ]
    meta_fields: dict[str, ft.TextField] = {}
    meta_controls = []
    for label, key in meta_labels:
        tf, col = styled_field(label)
        meta_fields[key] = tf
        meta_controls.append(col)

    meta_left  = ft.Column(meta_controls[:4], spacing=10, expand=True)
    meta_right = ft.Column(meta_controls[4:], spacing=10, expand=True)
    meta_grid  = ft.Row([meta_left, meta_right], spacing=16, expand=True)

    # ── Log: ListView con auto_scroll ──────────────────────────────────────
    log_list = ft.ListView(
        expand=True,
        auto_scroll=True,
        spacing=0,
        padding=ft.padding.all(12),
    )
    log_container = ft.Container(
        content=log_list,
        bgcolor=C_BG,
        border=ft.border.all(1, C_BORDER),
        border_radius=6,
        height=280,
    )

    def log(msg: str):
        def _add():
            for line in msg.splitlines(keepends=True):
                if line.strip():
                    color = (
                        C_ACCENT  if line.startswith("✅") else
                        C_ERROR   if line.startswith("❌") else
                        C_WARNING if line.startswith("⚠️") else
                        C_PRIMARY if line.startswith("🔍") or line.startswith("🧾") else
                        C_TEXT
                    )
                    log_list.controls.append(
                        ft.Text(line.rstrip("\n"),
                                size=11, color=color,
                                font_family=FONT_MONO, selectable=True)
                    )
        ui_call(page, _add)

    # ── Botones de acción ──────────────────────────────────────────────────
    copy_btn  = btn_primary("▶  Copy data")
    check_btn = btn_primary("✓  Check data", disabled=True)
    mount_btn = btn_secondary("⊞  Mount destination")
    mount_btn.visible = not IS_WEB
    save_btn  = btn_secondary("↓  Save log")
    close_btn = btn_secondary("✕  Close")

    def enable_btn(btn):
        def _do():
            btn.disabled = False
            btn.update()
        ui_call(page, _do)

    # ── FilePicker (solo desktop) ──────────────────────────────────────────
    if not IS_WEB:
        file_picker   = ft.FilePicker()
        folder_picker = ft.FilePicker()
        save_picker   = ft.FilePicker()
        page.overlay.extend([file_picker, folder_picker, save_picker])

        def on_file_picked(e: ft.FilePickerResultEvent):
            if e.files:
                ruta = backend.traducir_ruta_a_remote(e.files[0].path, mounts_activos)
                origen_tf.value = ruta
                actualizar_ruta_label()
                page.update()

        def on_folder_picked(e: ft.FilePickerResultEvent):
            if e.path:
                ruta = backend.traducir_ruta_a_remote(e.path, mounts_activos)
                origen_tf.value = ruta
                actualizar_ruta_label()
                page.update()

        def on_save_result(ev: ft.FilePickerResultEvent):
            if ev.path:
                contenido = "\n".join(
                    c.value for c in log_list.controls
                    if isinstance(c, ft.Text) and c.value
                )
                try:
                    with open(ev.path, "w", encoding="utf-8") as f:
                        f.write(contenido)
                    show_dialog(page, "Log saved", f"Saved to:\n{ev.path}", C_ACCENT)
                except Exception as ex:
                    show_dialog(page, "Error", str(ex), C_ERROR)

        file_picker.on_result   = on_file_picked
        folder_picker.on_result = on_folder_picked
        save_picker.on_result   = on_save_result

        pick_file_btn   = btn_secondary("📄 File",
                                        on_click=lambda e: file_picker.pick_files())
        pick_folder_btn = btn_secondary("📁 Folder",
                                        on_click=lambda e: folder_picker.get_directory_path())
        pick_row = ft.Row([pick_file_btn, pick_folder_btn], spacing=8)
    else:
        pick_row    = ft.Text("Enter the full server path above.", size=11, color=C_TEXT_DIM)
        save_picker = None

    # ── Verificación destino con debounce ──────────────────────────────────
    _debounce = {"timer": None}

    def actualizar_ruta_label(*_):
        destino = (destino_tf.value or "").strip().rstrip("/")
        ruta_label.value = f"→ {destino}/" if destino else "Destination: [incomplete]"
        ruta_label.update()

    def _check_dest_thread():
        ruta = (destino_tf.value or "").strip()
        if not ruta:
            return
        ok = backend.verificar_ruta_rclone_accesible(perfil_rclone, ruta)
        def _update_border():
            destino_tf.border_color = C_ACCENT if ok else C_ERROR
            destino_tf.update()
        ui_call(page, _update_border)

    def on_destino_change(e=None):
        actualizar_ruta_label()
        if _debounce["timer"]:
            _debounce["timer"].cancel()
        _debounce["timer"] = threading.Timer(0.6, _check_dest_thread)
        _debounce["timer"].start()

    destino_tf.on_change = on_destino_change
    origen_tf.on_change  = lambda e: actualizar_ruta_label()

    # ── Copiar ─────────────────────────────────────────────────────────────
    def do_copy(e):
        origen  = (origen_tf.value  or "").strip()
        destino = (destino_tf.value or "").strip()
        if not origen or not destino:
            show_dialog(page, "Error", "Source and destination are required.", C_ERROR)
            return

        metadatos = {k: (tf.value or "").strip() for k, tf in meta_fields.items()}
        flags     = (flags_tf.value or "").strip().split()

        copy_btn.disabled  = True
        check_btn.disabled = True
        page.update()

        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log(f"### Copy started at {ahora} ###\n")
        log("### Metadata ###\n")
        for k, v in metadatos.items():
            log(f"  {k}: {v}\n")
        log("\n")

        safe_thread(page, lambda: backend.ejecutar_rclone_copy(
            origen=origen,
            destino_perfil=perfil_rclone,
            destino_path=destino,
            rclone_config_path=rclone_config_path,
            metadatos_dict=metadatos,
            flags_adicionales=flags,
            num_cores=num_cores,
            log_fn=log,
            on_success=lambda: enable_btn(check_btn),
            on_finish=lambda: enable_btn(copy_btn),
        )).start()

    # ── Check ──────────────────────────────────────────────────────────────
    def do_check(e):
        origen  = (origen_tf.value  or "").strip()
        destino = (destino_tf.value or "").strip()
        if not origen or not destino:
            show_dialog(page, "Error", "Source and destination are required.", C_ERROR)
            return

        flags = (flags_tf.value or "").strip().split()
        check_btn.disabled = True
        page.update()
        log(f"\n🔍 Verifying: rclone check {origen} → {perfil_rclone}:/{destino}\n\n")

        safe_thread(page, lambda: backend.ejecutar_rclone_check(
            origen=origen,
            destino_perfil=perfil_rclone,
            destino_path=destino,
            rclone_config_path=rclone_config_path,
            flags_adicionales=flags,
            mounts_activos=mounts_activos,
            log_fn=log,
            on_finish=lambda: enable_btn(check_btn),
        )).start()

    # ── Montar destino ─────────────────────────────────────────────────────
    def do_mount(e):
        ruta = (destino_tf.value or "").strip()
        if not ruta:
            show_dialog(page, "Error", "Specify a destination path to mount.", C_ERROR)
            return
        try:
            backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
        except EnvironmentError as ex:
            show_dialog(page, "FUSE / WinFSP not detected", str(ex), C_ERROR)
        except Exception as ex:
            show_dialog(page, "Mount error", str(ex), C_ERROR)

    # ── Guardar log ────────────────────────────────────────────────────────
    def do_save_log(e):
        contenido = "\n".join(
            c.value for c in log_list.controls
            if isinstance(c, ft.Text) and c.value
        )
        if not contenido.strip():
            show_dialog(page, "Save log", "No log content to save.", C_WARNING)
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if IS_WEB:
            fname = f"bifrost-{ts}.log"
            try:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(contenido)
                show_dialog(page, "Log saved", f"Saved as {fname} on the server.", C_ACCENT)
            except Exception as ex:
                show_dialog(page, "Error", str(ex), C_ERROR)
        else:
            save_picker.save_file(file_name=f"bifrost-{ts}.log")

    # ── Cierre ─────────────────────────────────────────────────────────────
    def _do_close_cleanup():
        log("\n🧹 Unmounting mount points...\n")
        ruta_dest = (destino_tf.value or "").strip()
        if ruta_dest:
            mp = backend.resolver_mount_point_destino(perfil_rclone, ruta_dest)
            backend.desmontar_punto_montaje(mp, log_fn=log)
        log("✅ Done.\n")
        ui_call(page, on_close)

    def do_close(e):
        show_confirm(
            page,
            "Close BIFROST",
            "This will unmount all mount points and close the application.",
            on_yes=lambda: safe_thread(page, _do_close_cleanup).start(),
        )

    copy_btn.on_click  = do_copy
    check_btn.on_click = do_check
    mount_btn.on_click = do_mount
    save_btn.on_click  = do_save_log
    close_btn.on_click = do_close

    # ── Layout ────────────────────────────────────────────────────────────
    content = ft.Column(
        [
            build_header(f"Copy & Verify — {perfil_rclone}"),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("PATHS"),
                        ft.Container(height=10),
                        card(
                            ft.Column(
                                [
                                    origen_col,
                                    ft.Container(height=4),
                                    pick_row,
                                    ft.Container(height=12),
                                    destino_col,
                                    ft.Container(height=6),
                                    ruta_label,
                                    ft.Container(height=12),
                                    flags_col,
                                ],
                                spacing=0,
                            ),
                        ),
                        ft.Container(height=16),
                        section_title("METADATA"),
                        ft.Container(height=10),
                        card(meta_grid),
                        ft.Container(height=16),
                        ft.Row(
                            [copy_btn, check_btn, mount_btn, save_btn,
                             ft.Container(expand=True), close_btn],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            wrap=True,
                        ),
                        ft.Container(height=12),
                        section_title("LOG OUTPUT"),
                        ft.Container(height=8),
                        log_container,
                        ft.Container(height=16),
                    ],
                    spacing=0,
                    expand=True,
                ),
                expand=True,
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        expand=True,
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    return content


# ============================================================================
# VERIFICACIÓN DE RCLONE EN DESKTOP
# ============================================================================

def check_rclone_installation_flet(page: ft.Page) -> None:
    if not backend.detect_rclone_installed():
        sistema = sys.platform
        if sistema == "darwin":
            if not backend.is_brew_installed():
                show_dialog(
                    page,
                    "Rclone not found",
                    "Rclone is not installed and Homebrew is not available.\n"
                    "Install Homebrew first: https://brew.sh/",
                    C_ERROR,
                )
                sys.exit(1)
            backend.install_rclone_macos()
        elif sistema == "win32":
            show_dialog(
                page,
                "Rclone.exe not found",
                "Download rclone.exe and place it in the same folder as this executable.\n"
                "https://rclone.org/downloads/\n\n"
                "Also install WinFsp from https://winfsp.dev/rel/",
                C_ERROR,
            )
            sys.exit(1)

    if sys.platform == "darwin":
        try:
            backend.ensure_fuse_macos()
        except EnvironmentError as e:
            show_dialog(page, "fuse-t not available", str(e), C_ERROR)
            sys.exit(1)


# ============================================================================
# UPDATER WINDOWS
# ============================================================================

def _escribir_y_lanzar_updater_windows(ruta_actual: str, nueva_ruta: str) -> None:
    updater_code = f"""@echo off
setlocal
set "OLD_EXE={ruta_actual}"
set "NEW_EXE={nueva_ruta}"
echo Waiting for the application to close...
set /a i=0
:waitloop
if %i% geq 30 goto timeout_err
del /f "%OLD_EXE%" >nul 2>&1
if not exist "%OLD_EXE%" goto do_move
timeout /t 1 /nobreak >nul
set /a i+=1
goto waitloop
:do_move
move /y "%NEW_EXE%" "%OLD_EXE%"
if errorlevel 1 (echo ERROR: Could not replace executable. & pause & exit /b 1)
echo Update completed! Please reopen the application.
pause
exit /b 0
:timeout_err
echo ERROR: Timeout waiting for old executable.
pause
exit /b 1
"""
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".bat", mode="w", encoding="utf-8"
    ) as f:
        f.write(updater_code)
        updater_path = f.name
    subprocess.Popen(["cmd.exe", "/c", "start", "", updater_path], shell=False)
    os._exit(0)


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
    page.title             = "BIFROST — IRB Data Transfer"
    page.bgcolor           = C_BG
    page.window.width      = 1100
    page.window.height     = 820
    page.window.min_width  = 800
    page.window.min_height = 600
    page.theme             = ft.Theme(color_scheme_seed=C_PRIMARY)
    page.theme_mode        = ft.ThemeMode.DARK
    page.padding           = 0

    state = {
        "credenciales_ldap":     None,
        "grupos_ldap":           [],
        "usar_privilegios":      False,
        "credenciales_admin":    None,
        "credenciales_smb":      None,
        "shares_accesibles":     [],
        "perfiles_configurados": [],
        "mounts_activos":        [],
        "servidor_minio":        None,
        "perfil_rclone":         None,
        "endpoint":              None,
    }

    ALLOW_CUSTOM_USER = "--customuser" in sys.argv or "-c" in sys.argv

    body = ft.Container(expand=True, bgcolor=C_BG)
    page.scroll = ft.ScrollMode.AUTO
    page.add(body)
    page.update()

    def show_screen(content: ft.Control):
        body.content = content
        page.update()

    def show_loading(message: str = "Loading..."):
        show_screen(
            ft.Column(
                [
                    ft.Container(expand=True),
                    ft.Column(
                        [
                            ft.ProgressRing(color=C_PRIMARY, width=48, height=48, stroke_width=4),
                            ft.Container(height=16),
                            ft.Text(message, size=14, color=C_TEXT_DIM),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=0,
                    ),
                    ft.Container(expand=True),
                ],
                expand=True,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            )
        )

    if not IS_WEB:
        def on_close(e):
            if state["mounts_activos"]:
                usuario = (
                    (state["credenciales_smb"] or {}).get("usuario")
                    or getpass.getuser()
                )
                safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()

        page.on_close = on_close

    def go_login():
        show_screen(_build_login_content(page, on_success=on_login_success,
                                          allow_custom_user=ALLOW_CUSTOM_USER))

    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds
        show_loading("Fetching LDAP groups...")

        def _load_groups():
            grupos = backend.get_ldap_groups(creds["usuario"])
            state["grupos_ldap"] = grupos

            if "its" in grupos and not IS_WEB:
                def _ask_privileges():
                    show_confirm(
                        page,
                        "ITS Administrator Privileges",
                        "Do you want to use ITS administrator privileges for CIFS shares?",
                        on_yes=_ask_admin_creds,
                        on_no=_after_privileges,
                    )
                ui_call(page, _ask_privileges)
            else:
                state["usar_privilegios"] = False
                ui_call(page, _after_privileges)

        safe_thread(page, _load_groups).start()

    def _ask_admin_creds():
        admin_user = "admin_" + state["credenciales_ldap"]["usuario"]
        # FIX: sin hint en campo password
        admin_tf, admin_col = styled_field("Admin password", password=True)
        err = ft.Text("", color=C_ERROR, size=12, visible=False)

        def confirm(e):
            pwd = (admin_tf.value or "").strip()
            if not pwd:
                err.value   = "Password required."
                err.visible = True
                page.update()
                return
            state["usar_privilegios"]   = True
            state["credenciales_admin"] = {"usuario": admin_user, "password": pwd}
            dlg.open = False
            page.update()
            _after_privileges()

        def cancel(e):
            state["usar_privilegios"]   = False
            state["credenciales_admin"] = None
            dlg.open = False
            page.update()
            _after_privileges()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Admin Credentials", color=C_TEXT, size=15,
                          weight=ft.FontWeight.W_600),
            content=ft.Column(
                [
                    ft.Text(f"Username: {admin_user}", color=C_TEXT_DIM, size=12),
                    ft.Container(height=10),
                    admin_col,
                    err,
                ],
                spacing=6, tight=True, width=300,
            ),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                btn_primary("Confirm",  on_click=confirm),
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.overlay.append(dlg)
        dlg.open = True
        page.update()

    def _after_privileges():
        creds_ldap = state["credenciales_ldap"]
        try:
            state["credenciales_smb"] = backend.construir_credenciales_smb(
                creds_ldap,
                state["usar_privilegios"],
                state["credenciales_admin"],
            )
        except ValueError as ex:
            show_dialog(page, "Error", str(ex), C_ERROR)
            return

        show_loading("Loading accessible shares...")

        def _load_shares():
            perfiles = backend.obtener_perfiles_rclone_config()
            shares   = backend.obtener_shares_accesibles(
                state["grupos_ldap"],
                creds_ldap["usuario"],
                creds_ldap["password"],
                state["credenciales_smb"]["usuario"],
                backend.EXCEPCION_FILERS,
                state["usar_privilegios"],
            )
            perfiles = backend.configurar_perfiles_smb_si_faltan(
                shares, state["credenciales_smb"], perfiles
            )
            state["shares_accesibles"]     = shares
            state["perfiles_configurados"] = perfiles

            def _show():
                show_screen(_build_shares_content(
                    page,
                    shares=shares,
                    usuario_actual=state["credenciales_smb"]["usuario"],
                    mounts_activos=state["mounts_activos"],
                    es_admin_its=state["usar_privilegios"],
                    credenciales_ldap=creds_ldap,
                    on_continue=go_minio,
                ))
            ui_call(page, _show)

        safe_thread(page, _load_shares).start()

    def go_minio():
        show_screen(_build_minio_content(page, on_continue=on_minio_selected))

    def on_minio_selected(eleccion: dict):
        state["servidor_minio"] = eleccion["servidor"]
        state["perfil_rclone"]  = eleccion["perfil"]
        state["endpoint"]       = eleccion["endpoint"]

        if not IS_WEB:
            check_rclone_installation_flet(page)

        show_screen(_build_credentials_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            endpoint=state["endpoint"],
            credenciales_ldap=state["credenciales_ldap"],
            on_continue=go_copy,
        ))

    def go_copy():
        show_screen(_build_copy_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            mounts_activos=state["mounts_activos"],
            on_close=do_close,
        ))

    def do_close():
        usuario = (state["credenciales_smb"] or {}).get("usuario") or getpass.getuser()
        safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()
        if IS_WEB:
            show_screen(
                ft.Column(
                    [
                        ft.Container(expand=True),
                        ft.Column(
                            [
                                ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=56),
                                ft.Text("Session closed", size=24, color=C_TEXT,
                                        weight=ft.FontWeight.W_600),
                                ft.Text("You can close this browser tab.",
                                        size=14, color=C_TEXT_DIM),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=12,
                        ),
                        ft.Container(expand=True),
                    ],
                    expand=True,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                )
            )
        else:
            page.window.close()

    show_screen(_build_update_content(page, on_continue=go_login))

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if IS_WEB:
        ft.app(
            target=main,
            view=ft.AppView.WEB_BROWSER,
            port=int(os.environ.get("BIFROST_PORT", "8080")),
        )
    else:
        ft.app(target=main)