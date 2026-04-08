from __future__ import annotations


"""
IRB MinIO Rclone Data Transfer Tool — FRONTEND (Flet)
=====================================================

Migración de tkinter a Flet.
Soporta modo desktop y modo web (--web).

Uso:
    python bifrost.py          # desktop
    python bifrost.py --web    # Open OnDemand / cluster (Rocky Linux)

Flujo de vistas (Mac / Windows / Web):
    view_update → view_login → view_minio → view_credentials (auto) → view_copy

Flujo de vistas (Linux cluster):
    view_update → view_login → view_shares → view_minio
    → view_credentials → view_copy

Notas sobre credenciales STS:
  - Si quedan MÁS de 3 días → se salta la renovación y va directo a view_copy
  - Si quedan MENOS de 3 días (o no hay credenciales) → renueva automáticamente
    por 7 días, mostrando el progreso en un log en pantalla
  - No hay botones manuales de renovación en el flujo Mac/Windows/Web

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
  - Navegador de carpetas rclone para el destino (build_rclone_browser)
  - FIX: carga inicial del browser diferida con Timer para evitar
    "Text Control must be added to the page first"
"""

import os
import sys
import io
import stat
import getpass
import tempfile
import subprocess
import threading
import traceback
import pathlib
from datetime import datetime
from typing import Callable

import flet as ft

import backend

# ============================================================================
# MODO DE EJECUCIÓN
# ============================================================================

#Para desarrollo local: DEV_WEB = True
DEV_WEB = os.environ.get("BIFROST_DEV") == "1"
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or DEV_WEB

# En Linux cluster el flujo incluye CIFS; en el resto se omite
# Para desarrollo local: BIFROST_CLUSTER = "1"
IS_LINUX_CLUSTER = (sys.platform == "linux" and "_linux_cluster" in os.path.basename(
    sys.argv[0] if sys.argv else "" 
)) or os.environ.get("BIFROST_CLUSTER") == "1"

# Umbral (en días) por debajo del cual se renuevan las credenciales STS automáticamente
STS_RENEWAL_THRESHOLD_DAYS = 3
# Duración (en días) de las credenciales STS renovadas automáticamente
STS_AUTO_RENEWAL_DAYS = 7

# ============================================================================
# HELPER THREAD-SAFE PARA ACTUALIZAR UI
# ============================================================================

def ui_call(page: ft.Page, fn: Callable) -> None:
    page.run_thread(fn)

# ============================================================================
# PARA EVITAR PROBLEMAS DE CODIFICACIÓN EN CONSOLA (ESPECIALMENTE EN WINDOWS)
# ============================================================================
if sys.stdout and hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'buffer'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


# ============================================================================
# WRAPPER SEGURO PARA HILOS — captura excepciones y las muestra en diálogo
# ============================================================================

def safe_thread(page: ft.Page, target: Callable, daemon: bool = True) -> threading.Thread:
    """
    Crea un Thread que captura cualquier excepción no controlada y la muestra
    en un diálogo de error en lugar de matar el proceso silenciosamente.
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
C_OVERLAY  = "#1C2027"
FONT_MONO  = "Courier New"


def btn_primary(text: str, on_click=None, width=None, disabled=False) -> ft.ElevatedButton:
    return ft.ElevatedButton(
        content=ft.Text(text),
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
        content=ft.Text(text),
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
# SESSION PERSISTENCE (web mode — in-memory, TTL = Hypercorn process lifetime)
# ============================================================================
#
# _WEB_SESSIONS[username] holds every piece of navigation state that can be
# restored without the user's password:
#   - servidor_minio, perfil_rclone, endpoint, extra_config
#   - mounts_activos, usar_privilegios, credenciales_smb_usuario
#   - copy_log_buffer  — accumulated log lines from a running/finished copy
#   - copy_status      — "idle" | "running" | "done" | "error"
#   - copy_proceso     — the live subprocess.Popen object (or None)
#   - copy_origen, copy_destino  — last copy paths
#   - copy_log_callbacks         — callables registered by the current UI page;
#                                  multiple sessions may subscribe simultaneously
#
# The password is NEVER stored here.
# ============================================================================

_WEB_SESSIONS: dict[str, dict] = {}
_LAST_WEB_USER: list[str] = [None]   # one-element list so closures can mutate it


def _ws_save(usuario: str, state: dict) -> None:
    """Persist navigation + copy state for *usuario* into the in-memory store."""
    if not IS_WEB:
        return
    existing = _WEB_SESSIONS.get(usuario, {})
    _WEB_SESSIONS[usuario] = {
        # navigation state (enough to skip update/shares/minio on reconnect)
        "servidor_minio": state.get("servidor_minio"),
        "perfil_rclone":  state.get("perfil_rclone"),
        "endpoint":       state.get("endpoint"),
        "extra_config": (
            backend.MINIO_SERVERS
            .get(state.get("servidor_minio") or "", {})
            .get("IRB", {})
            .get("extra_rclone_config")
        ),
        # copy state — always inherited so a running copy survives reconnection
        "copy_log_buffer":    existing.get("copy_log_buffer", []),
        "copy_status":        existing.get("copy_status", "idle"),
        "copy_origen":        existing.get("copy_origen", ""),
        "copy_destino":       existing.get("copy_destino", ""),
        "copy_log_callbacks": existing.get("copy_log_callbacks", []),
        # The Popen wrapper dict — shared with the background thread so that
        # a new UI session can cancel a process that survived a tab close.
        "copy_proceso":        existing.get("copy_proceso", {"proc": None}),
    }
    _LAST_WEB_USER[0] = usuario
    print(f"[session] Saved session for {usuario!r}")


def _ws_load(usuario: str) -> dict | None:
    """Return the persisted session for *usuario*, or None if absent/incomplete."""
    s = _WEB_SESSIONS.get(usuario)
    if s and s.get("perfil_rclone") and s.get("endpoint"):
        return s
    return None


def _ws_clear(usuario: str) -> None:
    """Remove the session for *usuario*."""
    _WEB_SESSIONS.pop(usuario, None)
    if _LAST_WEB_USER[0] == usuario:
        _LAST_WEB_USER[0] = None
    print(f"[session] Cleared session for {usuario!r}")




# ============================================================================
# HEADER COMÚN
# ============================================================================

def build_header(subtitle: str = "") -> ft.Container:
    version_str = f"v{backend.__version__}" if hasattr(backend, "__version__") else ""
    return ft.Container(
        content=ft.Row(
            [
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
                ft.Text(version_str, size=11, color=C_TEXT_DIM, font_family=FONT_MONO),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE,
        border=ft.border.only(bottom=ft.BorderSide(1, C_BORDER)),
        padding=ft.padding.symmetric(horizontal=24, vertical=16),
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
        page.pop_dialog()

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
    #page.overlay.append(dlg)
    #dlg.open = True
    page.show_dialog(dlg)
    page.update()


def show_confirm(
    page: ft.Page,
    title: str,
    message: str,
    on_yes: Callable,
    on_no: Callable | None = None,
):
    def yes(e):
        page.pop_dialog()
        on_yes()

    def no(e):
        page.pop_dialog()
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
    #page.overlay.append(dlg)
    #dlg.open = True
    page.show_dialog(dlg)
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
    allow_custom_user: bool = True,
    prefill_user: str = "",
) -> ft.Control:

    try:
        default_user = prefill_user or getpass.getuser()
    except Exception:
        default_user = prefill_user or ""

    user_tf, user_col = styled_field(
        "Username",
        value=default_user,
        disabled=False,  # siempre editable
        hint="your.username",
    )

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
                                *(
                                    [
                                        ft.Container(
                                            content=ft.Row(
                                                [
                                                    ft.Icon(ft.Icons.RESTORE, color=C_WARNING, size=14),
                                                    ft.Text(
                                                        "Resuming previous session — enter your password to continue",
                                                        size=11, color=C_WARNING,
                                                    ),
                                                ],
                                                spacing=6,
                                            ),
                                            bgcolor=f"{C_WARNING}18",
                                            border=ft.border.all(1, f"{C_WARNING}44"),
                                            border_radius=6,
                                            padding=ft.padding.symmetric(horizontal=10, vertical=6),
                                        )
                                    ]
                                    if prefill_user else
                                    [ft.Text("Use your IRB network credentials",
                                             size=12, color=C_TEXT_DIM)]
                                ),
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
            page.pop_dialog()
            show_dialog(page, "Success",
                        f"Credentials updated for all profiles of {usuario_actual}.",
                        C_ACCENT)
        except Exception as ex:
            err.value   = str(ex)
            err.visible = True
            page.update()

    def cancel(e):
        page.pop_dialog()

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
    #page.overlay.append(dlg)
    #dlg.open = True
    page.show_dialog(dlg)
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
# VISTA: CREDENCIALES STS — RENOVACIÓN AUTOMÁTICA
# ============================================================================

def _build_credentials_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    credenciales_ldap: dict,
    on_continue: Callable,
    extra_config: dict | None = None,
    duracion_dias: int | None = None,
) -> ft.Control:
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
        height=220,
    )

    progress    = ft.ProgressBar(color=C_PRIMARY, bgcolor=C_SURFACE2)
    status_text = ft.Text("Renewing credentials...", size=13, color=C_TEXT_DIM,
                           font_family=FONT_MONO)

    def log(msg: str, color: str = C_TEXT):
        print(msg.rstrip())
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, selectable=True)
            )
        ui_call(page, _add)

    def _do_renew():
        import time
        from datetime import timedelta

        duracion_segundos = (duracion_dias or STS_AUTO_RENEWAL_DAYS) * 86400

        token_actual = backend.get_rclone_session_token(perfil_rclone)
        if token_actual:
            tiempo = backend.get_expiration_from_session_token(token_actual)
            if tiempo:
                log(f"⚠️  Current credentials expire in: {tiempo}", C_WARNING)
                log(f"    (threshold: {STS_RENEWAL_THRESHOLD_DAYS} days → renewal required)", C_TEXT_DIM)
            else:
                log("⚠️  Could not read expiry from current token.", C_WARNING)
        else:
            log("⚠️  No credentials found for this profile.", C_WARNING)

        log(f"\n🔄 Requesting new STS credentials ({STS_AUTO_RENEWAL_DAYS} days)...", C_PRIMARY)
        log(f"   Profile  : {perfil_rclone}", C_TEXT_DIM)
        log(f"   Endpoint : {endpoint}", C_TEXT_DIM)
        log(f"   User     : {credenciales_ldap['usuario']}", C_TEXT_DIM)

        creds = backend.get_credentials(
            endpoint,
            credenciales_ldap["usuario"],
            credenciales_ldap["password"],
            duracion_segundos,
        )

        if creds is None:
            log("\n❌ Failed to obtain credentials. Check your password or contact ITS.", C_ERROR)
            def _show_err():
                progress.visible  = False
                status_text.value = "❌ Renewal failed."
                status_text.color = C_ERROR
            ui_call(page, _show_err)
            return

        log("\n✅ Credentials obtained successfully.", C_ACCENT)
        log("   Writing to rclone config...", C_TEXT_DIM)

        backend.configure_rclone(
            creds["AccessKeyId"],
            creds["SecretAccessKey"],
            creds["SessionToken"],
            endpoint,
            perfil_rclone,
            extra_config=extra_config,
        )

        new_token = backend.get_rclone_session_token(perfil_rclone)
        if new_token:
            nuevo_tiempo = backend.get_expiration_from_session_token(new_token)
            if nuevo_tiempo:
                dias_renovados = duracion_dias or STS_AUTO_RENEWAL_DAYS
                log(f"   New credentials expire in: {dias_renovados} days", C_ACCENT)

        log(f"\n✅ Done. Continuing to copy interface...", C_ACCENT)

        def _finish():
            progress.visible  = False
            status_text.value = "✓ Credentials renewed. Loading..."
            status_text.color = C_ACCENT

        ui_call(page, _finish)
        time.sleep(1.2)
        ui_call(page, on_continue)

    content = ft.Column(
        [
            build_header("S3 Credentials — Auto Renewal"),
            ft.Container(
                content=ft.Column(
                    [
                        section_title(f"STS AUTO-RENEWAL — {perfil_rclone.upper()}"),
                        ft.Container(height=12),
                        card(
                            ft.Column(
                                [
                                    ft.Row(
                                        [
                                            ft.Icon(ft.Icons.AUTORENEW, color=C_PRIMARY, size=18),
                                            ft.Text(
                                                f"Automatically renewing for {STS_AUTO_RENEWAL_DAYS} days",
                                                size=13, color=C_TEXT,
                                            ),
                                        ],
                                        spacing=10,
                                    ),
                                    ft.Container(height=12),
                                    progress,
                                    ft.Container(height=8),
                                    status_text,
                                ],
                                spacing=0,
                            ),
                        ),
                        ft.Container(height=16),
                        section_title("RENEWAL LOG"),
                        ft.Container(height=8),
                        log_container,
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

    safe_thread(page, _do_renew).start()
    return content


# ============================================================================
# COMPONENTE: NAVEGADOR DE BUCKETS/CARPETAS RCLONE
#
# FIX: la carga inicial NO se lanza aquí dentro sino que se devuelve como
# callable (dest_browser_refresh) para que _build_copy_content la dispare
# con un Timer de 50ms, después de que show_screen() haya añadido todos los
# controles al árbol de Flet y page.update() haya sido llamado.
# Esto evita el error:
#   AssertionError: Text Control must be added to the page first
# ============================================================================

def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str], None],
) -> tuple[ft.Column, Callable]:
    """
    Navegador interactivo de carpetas rclone con breadcrumb.
    La creación de carpetas es VIRTUAL — solo actualiza el path de destino,
    no llama a rclone mkdir. S3 crea el prefijo automáticamente al copiar.

    Returns:
        (widget, refresh_fn) — llama a refresh_fn() una vez que el widget
        esté en la página para arrancar la carga inicial.
    """
    nav_state = {"current_path": "", "timeout": 15}

    breadcrumb_row = ft.Row(spacing=2, wrap=True,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER)
    folder_col     = ft.Column(spacing=4, tight=True)
    loading_row    = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8,
        visible=False,
    )
    error_text = ft.Text("", color=C_ERROR, size=11, visible=False)

    # ── Crear nueva carpeta (virtual) ─────────────────────────────────────
    new_folder_tf = ft.TextField(
        hint_text="new-folder-name",
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        hint_style=ft.TextStyle(color=C_TEXT_DIM),
        border_radius=6,
        content_padding=ft.padding.symmetric(horizontal=10, vertical=8),
        text_size=12,
        expand=True,
    )
    mkdir_status = ft.Text("", size=11, color=C_TEXT_DIM, visible=False)
    mkdir_btn    = ft.IconButton(
        icon=ft.Icons.CREATE_NEW_FOLDER_OUTLINED,
        icon_color=C_ACCENT,
        icon_size=18,
        tooltip="Add folder to destination path (virtual — created on copy)",
    )

    def _rebuild_breadcrumb():
        breadcrumb_row.controls.clear()
        breadcrumb_row.controls.append(
            ft.TextButton(
                content=ft.Text(f"{perfil_rclone}:"),
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.padding.symmetric(horizontal=6, vertical=2),
                ),
                on_click=lambda e: _navigate(""),
            )
        )
        parts = [p for p in nav_state["current_path"].split("/") if p]
        accumulated = ""
        for i, part in enumerate(parts):
            accumulated = f"{accumulated}/{part}" if accumulated else part
            path_snap   = accumulated
            is_last     = (i == len(parts) - 1)
            breadcrumb_row.controls.append(ft.Text("/", size=12, color=C_TEXT_DIM))
            if is_last:
                breadcrumb_row.controls.append(
                    ft.Text(part, size=12, color=C_TEXT, weight=ft.FontWeight.W_600)
                )
            else:
                breadcrumb_row.controls.append(
                    ft.TextButton(
                        content=ft.Text(part),
                        style=ft.ButtonStyle(
                            color=C_PRIMARY,
                            padding=ft.padding.symmetric(horizontal=6, vertical=2),
                        ),
                        on_click=lambda e, p=path_snap: _navigate(p),
                    )
                )

    def _navigate(path: str):
        nav_state["current_path"] = path
        on_select(path)

        loading_row.visible  = True
        error_text.visible   = False
        folder_col.controls.clear()
        _rebuild_breadcrumb()
        page.update()

        def _load():
            try:
                folders = backend.rclone_lsd(perfil_rclone, path, timeout=nav_state["timeout"])
                print(f"[browser] path={path!r} folders={folders}")

                def _show():
                    loading_row.visible = False
                    folder_col.controls.clear()

                    if not folders:
                        folder_col.controls.append(
                            ft.Text("(empty — no subfolders)", size=11, color=C_TEXT_DIM, italic=True)
                        )
                    else:
                        for fname in folders:
                            full_path = f"{path}/{fname}" if path else fname
                            fp_snap   = full_path

                            row = ft.Container(
                                content=ft.Row(
                                    [
                                        ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
                                        ft.Text(fname, size=12, color=C_TEXT, expand=True),
                                        ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=14),
                                    ],
                                    spacing=8,
                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                ),
                                bgcolor=C_SURFACE2,
                                border=ft.border.all(1, C_BORDER),
                                border_radius=6,
                                padding=ft.padding.symmetric(horizontal=12, vertical=8),
                                on_click=lambda e, p=fp_snap: _navigate(p),
                                ink=True,
                            )
                            folder_col.controls.append(row)

                    page.update()

                ui_call(page, _show)

            except subprocess.TimeoutExpired:
                def _timeout_ui():
                    loading_row.visible = False
                    folder_col.controls.clear()

                    # Input para path manual, prefijado con el path actual
                    manual_tf = ft.TextField(
                        value=path,
                        bgcolor=C_SURFACE2,
                        border_color=C_BORDER,
                        focused_border_color=C_PRIMARY,
                        color=C_TEXT,
                        border_radius=6,
                        content_padding=ft.padding.symmetric(horizontal=10, vertical=8),
                        text_size=12,
                        expand=True,
                        visible=False,
                    )
                    def confirm_manual(e):
                        new_path = manual_tf.value.strip()
                        nav_state["current_path"] = new_path
                        on_select(new_path)
                        _rebuild_breadcrumb()
                        manual_tf.visible   = False
                        confirm_btn.visible = False
                        confirmed_badge.visible = True
                        page.update()

                    confirmed_badge = ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=14),
                                ft.Text("Path set!", color=C_ACCENT, size=11, weight=ft.FontWeight.W_600),
                            ],
                            spacing=6,
                        ),
                        visible=False,
                    )

                    confirm_btn = btn_primary("✓ Confirm path", on_click=confirm_manual)
                    confirm_btn.visible = False

                    def show_manual_input(e):
                        manual_tf.visible  = True
                        confirm_btn.visible = True
                        page.update()

                    def retry_60(e):
                        nav_state["timeout"] = 60
                        _navigate(path)

                    folder_col.controls.append(
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Row(
                                        [
                                            ft.Icon(ft.Icons.WARNING_AMBER_OUTLINED, color=C_WARNING, size=16),
                                            ft.Text(
                                                "Listing timed out — this folder has too many objects.",
                                                color=C_WARNING, size=12, weight=ft.FontWeight.W_600,
                                            ),
                                        ],
                                        spacing=8,
                                    ),
                                    ft.Text(
                                        "No worries! You can still copy objects here and mount this folder as a volume.\n"
                                        "To browse subfolders, retry with a longer timeout or enter the path manually.",
                                        color=C_TEXT_DIM, size=11,
                                    ),
                                    ft.Row(
                                        [
                                            btn_primary("↺ Retry (60s)", on_click=retry_60),
                                            btn_secondary("✎ Enter path manually", on_click=show_manual_input),
                                        ],
                                        spacing=8,
                                    ),
                                    ft.Row(
                                        [manual_tf, confirm_btn, confirmed_badge],
                                        spacing=8,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                ],
                                spacing=8,
                                tight=True,
                            ),
                            bgcolor=f"{C_WARNING}11",
                            border=ft.border.all(1, f"{C_WARNING}44"),
                            border_radius=8,
                            padding=12,
                        )
                    )
                    page.update()

                ui_call(page, _timeout_ui)
            except Exception as ex:
                def _err():
                    loading_row.visible = False
                    error_text.value    = f"Error: {ex}"
                    error_text.visible  = True
                    page.update()
                ui_call(page, _err)

        threading.Thread(target=_load, daemon=True).start()

    def _do_mkdir(e=None):
        """
        Crea una carpeta VIRTUAL: solo actualiza el path de destino en la UI.
        No llama a rclone — S3 creará el prefijo automáticamente al copiar.
        """
        name = (new_folder_tf.value or "").strip()
        if not name:
            mkdir_status.value   = "⚠ Enter a folder name first."
            mkdir_status.color   = C_WARNING
            mkdir_status.visible = True
            page.update()
            return

        if "/" in name or "\\" in name:
            mkdir_status.value   = "⚠ Folder name cannot contain slashes."
            mkdir_status.color   = C_WARNING
            mkdir_status.visible = True
            page.update()
            return

        base     = nav_state["current_path"]
        new_path = f"{base}/{name}" if base else name

        new_folder_tf.value = ""

        # Actualizar estado y breadcrumb sin llamar a rclone
        nav_state["current_path"] = new_path
        on_select(new_path)
        _rebuild_breadcrumb()

        # Mostrar la carpeta como "nueva/vacía" en la lista
        folder_col.controls.clear()
        folder_col.controls.append(
            ft.Text(
                "(new folder — will be created on copy)",
                size=11, color=C_TEXT_DIM, italic=True,
            )
        )

        #mkdir_status.value   = f"✓ Destination set to: {perfil_rclone}:{new_path}"
        #mkdir_status.color   = C_ACCENT
        #mkdir_status.visible = True

        page.update()

    mkdir_btn.on_click      = _do_mkdir
    new_folder_tf.on_submit = _do_mkdir  # Enter también funciona


    # ── Widget ────────────────────────────────────────────────────────────
    browser_widget = ft.Column(
        [
            ft.Container(
                content=breadcrumb_row,
                bgcolor=C_SURFACE2,
                border=ft.border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.padding.symmetric(horizontal=8, vertical=4),
            ),
            loading_row,
            error_text,
            ft.Container(
                content=ft.Column(
                    [folder_col],
                    scroll=ft.ScrollMode.AUTO,
                    spacing=0,
                ),
                bgcolor=C_SURFACE,
                border=ft.border.all(1, C_BORDER),
                border_radius=6,
                height=200,
                padding=ft.padding.all(8),
            ),
            # ── Fila "Create folder" ──────────────────────────────────────
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.CREATE_NEW_FOLDER_OUTLINED,
                                        color=C_TEXT_DIM, size=14),
                                ft.Text("Add subfolder to destination:",
                                        size=11, color=C_TEXT_DIM),
                            ],
                            spacing=6,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Row(
                            [new_folder_tf, mkdir_btn],
                            spacing=6,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        #mkdir_status,
                    ],
                    spacing=6,
                    tight=True,
                ),
                bgcolor=C_SURFACE2,
                border=ft.border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.padding.symmetric(horizontal=12, vertical=10),
            ),
        ],
        spacing=6,
        tight=True,
    )

    return browser_widget, lambda: _navigate("")


# ============================================================================
# COMPONENTE: NAVEGADOR DE FICHEROS LOCAL (para modo web)
#
# Lee el filesystem del servidor donde corre BIFROST.
# Usa os.scandir — no necesita rclone.
# Soporta select_mode = "folder" | "file" | "both"
# ============================================================================

def build_local_fs_browser(
    page: ft.Page,
    on_select: Callable[[str], None],
    select_mode: str = "folder",   # "folder" | "file" | "both"
    start_path: str | None = None,
) -> tuple[ft.Column, Callable]:
    """
    Navegador de ficheros del servidor con breadcrumb.

    Returns:
        (widget, refresh_fn) — llama a refresh_fn() después de añadir
        el widget al árbol para arrancar la carga inicial.
    """

    root_path = pathlib.Path(start_path or pathlib.Path.home())
    nav_state = {"current": root_path}

    breadcrumb_row = ft.Row(spacing=2, wrap=True,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER)
    entries_col    = ft.Column(spacing=4, tight=True)
    loading_row    = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8, visible=False,
    )
    error_text = ft.Text("", color=C_ERROR, size=11, visible=False)

    def _rebuild_breadcrumb(path: pathlib.Path):
        breadcrumb_row.controls.clear()
        parts = path.parts
        accumulated = pathlib.Path(parts[0])
        breadcrumb_row.controls.append(
            ft.TextButton(
                content=ft.Text("/"),
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.padding.symmetric(horizontal=6, vertical=2),
                ),
                on_click=lambda e, p=accumulated: _navigate(p),
            )
        )
        for i, part in enumerate(parts[1:], start=1):
            accumulated = accumulated / part
            acc_snap = accumulated
            is_last  = (i == len(parts) - 1)
            breadcrumb_row.controls.append(ft.Text("/", size=12, color=C_TEXT_DIM))
            if is_last:
                breadcrumb_row.controls.append(
                    ft.Text(part, size=12, color=C_TEXT, weight=ft.FontWeight.W_600)
                )
            else:
                breadcrumb_row.controls.append(
                    ft.TextButton(
                        content=ft.Text(part),
                        style=ft.ButtonStyle(
                            color=C_PRIMARY,
                            padding=ft.padding.symmetric(horizontal=6, vertical=2),
                        ),
                        on_click=lambda e, p=acc_snap: _navigate(p),
                    )
                )

    def _navigate(path: pathlib.Path):
        nav_state["current"] = path
        # Auto-select the current folder when browsing in folder/both mode,
        # so the user can just navigate and press Confirm without needing the ✓ icon.
        if select_mode in ("folder", "both"):
            on_select(str(path))
        loading_row.visible  = True
        error_text.visible   = False
        entries_col.controls.clear()
        _rebuild_breadcrumb(path)
        page.update()

        def _load():
            try:
                raw = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
            except PermissionError:
                def _perm():
                    loading_row.visible = False
                    error_text.value    = f"Permission denied: {path}"
                    error_text.visible  = True
                    page.update()
                ui_call(page, _perm)
                return

            dirs  = [p for p in raw if p.is_dir()  and not p.name.startswith(".")]
            files = [p for p in raw if p.is_file() and not p.name.startswith(".")]

            def _show():
                loading_row.visible = False
                entries_col.controls.clear()

                # Botón ".." para subir (si no estamos en root_path)
                if path != root_path and path.parent >= root_path:
                    parent_snap = path.parent
                    entries_col.controls.append(
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.ARROW_UPWARD, color=C_TEXT_DIM, size=15),
                                    ft.Text("..", size=12, color=C_TEXT_DIM, expand=True),
                                ],
                                spacing=8,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            bgcolor=C_BG,
                            border=ft.border.all(1, C_BORDER),
                            border_radius=6,
                            padding=ft.padding.symmetric(horizontal=12, vertical=6),
                            on_click=lambda e, p=parent_snap: _navigate(p),
                            ink=True,
                        )
                    )

                if not dirs and not files:
                    entries_col.controls.append(
                        ft.Text("(empty)", size=11, color=C_TEXT_DIM, italic=True)
                    )

                for entry in dirs + files:
                    is_dir   = entry.is_dir()
                    ep_snap  = entry

                    # ¿Es seleccionable como destino final?
                    selectable = (
                        (select_mode == "folder" and is_dir) or
                        (select_mode == "file"   and not is_dir) or
                        (select_mode == "both")
                    )
                    # Carpetas siempre navegables aunque no sean el modo seleccionado
                    navigable = is_dir

                    def _make_click(ep=ep_snap, nav=navigable, sel=selectable):
                        def _click(e):
                            if nav:
                                _navigate(ep)
                            if sel and not nav:
                                on_select(str(ep))
                        return _click

                    # Botón "Select" solo si es seleccionable Y no vamos a navegar
                    select_icon = ft.IconButton(
                        icon=ft.Icons.CHECK_CIRCLE_OUTLINE,
                        icon_color=C_ACCENT,
                        icon_size=16,
                        tooltip="Select this folder" if is_dir else "Select this file",
                        on_click=lambda e, ep=ep_snap: on_select(str(ep)),
                        visible=selectable,
                    ) if selectable else ft.Container(width=24)

                    row = ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(
                                    ft.Icons.FOLDER_OUTLINED if is_dir
                                    else ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                    color=C_WARNING if is_dir else C_TEXT_DIM,
                                    size=16,
                                ),
                                ft.Text(
                                    entry.name,
                                    size=12,
                                    color=C_TEXT if is_dir else C_TEXT_DIM,
                                    expand=True,
                                ),
                                select_icon,
                                ft.Icon(
                                    ft.Icons.CHEVRON_RIGHT,
                                    color=C_TEXT_DIM, size=14,
                                ) if is_dir else ft.Container(width=14),
                            ],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        bgcolor=C_SURFACE2 if is_dir else C_BG,
                        border=ft.border.all(1, C_BORDER),
                        border_radius=6,
                        padding=ft.padding.symmetric(horizontal=12, vertical=8),
                        on_click=_make_click() if navigable else (
                            (lambda e, ep=ep_snap: on_select(str(ep))) if selectable else None
                        ),
                        ink=navigable or selectable,
                    )
                    entries_col.controls.append(row)

                page.update()

            ui_call(page, _show)

        safe_thread(page, _load).start()

    browser_widget = ft.Column(
        [
            ft.Container(
                content=breadcrumb_row,
                bgcolor=C_SURFACE2,
                border=ft.border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.padding.symmetric(horizontal=8, vertical=4),
            ),
            loading_row,
            error_text,
            ft.Container(
                content=ft.Column(
                    [entries_col],
                    scroll=ft.ScrollMode.AUTO,
                    spacing=0,
                ),
                bgcolor=C_SURFACE,
                border=ft.border.all(1, C_BORDER),
                border_radius=6,
                height=260,
                padding=ft.padding.all(8),
            ),
        ],
        spacing=6,
        tight=True,
    )

    return browser_widget, lambda: _navigate(root_path), _navigate


def show_local_fs_modal(
    page: ft.Page,
    on_select: Callable[[str], None],
    select_mode: str = "folder",
) -> None:
    """
    Abre un modal con el navegador de ficheros local.
    Al seleccionar, cierra el modal y llama on_select(path).
    """
    selected_label = ft.Text(
        "No selection yet", size=11, color=C_TEXT_DIM, italic=True
    )

    def _on_pick(path: str):
        selected_label.value  = path
        selected_label.color  = C_ACCENT
        selected_label.italic = False
        page.update()

    browser_widget, refresh_fn, navigate_to = build_local_fs_browser(
        page,
        on_select=_on_pick,
        select_mode=select_mode,
    )

    def confirm(e):
        path = selected_label.value
        if path and path != "No selection yet":
            page.pop_dialog()
            on_select(path)
        else:
            selected_label.value  = "⚠ Select something first"
            selected_label.color  = C_WARNING
            selected_label.italic = True
            page.update()

    def cancel(e):
        page.pop_dialog()

    title_text = {
        "folder": "Select Folder",
        "file":   "Select File",
        "both":   "Select File or Folder",
    }.get(select_mode, "Browse")

    # ── Shortcuts ──────────────────────────────────────────────────
    _shortcut_defs = [
        ("~ Home",   ft.Icons.HOME_OUTLINED,          pathlib.Path.home()),
        ("/data",    ft.Icons.STORAGE_OUTLINED,        pathlib.Path("/data")),
        ("/scratch", ft.Icons.FOLDER_SPECIAL_OUTLINED, pathlib.Path("/scratch")),
    ]

    def _make_shortcut(label: str, icon, dest: pathlib.Path) -> ft.TextButton:
        return ft.TextButton(
            content=ft.Row(
                [
                    ft.Icon(icon, size=13, color=C_PRIMARY),
                    ft.Text(label, size=11, color=C_PRIMARY),
                ],
                spacing=4,
                tight=True,
            ),
            style=ft.ButtonStyle(
                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                bgcolor={ft.ControlState.HOVERED: f"{C_PRIMARY}22"},
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=lambda e, p=dest: navigate_to(p),
        )

    shortcuts_row = ft.Row(
        [_make_shortcut(lbl, ico, dest) for lbl, ico, dest in _shortcut_defs],
        spacing=4,
        wrap=True,
    )

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text(title_text, color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
        content=ft.Column(
            [
                shortcuts_row,
                browser_widget,
                ft.Container(height=8),
                ft.Row(
                    [
                        ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=14),
                        selected_label,
                    ],
                    spacing=6,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=6,
            tight=True,
            width=520,
        ),
        actions=[
            btn_secondary("Cancel",  on_click=cancel),
            btn_primary("Confirm selection", on_click=confirm),
        ],
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    #page.overlay.append(dlg)
    #dlg.open = True
    page.show_dialog(dlg)
    page.update()

    # Arrancar carga inicial después de que el modal esté en el árbol
    threading.Timer(0.1, refresh_fn).start()


# ============================================================================
# VISTA: INTERFAZ PRINCIPAL DE COPIA
# ============================================================================

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
) -> ft.Control:
    usuario_actual = credenciales_ldap["usuario"]

    num_cores = backend.obtener_num_cpus()
    _, rclone_config_path, _ = backend.get_rclone_paths(perfil_rclone)

    # ── Badge de expiración de credenciales ───────────────────────────────
    token_actual = backend.get_rclone_session_token(perfil_rclone)
    tiempo_expira = backend.get_expiration_from_session_token(token_actual) if token_actual else None

    if tiempo_expira:
        dias = tiempo_expira.days
        color_badge = C_ERROR if dias < 1 else C_WARNING if dias <= STS_RENEWAL_THRESHOLD_DAYS else C_ACCENT
        expiry_text = f"🔑 Credentials expire in {dias}d {tiempo_expira.seconds // 3600}h"
    else:
        color_badge = C_TEXT_DIM
        expiry_text = "🔑 Credentials: unknown expiry"

    expiry_badge = ft.Container(
        content=ft.Text(expiry_text, size=11, color=color_badge, weight=ft.FontWeight.W_600),
        bgcolor=f"{color_badge}22",
        border=ft.border.all(1, f"{color_badge}55"),
        border_radius=20,
        padding=ft.padding.symmetric(horizontal=10, vertical=4),
    )

    def show_renew_dialog(e):
        days_tf = ft.TextField(
            value=str(STS_AUTO_RENEWAL_DAYS),
            bgcolor=C_SURFACE2,
            border_color=C_BORDER,
            focused_border_color=C_PRIMARY,
            color=C_TEXT,
            border_radius=6,
            content_padding=ft.padding.symmetric(horizontal=12, vertical=10),
            text_size=13,
            width=80,
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        err = ft.Text("", color=C_ERROR, size=12, visible=False)

        def do_renew(ev=None):
            try:
                dias_int = int(days_tf.value or "0")
                if dias_int < 1 or dias_int > 30:
                    err.value   = "Enter a value between 1 and 30 days."
                    err.visible = True
                    page.update()
                    return
            except ValueError:
                err.value   = "Invalid number."
                err.visible = True
                page.update()
                return

            page.pop_dialog()

            show_screen(_build_credentials_content(
                page,
                perfil_rclone=perfil_rclone,
                endpoint=endpoint,
                credenciales_ldap=credenciales_ldap,
                on_continue=on_renew_complete,
                extra_config=extra_config,
                duracion_dias=dias_int,
            ))

        def cancel(ev):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Row(
                [
                    ft.Icon(ft.Icons.AUTORENEW, color=C_PRIMARY, size=20),
                    ft.Text("Renew S3 Credentials", color=C_TEXT, size=15,
                            weight=ft.FontWeight.W_600),
                ],
                spacing=8,
            ),
            content=ft.Column(
                [
                    ft.Text(f"User: {credenciales_ldap['usuario']}", color=C_TEXT_DIM, size=12),
                    ft.Text(f"Profile: {perfil_rclone}", color=C_TEXT_DIM, size=12),
                    ft.Container(height=12),
                    ft.Row(
                        [
                            ft.Text("Renew for:", size=13, color=C_TEXT),
                            days_tf,
                            ft.Text("days", size=13, color=C_TEXT),
                        ],
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    err,
                ],
                spacing=8,
                tight=True,
                width=320,
            ),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                btn_primary("🔄 Renew", on_click=do_renew),
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        #page.overlay.append(dlg)
        #dlg.open = True
        page.show_dialog(dlg)
        page.update()

    renew_btn = btn_secondary("🔑 Renew credentials", on_click=show_renew_dialog)

    # ── Origen ────────────────────────────────────────────────────────────
    origen_tf, origen_col = styled_field(
        "Source path" + (" (server path)" if IS_WEB else " (local path or rclone remote)"),
        hint="/path/to/data" if IS_WEB else "/local/path  or  profile:/path",
    )
    flags_tf, flags_col = styled_field(
        "Additional rclone flags (advanced)",
        value=f"--transfers={num_cores} --checkers={num_cores} --s3-no-check-bucket",
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

    # ── Log ────────────────────────────────────────────────────────────────
    log_list = ft.ListView(
        expand=True,
        auto_scroll=True,
        spacing=0,
        padding=ft.padding.all(12),
    )

    _log_lock = threading.Lock()

    log_container = ft.Container(
        content=log_list,
        bgcolor=C_BG,
        border=ft.border.all(1, C_BORDER),
        border_radius=6,
        height=280,
    )

    def log(msg: str):
        """Append *msg* to the visible log list in this UI page."""
        lines_to_add = []
        for line in msg.splitlines(keepends=True):
            if line.strip():
                color = (
                    C_ACCENT  if line.startswith("✅") else
                    C_ERROR   if line.startswith("❌") else
                    C_WARNING if line.startswith("⚠️") else
                    C_PRIMARY if line.startswith("🔍") or line.startswith("🧾") else
                    C_TEXT
                )
                lines_to_add.append(
                    ft.Text(line.rstrip("\n"),
                            size=11, color=color,
                            font_family=FONT_MONO, selectable=True)
                )

        def _add():
            with _log_lock:
                log_list.controls.extend(lines_to_add)
                page.update()

        ui_call(page, _add)

    # ── Session-level log dispatcher (web only) ───────────────────────────
    # _dispatch_log accumulates every line in the session buffer AND forwards
    # to every registered UI callback (current page + any future reconnect).
    def _dispatch_log(msg: str) -> None:
        if IS_WEB and web_session is not None:
            web_session["copy_log_buffer"].append(msg)
            dead = []
            for cb in list(web_session["copy_log_callbacks"]):
                try:
                    cb(msg)
                except Exception:
                    dead.append(cb)
            for cb in dead:
                try:
                    web_session["copy_log_callbacks"].remove(cb)
                except ValueError:
                    pass
        else:
            log(msg)

    # Register this page's log() as a callback so live output reaches the UI
    if IS_WEB and web_session is not None:
        if log not in web_session["copy_log_callbacks"]:
            web_session["copy_log_callbacks"].append(log)


    # ── Estado del proceso activo ─────────────────────────────────────────
    # _active_proceso guarda el Popen de rclone en curso (copy o check).
    # En modo web se reutiliza el dict de la sesión para que sobreviva a
    # un cierre/reapertura de pestaña (el hilo background ya tiene ref al mismo objeto).
    if IS_WEB and web_session is not None:
        _active_proceso: dict = web_session.setdefault("copy_proceso", {"proc": None})
    else:
        _active_proceso: dict = {"proc": None}

    # ── Botones ────────────────────────────────────────────────────────────
    copy_btn   = btn_primary("▶  Copy data")
    check_btn  = btn_primary("✓  Check data", disabled=False)
    cancel_btn = ft.ElevatedButton(
        content=ft.Row(
            [ft.Icon(ft.Icons.STOP_CIRCLE_OUTLINED, size=16), ft.Text("Cancel")],
            spacing=6, tight=True,
        ),
        visible=False,
        style=ft.ButtonStyle(
            bgcolor={
                ft.ControlState.DEFAULT: C_ERROR,
                ft.ControlState.HOVERED: "#FF6B6B",
            },
            color={ft.ControlState.DEFAULT: "#0D1117"},
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.padding.symmetric(horizontal=16, vertical=12),
        ),
    )
    mount_btn = btn_secondary("⊞  Mount destination")
    mount_btn.visible = not IS_WEB
    save_btn  = btn_secondary("↓  Save log")
    close_btn = btn_secondary("✕  Close")

    def enable_btn(btn):
        def _do():
            btn.disabled = False
            btn.update()
        ui_call(page, _do)

    def _set_running(running: bool):
        """Show/hide cancel button and toggle copy/check buttons."""
        def _do():
            cancel_btn.visible  = running
            copy_btn.disabled   = running
            check_btn.disabled  = running
            page.update()
        ui_call(page, _do)

    def do_cancel(e):
        proc = _active_proceso["proc"]
        if proc and proc.poll() is None:
            proc.terminate()
            _dispatch_log("\n⚠️  Transfer cancelled by user.\n")
            if IS_WEB and web_session is not None:
                web_session["copy_status"] = "error"
        else:
            _dispatch_log("\n⚠️  No active process to cancel.\n")

    cancel_btn.on_click = do_cancel

    # ── FilePicker (solo desktop) ──────────────────────────────────────────
    if not IS_WEB:
        file_picker   = ft.FilePicker()
        folder_picker = ft.FilePicker()
        save_picker   = ft.FilePicker()
        page.services.extend([file_picker, folder_picker, save_picker])

        async def _pick_file(e):
            result = await file_picker.pick_files()
            if result:
                ruta = backend.traducir_ruta_a_remote(result[0].path, mounts_activos)
                origen_tf.value = ruta
                page.update()

        async def _pick_folder(e):
            result = await folder_picker.get_directory_path()
            if result:
                ruta = backend.traducir_ruta_a_remote(result, mounts_activos)
                origen_tf.value = ruta
                page.update()

        async def _save_log_picker(file_name: str):
            result = await save_picker.save_file(file_name=file_name)
            if result and result.path:
                contenido = "\n".join(
                    c.value for c in log_list.controls
                    if isinstance(c, ft.Text) and c.value
                )
                try:
                    with open(result.path, "w", encoding="utf-8") as f:
                        f.write(contenido)
                    show_dialog(page, "Log saved", f"Saved to:\n{result.path}", C_ACCENT)
                except Exception as ex:
                    show_dialog(page, "Error", str(ex), C_ERROR)

        pick_file_btn   = btn_secondary("📄 File",
                            on_click=lambda e: page.run_task(_pick_file, e))
        pick_folder_btn = btn_secondary("📁 Folder",
                            on_click=lambda e: page.run_task(_pick_folder, e))

        pick_row = ft.Row([pick_file_btn, pick_folder_btn], spacing=8)
    else:
        # Modo WEB: browsers propios que leen el filesystem del servidor
        def _open_folder_browser(e):
            def _picked(path: str):
                origen_tf.value = path
                page.update()
            show_local_fs_modal(page, on_select=_picked, select_mode="folder")

        def _open_file_browser(e):
            def _picked(path: str):
                origen_tf.value = path
                page.update()
            show_local_fs_modal(page, on_select=_picked, select_mode="file")

        pick_row    = ft.Row(
            [
                btn_secondary("📁 Folder", on_click=_open_folder_browser),
                btn_secondary("📄 File",   on_click=_open_file_browser),
            ],
            spacing=8,
        )
        save_picker = None

    # ── Destino: navegador rclone ──────────────────────────────────────────
    _dest_path = {"value": ""}

    # FIX: ruta_label se actualiza solo via page.update(), nunca via .update()
    # individual, para evitar el error "Control must be added to the page first"
    ruta_label = ft.Text(
        f"→ {perfil_rclone}: (root — select a folder above)",
        size=12,
        color=C_WARNING,
        font_family=FONT_MONO,
    )

    def on_browser_select(path: str):
        _dest_path["value"] = path
        if path:
            display = f"{perfil_rclone}:{path}"
            ruta_label.value = f"→ All files from source will be copied into: {display}"
            ruta_label.color = C_ACCENT
        else:
            ruta_label.value = f"→ {perfil_rclone}: (root — select a folder above)"
            ruta_label.color = C_WARNING
        # NO llamamos ruta_label.update() aquí porque este callback puede
        # ejecutarse antes de que el control esté en el árbol (carga inicial).
        # page.update() lo llama _navigate() justo después de on_select().

    # build_rclone_browser devuelve (widget, refresh_fn)
    # refresh_fn se llama con Timer después de show_screen() para la carga inicial
    dest_browser, dest_browser_refresh = build_rclone_browser(
        page, perfil_rclone, on_select=on_browser_select
    )
    dest_browser_col = ft.Column(
        [field_label(f"Destination path (bucket in {perfil_rclone})"), dest_browser],
        spacing=4,
        tight=True,
    )

    # ── Copiar ─────────────────────────────────────────────────────────────
    def do_copy(e):
        origen  = (origen_tf.value or "").strip()
        destino = _dest_path["value"].strip()
        if not origen or not destino:
            show_dialog(page, "Error", "Source and destination are required.", C_ERROR)
            return

        metadatos = {k: (tf.value or "").strip() for k, tf in meta_fields.items()}
        flags     = (flags_tf.value or "").strip().split()

        _set_running(True)

        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _dispatch_log(f"### Copy started at {ahora} ###\n")
        _dispatch_log("### Metadata ###\n")
        for k, v in metadatos.items():
            _dispatch_log(f"  {k}: {v}\n")
        _dispatch_log("\n")

        # Persist copy state so reconnecting sessions can see it
        if IS_WEB and web_session is not None:
            web_session["copy_status"]  = "running"
            web_session["copy_origen"]  = origen
            web_session["copy_destino"] = destino

        def _on_copy_success():
            if IS_WEB and web_session is not None:
                web_session["copy_status"] = "done"
            enable_btn(check_btn)

        def _on_copy_finish():
            _active_proceso["proc"] = None
            _set_running(False)
            if IS_WEB and web_session is not None:
                if web_session["copy_status"] == "running":
                    web_session["copy_status"] = "error"
            if IS_WEB:
                _autosave_log()

        def _run_copy():
            proc = backend.ejecutar_rclone_copy(
                origen=origen,
                destino_perfil=perfil_rclone,
                destino_path=destino,
                rclone_config_path=rclone_config_path,
                metadatos_dict=metadatos,
                flags_adicionales=flags,
                num_cores=num_cores,
                log_fn=_dispatch_log,
                on_success=_on_copy_success,
                on_finish=_on_copy_finish,
                expose_proceso=_active_proceso,
            )

        safe_thread(page, _run_copy).start()

    # ── Check ──────────────────────────────────────────────────────────────
    def do_check(e):
        origen  = (origen_tf.value or "").strip()
        destino = _dest_path["value"].strip()
        if not origen or not destino:
            show_dialog(page, "Error", "Source and destination are required.", C_ERROR)
            return

        flags = (flags_tf.value or "").strip().split()
        _set_running(True)
        _dispatch_log(f"\n🔍 Verifying: rclone check {origen} → {perfil_rclone}:/{destino}\n\n")

        def _on_check_finish():
            _active_proceso["proc"] = None
            _set_running(False)
            if IS_WEB:
                _autosave_log()

        def _run_check():
            backend.ejecutar_rclone_check(
                origen=origen,
                destino_perfil=perfil_rclone,
                destino_path=destino,
                rclone_config_path=rclone_config_path,
                flags_adicionales=flags,
                mounts_activos=mounts_activos,
                log_fn=_dispatch_log,
                on_finish=_on_check_finish,
                expose_proceso=_active_proceso,
            )

        safe_thread(page, _run_check).start()

    # ── Montar destino ─────────────────────────────────────────────────────
    def do_mount(e):
        ruta = _dest_path["value"].strip()
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
    def _log_content_from_buffer() -> str:
        """Return log text from the session buffer (web) or the visible list (desktop)."""
        if IS_WEB and web_session is not None:
            return "".join(web_session.get("copy_log_buffer", []))
        return "\n".join(
            c.value for c in log_list.controls
            if isinstance(c, ft.Text) and c.value
        )

    def _autosave_log() -> str | None:
        """
        Automatically save the log to ~/bifrost-logs/ at end of copy/check.
        Returns the saved path, or None on failure.
        Only runs in web (OOD) mode.
        """
        if not IS_WEB:
            return None
        contenido = _log_content_from_buffer()
        if not contenido.strip():
            return None
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = pathlib.Path.home() / "bifrost-logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fpath = log_dir / f"bifrost-{ts}.log"
            fpath.write_text(contenido, encoding="utf-8")
            _dispatch_log(f"\n📄 Log auto-saved to: {fpath}\n")
            return str(fpath)
        except Exception as ex:
            _dispatch_log(f"\n⚠️  Could not auto-save log: {ex}\n")
            return None

    def do_save_log(e):
        contenido = _log_content_from_buffer()
        if not contenido.strip():
            show_dialog(page, "Save log", "No log content to save.", C_WARNING)
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if IS_WEB:
            log_dir = pathlib.Path.home() / "bifrost-logs"
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                fpath = log_dir / f"bifrost-{ts}.log"
                fpath.write_text(contenido, encoding="utf-8")
                show_dialog(page, "Log saved", f"Saved to:\n{fpath}", C_ACCENT)
            except Exception as ex:
                show_dialog(page, "Error", str(ex), C_ERROR)
        else:
            page.run_task(_save_log_picker, f"bifrost-{ts}.log")

    # ── Cierre ─────────────────────────────────────────────────────────────
    def _do_close_cleanup():
        log("\n🧹 Unmounting mount points...\n")
        ruta_dest = _dest_path["value"].strip()
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
    # cancel_btn.on_click already wired above

    # ── Layout ────────────────────────────────────────────────────────────
    content = ft.Column(
        [
            build_header(f"Copy & Verify — {perfil_rclone}"),
            ft.Container(
                content=ft.Row(
                    [expiry_badge, ft.Container(expand=True), renew_btn],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
                margin=ft.margin.only(bottom=4),
            ),
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
                                    dest_browser_col,
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
                            [copy_btn, check_btn, cancel_btn, mount_btn, save_btn, close_btn],
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
                ),
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    # FIX: lanzar la carga inicial del browser con un pequeño delay para que
    # show_screen() haya procesado el widget y page.update() se haya ejecutado
    # antes de que _navigate("") intente hacer page.update() sobre controles
    # ya registrados en el árbol de Flet.
    threading.Timer(0.1, dest_browser_refresh).start()

    # ── Replay historical log + show reconnect banner (web session restore) ─
    if IS_WEB and web_session is not None:
        buffer = list(web_session.get("copy_log_buffer", []))
        status = web_session.get("copy_status", "idle")
        if buffer:
            def _replay():
                import time
                time.sleep(0.2)   # wait for page tree to settle
                banner = (
                    f"\n{'─'*60}\n"
                    f"↩  Reconnected to existing session\n"
                    f"   Status: {status.upper()}\n"
                    f"   Origin:  {web_session.get('copy_origen', '')}\n"
                    f"   Dest:    {web_session.get('copy_destino', '')}\n"
                    f"{'─'*60}\n\n"
                )
                log(banner)
                for msg in buffer:
                    log(msg)
                if status == "running":
                    log("\n⚠️  Copy is still running — new output will appear below\n")
                    _set_running(True)  # restore cancel button
                elif status == "done":
                    log("\n✅  Copy finished while you were away\n")
                elif status == "error":
                    log("\n❌  Copy ended with errors while you were away\n")
                # Pre-fill origin/dest fields from session
                def _prefill():
                    if web_session.get("copy_origen"):
                        origen_tf.value = web_session["copy_origen"]
                    page.update()
                ui_call(page, _prefill)
            threading.Thread(target=_replay, daemon=True).start()

    return content


# ============================================================================
# VERIFICACIÓN DE RCLONE EN DESKTOP
# ============================================================================

def check_rclone_installation_flet(page: ft.Page) -> None:
    if not backend.detect_rclone_installed():
        sistema = sys.platform
        if sistema == "darwin":
            show_dialog(
                page,
                "Rclone not found",
                "Download it with macos-third-party-assets-downloader.sh.\n",
                C_ERROR,
            )
            sys.exit(1)
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

    import atexit
    
    def _cleanup_on_exit():
        print("[atexit] Cleaning up...")
        backend.desmontar_todos_los_mounts_s3()
        mounts = state.get("mounts_activos", [])
        if mounts and IS_LINUX_CLUSTER:
            usuario = (state.get("credenciales_smb") or {}).get("usuario") or getpass.getuser()
            try:
                backend.desmontar_todos_los_shares(usuario)
            except Exception as e:
                print(f"[atexit] Error unmounting shares: {e}")

    atexit.register(_cleanup_on_exit)


    # def on_window_close(e):
    #     print(f"[debug] on_window_close called, e={e}, e.data={e.data if hasattr(e, 'data') else 'no data'}")
    #     _cleanup_on_exit()
    #    page.window.close()

    async def on_window_event(e: ft.WindowEvent):
        if e.type == ft.WindowEventType.CLOSE:
            print("[close] Starting cleanup...")
            _cleanup_on_exit()
            print("[close] Cleanup done, destroying window...")
            await page.window.destroy()
            print("[close] Window destroyed")
            os._exit(0)


    #page.window.on_close = on_window_close
    page.window.on_event = on_window_event
    page.window.prevent_close = True
    

    ALLOW_CUSTOM_USER = True # "--customuser" in sys.argv or "-c" in sys.argv

    body = ft.Container(expand=True, bgcolor=C_BG)
    page.scroll = ft.ScrollMode.AUTO
    page.add(body)
    page.update()

    # --- WebSocket keep-alive -----------------------------------------------
    # OOD's nginx proxy closes idle WebSocket connections (default ~60 s).
    # Sending a Flet protocol update every 20 s resets the idle timer and
    # prevents the Flutter client from having to reconnect (which causes the
    # "working…" flash the user sees).
    if IS_WEB:
        async def _ws_heartbeat():
            import asyncio as _aio
            while True:
                await _aio.sleep(20)
                try:
                    page.update()
                except Exception:
                    return
        page.run_task(_ws_heartbeat)
    # ------------------------------------------------------------------------

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
            if IS_LINUX_CLUSTER and state["mounts_activos"]:
                usuario = (
                    (state["credenciales_smb"] or {}).get("usuario")
                    or getpass.getuser()
                )
                safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()

        page.on_close = on_close

    def go_login():
        # If a previous session exists for the last known user, pre-fill the
        # username and use a special on_success that skips update/shares/minio.
        if IS_WEB:
            last_user = _LAST_WEB_USER[0]
            session   = _ws_load(last_user) if last_user else None
            if session:
                print(f"[session] Previous session found for {last_user!r} — showing restore-login")
                show_screen(_build_login_content(
                    page,
                    on_success=lambda creds: on_login_success_with_restore(creds, session),
                    allow_custom_user=ALLOW_CUSTOM_USER,
                    prefill_user=last_user,
                ))
                return
        show_screen(_build_login_content(page, on_success=on_login_success,
                                          allow_custom_user=ALLOW_CUSTOM_USER))

    def on_login_success_with_restore(creds: dict, session: dict) -> None:
        """
        Called after password re-auth when restoring a previous web session.
        Restores navigation state and jumps straight to copy view,
        skipping update / shares / minio selection entirely.
        In OOD web mode there are no CIFS mounts to restore.
        """
        usuario = creds["usuario"]
        # If the user typed a different username, discard the old session
        # and run the normal fresh flow instead.
        if usuario != _LAST_WEB_USER[0]:
            print(f"[session] Username changed ({_LAST_WEB_USER[0]!r} → {usuario!r}), discarding old session")
            _ws_clear(_LAST_WEB_USER[0] or "")
            on_login_success(creds)
            return

        print(f"[session] Restoring session for {usuario!r}")
        state["credenciales_ldap"] = creds
        state["servidor_minio"]    = session["servidor_minio"]
        state["perfil_rclone"]     = session["perfil_rclone"]
        state["endpoint"]          = session["endpoint"]
        # mounts_activos stays [] — OOD web mode has no CIFS shares

        # Jump straight to credentials-check → copy view
        _go_credentials_or_copy()

    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds
        if IS_LINUX_CLUSTER:
            show_loading("Fetching LDAP groups...")

            def _load_groups():
                grupos = backend.get_ldap_groups(creds["usuario"])
                state["grupos_ldap"] = grupos

                if "its" in grupos:
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
        else:
            go_minio()

    def _ask_admin_creds():
        admin_user = "admin_" + state["credenciales_ldap"]["usuario"]
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
            page.pop_dialog()
            _after_privileges()

        def cancel(e):
            state["usar_privilegios"]   = False
            state["credenciales_admin"] = None
            page.pop_dialog()
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
        #page.overlay.append(dlg)
        #dlg.open = True
        #Migración a flet 0.82.2 
        page.show_dialog(dlg)
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

        if IS_WEB and state.get("credenciales_ldap"):
            _ws_save(state["credenciales_ldap"]["usuario"], state)

        _go_credentials_or_copy()

    def _go_credentials_or_copy():
        from datetime import timedelta

        perfil  = state["perfil_rclone"]
        token   = backend.get_rclone_session_token(perfil)
        usuario_actual = state["credenciales_ldap"]["usuario"]

        needs_renewal = True
        if token:
            usuario_token = backend.get_usuario_from_session_token(token)
            tiempo = backend.get_expiration_from_session_token(token)
            if (
                usuario_token == usuario_actual
                and tiempo
                and tiempo > timedelta(days=STS_RENEWAL_THRESHOLD_DAYS)
            ):
                needs_renewal = False
                print(
                    f"[credentials] Token valid for {tiempo} "
                    f"(> {STS_RENEWAL_THRESHOLD_DAYS} days) and belongs to {usuario_actual} → skipping renewal"
                )
            else:
                print(
                    f"[credentials] Renewal needed — token user: {usuario_token!r}, "
                    f"login user: {usuario_actual!r}, expiry: {tiempo}"
                )

        if needs_renewal:
            servidor     = state["servidor_minio"]
            extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")
            show_screen(_build_credentials_content(
                page,
                perfil_rclone=perfil,
                endpoint=state["endpoint"],
                credenciales_ldap=state["credenciales_ldap"],
                on_continue=go_copy,
                extra_config=extra_config,
            ))
        else:
            go_copy()

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
        ))

    def do_close():
        if IS_WEB:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario")
            if usuario:
                _ws_clear(usuario)
        if IS_LINUX_CLUSTER and state["mounts_activos"]:
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
# WEB VERSION IN OOD
# ============================================================================
if IS_WEB:
    from flet.fastapi import FletApp, app_manager
    from fastapi import FastAPI, WebSocket
    import asyncio

    WEBSOCKET_ENDPOINT = os.environ.get("FLET_WEBSOCKET_HANDLER_ENDPOINT")
    WEBPATH = os.environ.get("WEBPATH")
    SECRET_TOKEN = os.environ.get("password")

    app = FastAPI()
    flet_asgi_app  = ft.app(main,export_asgi_app=True)
    app.mount(WEBPATH, flet_asgi_app)

    @app.websocket(WEBSOCKET_ENDPOINT)
    async def flet_app(websocket: WebSocket):
        if not DEV_WEB:
            token = websocket.cookies.get("bifrost_auth_token")

            if token != SECRET_TOKEN:
                await websocket.close(code=1008)
                return

        await FletApp(
            loop=asyncio.get_running_loop(),
            executor=app_manager.executor,
            main=main,
            before_main=None,
        ).handle(websocket)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    ft.run(main)
