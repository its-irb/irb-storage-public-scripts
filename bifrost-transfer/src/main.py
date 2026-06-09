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
  - Thread-safety: toda modificación de UI desde hilos usa backend.ui_call(page, fn)
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
  - backend.safe_thread: todos los hilos capturan excepciones y las muestran en diálogo
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
from datetime import datetime, timedelta
from typing import Callable

import flet as ft

# # Dev: añadir shared/ al path si no está ya en él
# _shared = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
# if os.path.isdir(_shared):
#     sys.path.insert(0, os.path.abspath(_shared))

# import backend

from bifrost_backend import backend
from bifrost_frontend.frontend import *
from config import APP_INFO

# ============================================================================
# MODO DE EJECUCIÓN
# ============================================================================



# Modo web: producción (BIFROST_CLUSTER=1), Flet web runtime, o dev local (--web)
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")

# Umbral (en días) por debajo del cual se renuevan las credenciales STS automáticamente
STS_RENEWAL_THRESHOLD_DAYS = 3
# Duración (en días) de las credenciales STS renovadas automáticamente
STS_AUTO_RENEWAL_DAYS = 7

from meta_fields import FieldType, TAG_PROFILES, build_meta_fields
# ============================================================================
# PARA EVITAR PROBLEMAS DE CODIFICACIÓN EN CONSOLA (ESPECIALMENTE EN WINDOWS)
# ============================================================================
try:
    if sys.stdout and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    if sys.stderr and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
except Exception:
    pass





def divider() -> ft.Divider:
    return ft.Divider(height=1, color=C_BORDER)


# ============================================================================
# SESSION PERSISTENCE (web mode — in-memory, TTL = Hypercorn process lifetime)
# ============================================================================
#
# _WEB_SESSIONS[username] holds every piece of navigation state that can be
# restored without the user's password:
#   - servidor_minio, perfil_rclone, endpoint, extra_config
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
        "copy_tag_profile":   existing.get("copy_tag_profile", list(TAG_PROFILES.keys())[0]),
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
    session = _WEB_SESSIONS.get(usuario, {})
    # Clear callbacks first so they don't fire on a dead page object after logout.
    session.get("copy_log_callbacks", []).clear()
    # Cancel any pending throttle timer so it doesn't fire on a dead session.
    t = session.get("_dispatch_timer")
    if t:
        t.cancel()
    _WEB_SESSIONS.pop(usuario, None)
    if _LAST_WEB_USER[0] == usuario:
        _LAST_WEB_USER[0] = None
    print(f"[session] Cleared session for {usuario!r}")






# ============================================================================
# DIÁLOGOS GENÉRICOS
# ============================================================================


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
            ok, motivo = backend.validar_credenciales_ldap(creds)
            if ok:
                backend.ui_call(page, lambda: on_success(creds))
            else:
                msg = (
                    "⚠️ Cannot reach the IRB network. Are you connected to the VPN?"
                    if motivo == "vpn"
                    else "Invalid credentials. Please try again."
                )
                def _fail():
                    error_text.value   = msg
                    error_text.visible = True
                    login_btn.disabled = False
                    loading.visible    = False
                    page.update()
                backend.ui_call(page, _fail)

        backend.safe_thread(page, _auth).start()

    login_btn.on_click = do_login
    pass_tf.on_submit  = do_login
    user_tf.on_submit  = lambda e: pass_tf.focus()

    content = ft.Column(
        [
            build_header(subtitle="Authentication", IS_WEB=IS_WEB),
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
                                            border=ft.Border.all(1, f"{C_WARNING}44"),
                                            border_radius=6,
                                            padding=ft.Padding.symmetric(horizontal=10, vertical=6),
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
                        border=ft.Border.all(1, C_BORDER),
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
    grupos_ldap: list,
    credenciales_ldap: dict,
    on_back: Callable,
    on_admin_activated: Callable,
) -> ft.Control:

    recursos_cifs_dict = backend.construir_recursos_cifs_dict(shares, usuario_actual)

    if not shares:
        content = ft.Column(
            [
                build_header(subtitle=f"CIFS Shares — {usuario_actual}", IS_WEB=IS_WEB),
                ft.Container(
                    content=ft.Row(
                        [btn_secondary("← Back", on_click=lambda e: on_back())],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                    margin=ft.Margin.only(bottom=4),
                ),
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
                    padding=ft.Padding.symmetric(horizontal=24, vertical=16),
                ),
            ],
            expand=True,
            spacing=0,
        )
        return content

    _selected:         dict = {"name": None}
    _row_containers:   dict[str, ft.Container] = {}
    _status_spinners:  dict[str, ft.ProgressRing] = {}
    _status_texts:     dict[str, ft.Text] = {}
    _mounted_badges:   dict[str, ft.Container] = {}
    _mounting:         set[str] = set()

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
        if name in _mounting:
            return  # ya montando
        _mounting.add(name)
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
                _mounting.discard(name)
                spinner.visible = False
                if fallidos:
                    status_txt.value = "Error"
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

    es_admin_its = "its" in grupos_ldap

    def _show_admin_cred_dialog(e):
        user_tf, user_col = styled_field("Admin username")
        pass_tf, pass_col = styled_field("Admin password", password=True)
        err = ft.Text("", color=C_ERROR, size=12, visible=False)

        loading_indicator = ft.ProgressRing(
            width=16, height=16, stroke_width=2, color=C_PRIMARY, visible=False
        )
        confirm_btn = btn_primary("Confirm")  # on_click se asigna después

        def confirm(ev):
            admin_user = (user_tf.value or "").strip()
            pwd        = (pass_tf.value or "").strip()
            if not admin_user:
                err.value   = "Username required."
                err.visible = True
                page.update()
                return
            if not pwd:
                err.value   = "Password required."
                err.visible = True
                page.update()
                return

            confirm_btn.disabled      = True
            loading_indicator.visible = True
            err.visible               = False
            page.update()

            def _validate():
                creds = {"usuario": admin_user, "password": pwd}
                ok, motivo = backend.validar_credenciales_ldap(creds)
                if ok:
                    def _success():
                        page.pop_dialog()
                        on_admin_activated({"usuario": admin_user, "password": pwd})
                    backend.ui_call(page, _success)
                else:
                    msg = (
                        "⚠️ Cannot reach the IRB network. Are you connected to the VPN?"
                        if motivo == "vpn"
                        else "Invalid credentials."
                    )
                    def _fail():
                        err.value                 = msg
                        err.visible               = True
                        confirm_btn.disabled      = False
                        loading_indicator.visible = False
                        page.update()
                    backend.ui_call(page, _fail)

            backend.safe_thread(page, _validate).start()

        confirm_btn.on_click = confirm

        def cancel(ev):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Admin Credentials", color=C_TEXT, size=15,
                          weight=ft.FontWeight.W_600),
            content=ft.Column(
                [
                    user_col,
                    ft.Container(height=6),
                    pass_col,
                    err,
                    ft.Container(height=4),
                    ft.Row(
                        [loading_indicator],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                ],
                spacing=6,
                tight=True,
                width=300,
            ),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                confirm_btn,
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()

    admin_btn = btn_secondary("🔑 Admin credentials",
                              on_click=_show_admin_cred_dialog)
    #admin_btn.visible = es_admin_its
    admin_btn.visible = False

    back_btn_widget = btn_secondary("← Back", on_click=lambda e: on_back())

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
                content=ft.Row(
                    [c for c in [back_btn_widget] if c is not None],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                margin=ft.Margin.only(bottom=4),
            ),
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
                            [admin_btn],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=8,
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


# ============================================================================
# VISTA: SELECCIÓN DE SERVIDOR MINIO
# ============================================================================

def _build_minio_content(page: ft.Page, on_continue: Callable) -> ft.Control:
    servers  = list(backend.MINIO_SERVERS.keys())
    selected = {"current": servers[0]}

    server_cards: dict[str, ft.Container] = {}

    def _update_card_styles():
        for srv, card_c in server_cards.items():
            is_sel = srv == selected["current"]
            card_c.bgcolor = C_SURFACE2 if is_sel else C_SURFACE
            card_c.border  = ft.Border.all(2 if is_sel else 1,
                                             C_PRIMARY if is_sel else C_BORDER)
            card_c.content.controls[2].color = C_PRIMARY if is_sel else C_BORDER
        page.update()

    def on_radio_change_and_select(srv_name: str):
        rg.value = srv_name
        selected["current"] = srv_name
        _update_card_styles()

    def do_continue_direct(srv_name: str):
        on_continue({
            "servidor": srv_name,
            "perfil":   backend.MINIO_SERVERS[srv_name]["IRB"]["profile"],
            "endpoint": backend.MINIO_SERVERS[srv_name]["IRB"]["endpoint"],
        })

    def make_server_card(srv_name: str) -> ft.GestureDetector:
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
            border=ft.Border.all(2 if is_sel else 1,
                                  C_PRIMARY if is_sel else C_BORDER),
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
        )
        server_cards[srv_name] = c
        return ft.GestureDetector(
            content=c,
            on_tap=lambda e, s=srv_name: on_radio_change_and_select(s),
            on_double_tap=lambda e, s=srv_name: do_continue_direct(s),
        )

    rg = ft.RadioGroup(
        content=ft.Column([make_server_card(s) for s in servers], spacing=8),
        value=servers[0],
    )

    def on_radio_change(e):
        selected["current"] = rg.value
        _update_card_styles()

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
            build_header(subtitle="MinIO Server", IS_WEB=IS_WEB),
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
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
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
        padding=ft.Padding.all(12),
    )
    log_container = ft.Container(
        content=log_list,
        bgcolor=C_BG,
        border=ft.Border.all(1, C_BORDER),
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
        backend.ui_call(page, _add)

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
            backend.ui_call(page, _show_err)
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

        backend.ui_call(page, _finish)
        time.sleep(1.2)
        backend.ui_call(page, on_continue)

    content = ft.Column(
        [
            build_header(subtitle="S3 Credentials — Auto Renewal", IS_WEB=IS_WEB),
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
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        expand=True,
        spacing=0,
    )

    backend.safe_thread(page, _do_renew).start()
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
    initial_path: str = "",
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
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
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
                    padding=ft.Padding.symmetric(horizontal=6, vertical=2),
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
                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
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
                                border=ft.Border.all(1, C_BORDER),
                                border_radius=6,
                                padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                on_click=lambda e, p=fp_snap: _navigate(p),
                                ink=True,
                            )
                            folder_col.controls.append(row)

                    page.update()

                backend.ui_call(page, _show)

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
                        content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
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
                            border=ft.Border.all(1, f"{C_WARNING}44"),
                            border_radius=8,
                            padding=12,
                        )
                    )
                    page.update()

                backend.ui_call(page, _timeout_ui)
            except Exception as ex:
                def _err(ex_val=ex):
                    loading_row.visible = False
                    error_text.value    = f"Error: {ex_val}"
                    error_text.visible  = True
                    page.update()
                backend.ui_call(page, _err)

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
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.Padding.symmetric(horizontal=8, vertical=4),
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
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=200,
                padding=ft.Padding.all(8),
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
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            ),
        ],
        spacing=6,
        tight=True,
    )

    return browser_widget, lambda: _navigate(initial_path)


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
                    padding=ft.Padding.symmetric(horizontal=6, vertical=2),
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
                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
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
                backend.ui_call(page, _perm)
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
                            border=ft.Border.all(1, C_BORDER),
                            border_radius=6,
                            padding=ft.Padding.symmetric(horizontal=12, vertical=6),
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
                        border=ft.Border.all(1, C_BORDER),
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                        on_click=_make_click() if navigable else (
                            (lambda e, ep=ep_snap: on_select(str(ep))) if selectable else None
                        ),
                        ink=navigable or selectable,
                    )
                    entries_col.controls.append(row)

                page.update()

            backend.ui_call(page, _show)

        backend.safe_thread(page, _load).start()

    browser_widget = ft.Column(
        [
            ft.Container(
                content=breadcrumb_row,
                bgcolor=C_SURFACE2,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.Padding.symmetric(horizontal=8, vertical=4),
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
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=260,
                padding=ft.Padding.all(8),
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
                padding=ft.Padding.symmetric(horizontal=8, vertical=4),
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

    # Arrancar carga inicial después de que el modal esté en el árbol.
    # Route through backend.ui_call so the control mutations run on the asyncio event
    # loop and cannot race with ObjectPatch.from_diff (same fix as main browser).
    threading.Timer(0.1, lambda: backend.ui_call(page, refresh_fn)).start()


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
    on_back: Callable | None = None,
    on_tags: Callable | None = None,
    on_cifs: Callable | None = None,
) -> ft.Control:
    usuario_actual = credenciales_ldap["usuario"]

    num_cores = backend.obtener_num_cpus()
    rclone_config_path = str(backend.obtener_ruta_rclone_conf())

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
        border=ft.Border.all(1, f"{color_badge}55"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
    )

    def show_renew_dialog(e):
        days_tf = ft.TextField(
            value=str(STS_AUTO_RENEWAL_DAYS),
            bgcolor=C_SURFACE2,
            border_color=C_BORDER,
            focused_border_color=C_PRIMARY,
            color=C_TEXT,
            border_radius=6,
            content_padding=ft.Padding.symmetric(horizontal=12, vertical=10),
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
    back_btn  = btn_secondary("← Back", on_click=lambda e: on_back()) if on_back else None
    tags_btn  = btn_secondary("🏷️ Tags", on_click=lambda e: on_tags()) if on_tags else None
    cifs_btn = (
        btn_secondary("⊞  Mount CIFS", on_click=lambda e: on_cifs())
        if IS_WEB and on_cifs is not None
        else None
    )

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
    _initial_profile = (
        web_session.get("copy_tag_profile") if (IS_WEB and web_session) else None
    ) or list(TAG_PROFILES.keys())[0]
    active_copy_profile = {"name": _initial_profile}

    meta_fields: dict = {}
    meta_container = ft.Container()

    def _rebuild_meta(profile_name: str):
        col = build_meta_fields(profile_name, page, meta_fields)
        meta_container.content = col

    _rebuild_meta(active_copy_profile["name"])

    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in TAG_PROFILES.keys()],
        value=active_copy_profile["name"],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        width=220,
    )

    def _on_profile_change(e):
        new_profile = e.control.value
        if new_profile == active_copy_profile["name"]:
            return

        def _ask():
            def _do_switch():
                _rebuild_meta(new_profile)
                active_copy_profile["name"] = new_profile
                if IS_WEB and web_session is not None:
                    web_session["copy_tag_profile"] = new_profile
                page.update()

            def _cancel():
                profile_dd.value = active_copy_profile["name"]
                page.update()

            has_data = any((tf.value or "").strip() for tf in meta_fields.values())
            if has_data:
                show_confirm(
                    page,
                    "Change profile",
                    "Changing the profile will clear all metadata. Continue?",
                    on_yes=_do_switch,
                    on_no=_cancel,
                )
            else:
                _do_switch()

        backend.ui_call(page, _ask)

    profile_dd.on_select = _on_profile_change

    profile_row = ft.Row(
        [
            ft.Text("Metadata profile", size=12, color=C_TEXT_DIM, width=130),
            profile_dd,
        ],
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=8,
    )

    # ── Log ────────────────────────────────────────────────────────────────
    log_list = ft.ListView(
        expand=True,
        auto_scroll=True,
        spacing=0,
        padding=ft.Padding.all(12),
    )

    _log_lock = threading.Lock()

    log_container = ft.Container(
        content=log_list,
        bgcolor=C_BG,
        border=ft.Border.all(1, C_BORDER),
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

        backend.ui_call(page, _add)

    # ── Session-level log dispatcher (web only) ───────────────────────────
    # _dispatch_log accumulates every line in the session buffer AND forwards
    # to every registered UI callback (current page + any future reconnect).
    #
    # Throttling: instead of calling page.update() for every rclone output
    # line (up to 15+/s with 8 parallel transfers), we batch pending lines and
    # flush to callbacks at most every 150 ms. This keeps the Hypercorn asyncio
    # event loop free to accept new WebSocket connections, which was the root
    # cause of the "checking for updates" hang when reconnecting mid-transfer.
    import time as _time

    # Lock to prevent concurrent execution of the flush from both the
    # event-handler thread and a threading.Timer callback simultaneously.
    _dispatch_lock = threading.Lock()

    def _flush_log_callbacks() -> None:
        """Push all pending lines to live UI callbacks in one batched call."""
        with _dispatch_lock:
            if web_session is None:
                return
            pending = web_session.get("_dispatch_pending")
            if not pending:
                return
            web_session["_dispatch_pending"] = []
            web_session["_dispatch_last"]    = _time.monotonic()
            web_session["_dispatch_timer"]   = None
            combined = "".join(pending)
            dead = []
            for cb in list(web_session.get("copy_log_callbacks", [])):
                try:
                    cb(combined)   # one call → one page.update()
                except Exception:
                    dead.append(cb)
            for cb in dead:
                try:
                    web_session["copy_log_callbacks"].remove(cb)
                except ValueError:
                    pass

    def _dispatch_log(msg: str) -> None:
        if IS_WEB and web_session is not None:
            with _dispatch_lock:
                buf = web_session["copy_log_buffer"]
                buf.append(msg)
                # Cap buffer at 5 000 entries — on overflow drop the oldest 1 000.
                if len(buf) > 5000:
                    del buf[:-4000]

                web_session.setdefault("_dispatch_pending", []).append(msg)

                now  = _time.monotonic()
                last = web_session.get("_dispatch_last", 0.0)

            # Schedule / flush outside the lock (cb() calls page.run_thread
            # which must not be called while holding _dispatch_lock).
            if now - last >= 0.15:
                old_timer = web_session.get("_dispatch_timer")
                if old_timer:
                    old_timer.cancel()
                _flush_log_callbacks()
            elif not web_session.get("_dispatch_timer"):
                t = threading.Timer(0.2, _flush_log_callbacks)
                t.daemon = True
                t.start()
                web_session["_dispatch_timer"] = t
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
    cancel_btn = ft.Button(
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
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
        ),
    )
    mount_btn = btn_secondary("⊞  Mount destination")
    #mount_btn.visible = not IS_WEB
    mount_btn.visible = False
    save_btn  = btn_secondary("↓  Save log")
    close_btn = btn_secondary("✕  Close")

    def enable_btn(btn):
        def _do():
            btn.disabled = False
            btn.update()
        backend.ui_call(page, _do)

    _cancelling: list = [False]   # mutable flag; reset each time a new operation starts

    _cancelling: list = [False]   # mutable flag; reset each time a new operation starts

    def _set_running(running: bool):
        """Show/hide cancel button and toggle copy/check buttons."""
        if running:
            _cancelling[0] = False   # new operation — reset cancel guard
        def _do():
            cancel_btn.visible  = running
            copy_btn.disabled   = running
            check_btn.disabled  = running
            page.update()
        backend.ui_call(page, _do)

    def do_cancel(e):
        if _cancelling[0]:
            return   # already cancelling — ignore duplicate clicks
        proc = _active_proceso["proc"]
        if proc and proc.poll() is None:
            _cancelling[0] = True
            proc.terminate()
            _dispatch_log("\n⚠️  Transfer cancelled by user.\n")
            if IS_WEB and web_session is not None:
                web_session["copy_status"] = "error"
            # Update buttons directly here — we are already in the Flet event
            # handler context so page.update() is safe to call without
            # spawning a new thread (which could race with the log-dispatch
            # timer thread and cause concurrent page.update() calls inside
            # Flet's control-tree walker).
            cancel_btn.visible = False
            copy_btn.disabled  = False
            check_btn.disabled = False
            page.update()
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
            # no hace el save log bien, flet devuelve str y no path
            path = result.path if hasattr(result, "path") else result
            if path:
                contenido = "\n".join(
                    c.value for c in log_list.controls
                    if isinstance(c, ft.Text) and c.value
                )
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(contenido)
                    show_dialog(page, "Log saved", f"Saved to:\n{path}", C_ACCENT)
                except Exception as ex:
                    err_str = str(ex)
                    show_dialog(page, "Error", err_str, C_ERROR)

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
        # Persist non-empty selections to session.
        # Do NOT wipe copy_destino on empty path: the browser refresh timer
        # calls on_select("") on load — that must not overwrite a destination
        # the user already selected.
        if IS_WEB and web_session is not None and path:
            web_session["copy_destino"] = path
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
    _initial_dest = web_session.get("copy_destino", "") if (IS_WEB and web_session) else ""
    dest_browser, dest_browser_refresh = build_rclone_browser(
        page, perfil_rclone, on_select=on_browser_select, initial_path=_initial_dest
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

        backend.safe_thread(page, _run_copy).start()

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

        # Persist state so a reconnecting session can restore form + cancel btn
        if IS_WEB and web_session is not None:
            web_session["copy_status"]  = "running"
            web_session["copy_origen"]  = origen
            web_session["copy_destino"] = destino

        def _on_check_finish():
            _active_proceso["proc"] = None
            _set_running(False)
            if IS_WEB and web_session is not None:
                if web_session.get("copy_status") == "running":
                    web_session["copy_status"] = "done"
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

        backend.safe_thread(page, _run_check).start()

    # ── Montar destino ─────────────────────────────────────────────────────
    def do_mount(e):
        ruta = _dest_path["value"].strip()
        if not ruta:
            show_dialog(page, "Error", "Specify a destination path to mount.", C_ERROR)
            return
        try:
            backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
        except EnvironmentError as ex:
            err_str = str(ex)
            show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
        except Exception as ex:
            err_str = str(ex)
            show_dialog(page, "Mount error", err_str, C_ERROR)

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

            # Log rotation: keep only the most recent 50 files
            try:
                log_files = sorted(
                    [f for f in log_dir.glob("bifrost-*.log")],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                )
                MAX_LOG_FILES = 50
                if len(log_files) > MAX_LOG_FILES:
                    deleted_count = 0
                    for old_log in log_files[MAX_LOG_FILES:]:
                        old_log.unlink()
                        deleted_count += 1
                    if deleted_count > 0:
                        _dispatch_log(f"    (cleaned up {deleted_count} old log file(s))\n")
            except Exception as cleanup_ex:
                print(f"[log-rotation] Cleanup warning: {cleanup_ex}", flush=True)

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
                err_str = str(ex)
                show_dialog(page, "Error", err_str, C_ERROR)
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
        backend.ui_call(page, on_close)

    def do_close(e):
        show_confirm(
            page,
            "Close BIFROST",
            "This will unmount all mount points and close the application.",
            on_yes=lambda: backend.safe_thread(page, _do_close_cleanup).start(),
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
            build_header(subtitle=f"Copy & Verify — {perfil_rclone}", IS_WEB=IS_WEB),
            ft.Container(
                content=ft.Row(
                    [c for c in [back_btn, tags_btn, cifs_btn, expiry_badge, ft.Container(expand=True), renew_btn] if c is not None],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                margin=ft.Margin.only(bottom=4),
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
                        ft.Container(height=6),
                        profile_row,
                        ft.Container(height=10),
                        card(meta_container),
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
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    # FIX: lanzar la carga inicial del browser con un pequeño delay para que
    # show_screen() haya procesado el widget y page.update() se haya ejecutado
    # antes de que _navigate("") intente hacer page.update() sobre controles
    # ya registrados en el árbol de Flet.
    # The timer fires on a threading.Timer thread; routing through backend.ui_call keeps
    # all control mutations on the asyncio event loop (same fix as backend.ui_call above).
    threading.Timer(0.1, lambda: backend.ui_call(page, dest_browser_refresh)).start()

    # ── Replay historical log + show reconnect banner (web session restore) ─
    if IS_WEB and web_session is not None:
        buffer = list(web_session.get("copy_log_buffer", []))
        # Snapshot origin/dest/status NOW, before the browser-refresh timer
        # fires at t=0.1s and calls on_browser_select(""). Without the `and path`
        # guard in on_browser_select that call would wipe copy_destino; with it,
        # it doesn't — but we snapshot here as an extra safety net.
        _snap_origen  = web_session.get("copy_origen", "")
        _snap_destino = web_session.get("copy_destino", "")
        _snap_status  = web_session.get("copy_status", "idle")

        def _replay():
            import time
            time.sleep(0.2)   # wait for page tree to settle
            # Re-read status after sleep in case the process finished during reconnect.
            status = web_session.get("copy_status", _snap_status)
            # Check whether rclone is actually alive, regardless of copy_status.
            # copy_status can be "error" after the user clicked Cancel while the
            # process is still winding down (SIGTERM sent, proc not yet exited).
            # It can also be "running" while proc was already None (race between
            # the backend finally block and the copy_status update).
            _proc = web_session.get("copy_proceso", {}).get("proc")
            proc_alive = _proc is not None and _proc.poll() is None
            if proc_alive:
                status = "running"   # override — process is actually alive
            elif status == "running":
                status = "done"      # proc cleared before copy_status was updated
            if buffer:
                banner = (
                    f"\n{'─'*60}\n"
                    f"↩  Reconnected to existing session\n"
                    f"   Status: {status.upper()}\n"
                    f"   Origin:  {_snap_origen}\n"
                    f"   Dest:    {_snap_destino}\n"
                    f"{'─'*60}\n\n"
                )
                log(banner)
                # Batch all buffered lines into ONE log() call to avoid
                # flooding the event loop with thousands of page.update()
                # calls on reconnect (which caused the "checking for updates"
                # hang). Display only the last 200 lines; anything older is
                # already saved in ~/bifrost-logs/.
                MAX_REPLAY = 200
                if len(buffer) > MAX_REPLAY:
                    log(f"[… {len(buffer) - MAX_REPLAY} earlier lines omitted — see ~/bifrost-logs/ for the full log …]\n")
                log("".join(buffer[-MAX_REPLAY:]))
                if status == "running":
                    log("\n⚠️  Process is still running — new output will appear below\n")
                elif status == "done":
                    log("\n✅  Process finished while you were away\n")
                elif status == "error":
                    log("\n❌  Process ended with errors while you were away\n")

            # Always restore cancel button and form fields regardless of log
            if status == "running":
                _set_running(True)
                # The finish callback (_on_copy/check_finish) was created on
                # the PREVIOUS page and calls the OLD _set_running, so it
                # won't hide the cancel button on THIS (new) page. Poll until
                # the process ends and update the new page's buttons then.
                def _watch_proc_end():
                    import time as _t
                    while True:
                        _t.sleep(0.5)
                        if _active_proceso.get("proc") is None:
                            _set_running(False)
                            return
                threading.Thread(target=_watch_proc_end, daemon=True).start()

            def _prefill():
                if _snap_origen:
                    origen_tf.value = _snap_origen
                if _snap_destino:
                    _dest_path["value"] = _snap_destino
                    ruta_label.value = (
                        f"→ All files from source will be copied into: "
                        f"{perfil_rclone}:{_snap_destino}"
                    )
                    ruta_label.color = C_ACCENT
                page.update()
            backend.ui_call(page, _prefill)

        threading.Thread(target=_replay, daemon=True).start()

    return content


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
# VIEW: TAG MANAGER
# ============================================================================

def _build_tag_manager_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    on_back: Callable,
) -> ft.Control:
    # ── State ────────────────────────────────────────────────────────────
    s3  = {"client": None}
    nav = {"bucket": None, "prefix": "", "show_files": False}
    sel = {"type": "none", "key": None, "count": 0, "display": ""}
    active_profile  = {"name": list(TAG_PROFILES.keys())[0]}
    tag_fields: dict[str, ft.TextField] = {}
    _log_buffer: list[str] = []
    _current_items = {"folders": [], "files": []}
    _file_tag_rows: list[dict] = []          # freeform editor rows
    _file_editor_section  = None             # assigned after building widgets
    _profile_editor_section = None           # assigned after building widgets
    right_panel = {"visible": False}

    # ── Log ───────────────────────────────────────────────────────────────
    log_list = ft.ListView(
        expand=True, auto_scroll=True, spacing=0,
        padding=ft.Padding.all(12),
    )
    log_section = ft.Container(
        content=ft.Column([
            ft.Text("LOGS", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
            ft.Container(height=6),
            ft.Container(
                content=log_list,
                bgcolor=C_BG,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=180,
            ),
        ], spacing=0),
        padding=ft.Padding.symmetric(horizontal=24, vertical=8),
        visible=False,
    )

    def _log(msg: str, color: str = C_TEXT) -> None:
        _log_buffer.append(msg)
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, selectable=True)
            )
        backend.ui_call(page, _add)

    def _autosave_tag_log() -> None:
        content = "".join(_log_buffer)
        if not content.strip():
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = pathlib.Path.home() / "bifrost-logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fpath = log_dir / f"bifrost-tags-{ts}.log"
            fpath.write_text(content, encoding="utf-8")
            _log(f"\n📄 Log saved to: {fpath}", C_TEXT_DIM)
        except Exception as ex:
            _log(f"\n⚠️  Could not save log file: {ex}", C_WARNING)

    def _get_client():
        if s3["client"] is None:
            s3["client"] = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
        return s3["client"]

    # ── Browser ───────────────────────────────────────────────────────────
    breadcrumb_row = ft.Row(spacing=2, wrap=True)
    browser_col    = ft.Column(spacing=4, tight=True)
    browser_loading = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8, visible=False,
    )
    browser_error = ft.Text("", color=C_ERROR, size=11, visible=False)

    def _rebuild_breadcrumb() -> None:
        breadcrumb_row.controls.clear()

        def _crumb(label: str, on_click_fn):
            return ft.TextButton(
                label,
                on_click=on_click_fn,
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.Padding.symmetric(horizontal=4, vertical=0),
                ),
            )

        breadcrumb_row.controls.append(
            _crumb("buckets", lambda e: _navigate(None, ""))
        )
        if nav["bucket"]:
            breadcrumb_row.controls.append(ft.Text("/", color=C_TEXT_DIM, size=12))
            bname = nav["bucket"]
            breadcrumb_row.controls.append(
                _crumb(bname, lambda e, b=bname: _navigate(b, ""))
            )
            accumulated = ""
            for part in nav["prefix"].split("/"):
                if not part:
                    continue
                accumulated += part + "/"
                acc_copy = accumulated
                breadcrumb_row.controls.append(ft.Text("/", color=C_TEXT_DIM, size=12))
                breadcrumb_row.controls.append(
                    _crumb(part, lambda e, p=acc_copy: _navigate(nav["bucket"], p))
                )
        page.update()

    def _render_browser_contents() -> None:
        if hasattr(browser_col.controls, "clear"):
            browser_col.controls.clear()
        else:
            browser_col.controls = []

        if nav["bucket"] is None:
            for bname in _current_items["folders"]:
                arrow = ft.IconButton(
                    icon=ft.Icons.CHEVRON_RIGHT,
                    icon_color=C_TEXT_DIM,
                    icon_size=16,
                    tooltip="Enter bucket",
                    on_click=lambda e, b=bname: _navigate(b, ""),
                )

                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.STORAGE_OUTLINED, color=C_PRIMARY, size=16),
                        ft.Text(bname, size=13, color=C_TEXT, expand=True),
                        arrow,
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=C_SURFACE2,
                    border=ft.Border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                    ink=True,
                )

                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_double_tap=lambda e, b=bname: _navigate(b, ""),
                    )
                )
        else:
            for prefix in _current_items["folders"]:
                name = prefix.rstrip("/").split("/")[-1] + "/"
                is_sel = sel["type"] == "prefix" and sel["key"] == prefix

                tag_btn = ft.IconButton(
                    icon=ft.Icons.LABEL_OUTLINED,
                    icon_color=C_ACCENT,
                    icon_size=16,
                    tooltip="Edit tags for all files in this folder",
                    on_click=lambda e, p=prefix: _select_prefix_and_open(p),
                )

                arrow = ft.IconButton(
                    icon=ft.Icons.CHEVRON_RIGHT,
                    icon_color=C_TEXT_DIM,
                    icon_size=16,
                    tooltip="Enter folder",
                    on_click=lambda e, p=prefix: _navigate(nav["bucket"], p),
                )

                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
                        ft.Text(name, size=13, color=C_TEXT, expand=True),
                        tag_btn,
                        arrow,
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=f"{C_ACCENT}18" if is_sel else C_SURFACE,
                    border=ft.Border.all(
                        2 if is_sel else 1,
                        C_ACCENT if is_sel else C_BORDER,                     
                    ),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                    ink=True,
                )

                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_double_tap=lambda e, p=prefix: _navigate(nav["bucket"], p),
                    )
                )

            files = _current_items["files"]

            if not nav["show_files"]:
                view_files_btn = ft.TextButton(
                    "View files in this folder",
                    icon=ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                    style=ft.ButtonStyle(color=C_TEXT_DIM),
                )

                def _on_view_files(e):
                    view_files_btn.disabled = True
                    view_files_btn.text = "Loading files..."
                    browser_loading.visible = True
                    page.update()

                    def _async_load():
                        real_files = backend.rclone_list_files_only(
                            perfil_rclone, nav["bucket"], nav["prefix"]
                        )
                        _current_items["files"] = real_files
                        nav["show_files"] = True
                        browser_loading.visible = False
                        backend.ui_call(page, _render_browser_contents)

                    import threading
                    threading.Thread(target=_async_load, daemon=True).start()

                view_files_btn.on_click = _on_view_files
                browser_col.controls.append(
                    ft.Container(
                        content=view_files_btn,
                        padding=ft.Padding.symmetric(horizontal=4, vertical=2),
                    )
                )

            elif nav["show_files"]:
                for key in files:
                    name = key.split("/")[-1]
                    is_sel = sel["type"] == "file" and sel["key"] == key

                    c = ft.Container(
                        content=ft.Row([
                            ft.Icon(
                                ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                color=C_ACCENT if is_sel else C_TEXT_DIM,
                                size=16,
                            ),
                            ft.Text(name, size=12, color=C_TEXT, expand=True),
                        ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                        bgcolor=f"{C_ACCENT}18" if is_sel else C_SURFACE,
                        border=ft.Border.all(
                            2 if is_sel else 1,
                            C_ACCENT if is_sel else C_BORDER,
                        ),
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                        ink=True,
                    )

                    browser_col.controls.append(
                        ft.GestureDetector(
                            content=c,
                            on_tap=lambda e, k=key: _select_file(k),
                        )
                    )

        if not _current_items["folders"] and not _current_items["files"]:
            browser_col.controls.append(
                ft.Text("(empty content)", size=11, color=C_TEXT_DIM, italic=True)
            )

        page.update()
        
    def _select_prefix_and_open(prefix: str) -> None:
        # nav["show_files"] = False
        right_panel["visible"] = True
        right_editor.visible = True

        def _show_panel():
            right_editor.visible = True
            if _file_editor_section is not None:
                _file_editor_section.visible = False
                _profile_editor_section.visible = True
            page.update()

        backend.ui_call(page, _show_panel)

        bucket = nav["bucket"]
        if not bucket:
            return
        
        label   = f"📁 {prefix or (bucket + '/')}"
        note    = "(Will be recursively applied to all objects within this folder)"

        def _upd():
            sel["type"]    = "prefix"
            sel["key"]     = prefix
            sel["count"]   = 0
            sel["display"] = label
            target_label.value    = label
            obj_count_label.value = note
            apply_btn.disabled    = False
            _rebuild_tag_fields(profile_dd.value)
            _render_browser_contents() 
        backend.ui_call(page, _upd)

    def _select_prefix(prefix: str) -> None:
        nav["show_files"] = False
        right_panel["visible"] = True
        right_editor.visible = True

        def _show_panel():
            right_editor.visible = True
            if _file_editor_section is not None:
                _file_editor_section.visible = False
                _profile_editor_section.visible = True
            page.update()

        backend.ui_call(page, _show_panel)

        old_prefix = nav["prefix"]
        nav["prefix"] = prefix
        _update_prefix_selection()
        nav["prefix"] = old_prefix

    def _navigate(bucket: str | None, prefix: str) -> None:
        nav["bucket"]     = bucket
        nav["prefix"]     = prefix
        nav["show_files"] = False
        right_editor.visible = False
        right_panel["visible"] = False
        sel["type"]   = "none"
        sel["key"]    = None
        sel["count"]  = 0
        sel["display"] = ""
        _current_items["folders"] = []
        _current_items["files"]   = []

        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Select a folder or a file"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            if _file_editor_section is not None:
                _file_editor_section.visible  = False
                _profile_editor_section.visible = True
                _file_save_status.visible = False
            _rebuild_breadcrumb()
            
        backend.ui_call(page, _reset_editor)
        backend.safe_thread(page, _load_browser).start()

    def _navigate_to_prefix(bucket: str, prefix: str) -> None:
        _navigate(bucket, prefix)

    def _load_browser() -> None:
        def _set_loading():
            browser_loading.visible = True
            browser_error.visible   = False
            if hasattr(browser_col.controls, "clear"):
                browser_col.controls.clear()
            else:
                browser_col.controls = []
            page.update()
        backend.ui_call(page, _set_loading)

        try:
            client = _get_client()
            if nav["bucket"] is None:
                buckets = backend.rclone_lsd(perfil=perfil_rclone, path="")
                _current_items["folders"] = buckets
                _current_items["files"]   = []
            else:
                folders, files = backend.list_prefix_contents(
                    perfil_rclone, nav["bucket"], nav["prefix"]
                )
                _current_items["folders"] = folders
                _current_items["files"]   = files

            def _show():
                browser_loading.visible = False
                _render_browser_contents()
            backend.ui_call(page, _show)

        except Exception as ex:
            def _err(ex_val=ex):
                browser_loading.visible = False
                browser_error.value     = f"Error: {ex_val}"
                browser_error.visible   = True
                page.update()
            backend.ui_call(page, _err)

    def _update_prefix_selection() -> None:
        bucket = nav["bucket"]
        prefix = nav["prefix"]
        if not bucket:
            return
        
        label   = f"📁 {prefix or (bucket + '/')}"
        note    = "(Tag scanning and counting disabled for speed)"
        tags_cp = {}
        cnt_cp  = 0

        def _upd():
            sel["type"]    = "prefix"
            sel["key"]     = None
            sel["count"]   = cnt_cp
            sel["display"] = label
            target_label.value    = label
            obj_count_label.value = note
            apply_btn.disabled    = False
            _prefill_fields(tags_cp)
        backend.ui_call(page, _upd)

    def _select_file(key: str) -> None:
        def _do():
            client = _get_client()
            right_panel["visible"] = True
            right_editor.visible = True
            try:
                tags = backend.get_object_tags(client, nav["bucket"], key)
            except Exception as ex:
                tags = {}
                ex_str = str(ex)
                def _err():
                    browser_error.value   = f"Error reading tags: {ex_str}"
                    browser_error.visible = True
                    page.update()
                backend.ui_call(page, _err)

            display = f"📄 {key}"
            tags_cp = dict(tags)

            def _upd():
                sel["type"]    = "file"
                sel["key"]     = key
                sel["count"]   = 1
                sel["display"] = display
                target_label.value    = display
                obj_count_label.value = ""
                apply_btn.disabled    = False
                #_prefill_fields(tags_cp)
                _file_name_label.value = key
                _populate_file_editor(tags_cp)
                file_editor_mode["mode"] = "list"
                file_card_container.visible = False
                _file_tags_col.visible = True
                add_tag_btn.visible = True
                file_list_headers.visible = True
                if _file_editor_section is not None:
                    _file_editor_section.visible  = True
                _profile_editor_section.visible = False
                _render_browser_contents()
            backend.ui_call(page, _upd)
        backend.safe_thread(page, _do).start()

    # ── Editor ────────────────────────────────────────────────────────────
    profile_names = list(TAG_PROFILES.keys())
    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        width=220,
        #on_change=_on_profile_change,
    )

    print(f"[DEBUG] profile_dd creado: {id(profile_dd)}")
    
    # Contenedor raíz para los campos dinámicos
    card_container = ft.Container()
    target_label    = ft.Text("Select a folder or a file", size=12, color=C_TEXT_DIM, italic=True)
    obj_count_label = ft.Text("", size=11, color=C_TEXT_DIM)
    apply_btn       = btn_primary("Apply tags →")
    apply_btn.disabled = True
    apply_status    = ft.Text("", size=12, color=C_TEXT_DIM, visible=False)
        
    def _rebuild_tag_fields(profile_name: str, target_container=None, target_fields=None) -> None:
        container = target_container if target_container is not None else card_container
        fields    = target_fields    if target_fields    is not None else tag_fields
        active_profile["name"] = profile_name
        col = build_meta_fields(profile_name, page, fields)
        container.content = card(col, padding=16)
        page.update()

    def _on_profile_change(e):
        print(f"[DEBUG] _on_profile_change fired RAW, value: {e.control.value}")
        name = e.control.value
        print(f"[DEBUG] _on_profile_change fired, value: {name}")
        backend.ui_call(page, lambda: _rebuild_tag_fields(name))
        print(f"[DEBUG] ui_call scheduled")
    
    def _prefill_fields(tags: dict[str, str]) -> None:
        for key, tf in tag_fields.items():
            if key in tags:
                tf.value = tags[key]
        page.update()

    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        width=220
    )

    profile_dd.on_select = _on_profile_change
    print(f"[DEBUG] profile_dd id: {id(profile_dd)}, on_select registrado: {profile_dd.on_select}")
    _rebuild_tag_fields(profile_names[0])

    def do_apply(e) -> None:
        tagset = {k: (tf.value or "").strip() for k, tf in tag_fields.items()}
        apply_btn.disabled  = True
        apply_status.value  = "Applying tags..."
        apply_status.color  = C_TEXT_DIM
        apply_status.visible = True
        log_section.visible  = True
        page.update()

        def _do():
            client = _get_client()
            bucket = nav["bucket"]
            ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _log(f"### Tags applied — {ts} ###\n")
            _log(f"Profile: {active_profile['name']}\n", C_TEXT_DIM)
            for k, v in tagset.items():
                if v:
                    _log(f"  {k}: {v}\n", C_TEXT_DIM)
            _log("\n")

            try:
                if sel["type"] == "file":
                    _log(f"📄 File: {sel['key']}\n")
                    backend.apply_tags_to_object(client, bucket, sel["key"], tagset)
                    _log(f"  ✓ {sel['key']}\n", C_ACCENT)
                    n_ok = 1
                else:
                    prefix = sel["key"] if sel["key"] is not None else ""
                    _log(f"📁 Bulk Prefix S3/MinIO: {bucket}/{prefix}\n")
                    _log(f"⏳ Searching recursively for all objects inside this prefix...\n", C_TEXT_DIM)
                    n_ok = backend.apply_tags_to_prefix(
                        client, bucket, prefix, tagset,
                        log_fn=lambda msg: _log(msg),
                    )

                _log(f"\n✅ {n_ok} object(s) tagged successfully.\n", C_ACCENT)

                def _ok():
                    apply_btn.disabled   = False
                    apply_status.value   = f"✅ {n_ok} object(s) updated"
                    apply_status.color   = C_ACCENT
                    page.update()
                backend.ui_call(page, _ok)

            except Exception as ex:
                err_str = str(ex)
                _log(f"\n❌ Error: {err_str}\n", C_ERROR)
                def _err():
                    apply_btn.disabled   = False
                    apply_status.value   = "❌ Error applying tags"
                    apply_status.color   = C_ERROR
                    page.update()
                backend.ui_call(page, _err)

            _autosave_tag_log()

        backend.safe_thread(page, _do).start()

    apply_btn.on_click = do_apply

    # ── Freeform Editor (Individual File) ────────────────────────────
    _add_btn_ref  = {"btn": None}   
    _save_btn_ref = {"btn": None}   

    _file_name_label  = ft.Text("", size=12, color=C_TEXT_DIM, italic=True)
    _file_tags_col    = ft.Column(spacing=6, tight=True)
    _file_save_status = ft.Text("", size=12, visible=False)
    file_card_container = ft.Container(visible=False, expand=True)
    file_editor_mode = {"mode": "list"}  # "list" o "profile"
    file_tag_fields: dict = {}    

    file_list_headers = ft.Row(
            [
                ft.Text("Key", size=11, color=C_TEXT_DIM, expand=1),
                ft.Text("Value", size=11, color=C_TEXT_DIM, expand=2),
                ft.Container(width=40),
            ],
            spacing=6,
        )

    def _refresh_add_btn_state() -> None:
        if _add_btn_ref["btn"] is not None:
            _add_btn_ref["btn"].disabled = len(_file_tag_rows) >= 10

    def _build_file_editor_row(key: str = "", value: str = "") -> dict:
        
        key_tf = ft.TextField(
            value=key, hint_text="Key",
            bgcolor=C_SURFACE2, border_color=C_BORDER,
            focused_border_color=C_PRIMARY, color=C_TEXT,
            hint_style=ft.TextStyle(color=C_TEXT_DIM),
            border_radius=6,
            content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            text_size=12, max_length=128, expand=1,
        )
        
        val_container = ft.Container(expand=2)
        row_dict: dict = {"key_tf": key_tf, "val_tf": None, "row": None, "val_container": val_container}

        def update_value_field_type(current_key: str, current_val: str):
            field_tf = ft.TextField(
                value=current_val, hint_text="Value",
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                hint_style=ft.TextStyle(color=C_TEXT_DIM),
                border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                text_size=12, max_length=256, expand=True
            )
            row_dict["val_tf"] = field_tf
            val_container.content = field_tf  # siempre simple, sin dropdown

        update_value_field_type(key, value)

        def on_key_change(e):
            old_val = row_dict["val_tf"].value or ""
            update_value_field_type(key_tf.value, old_val)
            page.update()
            
        key_tf.on_change = on_key_change

        def _delete(e, rd=row_dict):
            if rd in _file_tag_rows:
                _file_tag_rows.remove(rd)
            if rd["row"] in _file_tags_col.controls:
                _file_tags_col.controls.remove(rd["row"])
            _refresh_add_btn_state()
            page.update()

        row = ft.Row(
            [
                key_tf, val_container,
                ft.IconButton(
                    icon=ft.Icons.CLOSE, icon_size=16, icon_color=C_TEXT_DIM,
                    tooltip="Remove", on_click=_delete,
                ),
            ],
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        row_dict["row"] = row
        return row_dict

    def _populate_file_editor(tags: dict[str, str]) -> None:
        _file_tag_rows.clear()
        _file_tags_col.controls = []
        _file_save_status.visible = False
        for k, v in tags.items():
            rd = _build_file_editor_row(k, v)
            _file_tag_rows.append(rd)
            _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()

    def _on_add_tag_row(e) -> None:
        if len(_file_tag_rows) >= 10:
            return
        rd = _build_file_editor_row()
        _file_tag_rows.append(rd)
        _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()

    def _on_prefill_from_profile(e) -> None:
        profile_name = prefill_profile_dd.value
        active_profile["name"] = profile_name
        file_editor_mode["mode"] = "profile"
        
        _file_tags_col.visible      = False
        add_tag_btn.visible         = False
        file_list_headers.visible   = False
        file_card_container.visible = True
        
        _rebuild_tag_fields(profile_name, target_container=file_card_container, target_fields=file_tag_fields)

    def _on_save_file_tags(e) -> None:
        if file_editor_mode["mode"] == "profile":
            tagset = {k: (c.value or "").strip() for k, c in file_tag_fields.items()}
        else:
            tagset = {
                rd["key_tf"].value.strip(): rd["val_tf"].value.strip()
                for rd in _file_tag_rows
                if rd["key_tf"].value.strip()
            }

        if _save_btn_ref["btn"] is not None:
            _save_btn_ref["btn"].disabled = True
        _file_save_status.value   = "Saving..."
        _file_save_status.color   = C_TEXT_DIM
        _file_save_status.visible = True
        page.update()

        def _do():
            client = _get_client()
            try:
                backend.apply_tags_to_object(client, nav["bucket"], sel["key"], tagset)
                def _ok():
                    if _save_btn_ref["btn"] is not None:
                        _save_btn_ref["btn"].disabled = False
                    _file_save_status.value = "✅ Tags saved successfully"
                    _file_save_status.color = C_ACCENT
                    page.update()
                backend.ui_call(page, _ok)
            except Exception as ex:
                err_str = str(ex)
                def _err():
                    if _save_btn_ref["btn"] is not None:
                        _save_btn_ref["btn"].disabled = False
                    _file_save_status.value = f"❌ Error: {err_str}"
                    _file_save_status.color = C_ERROR
                    page.update()
                backend.ui_call(page, _err)

        backend.safe_thread(page, _do).start()

    add_tag_btn = btn_secondary("+ Add tag", on_click=_on_add_tag_row)
    _add_btn_ref["btn"] = add_tag_btn

    prefill_profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=12,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        width=175,
    )
    prefill_profile_dd.on_change = lambda e: active_profile.update({"name": e.control.value})
    prefill_btn   = btn_secondary("Pre-fill", on_click=_on_prefill_from_profile)
    file_save_btn = btn_primary("Save tags")
    file_save_btn.on_click = _on_save_file_tags
    _save_btn_ref["btn"]   = file_save_btn

    _file_editor_section = ft.Container(
        visible=False,
        expand=True,
        content=ft.Column(
            [
                ft.Text("FILE TAGS EDITOR", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                _file_name_label,
                ft.Container(height=8),
                file_list_headers,
                ft.Container(height=4),
                _file_tags_col,
                file_card_container, 
                ft.Container(height=8),
                add_tag_btn,
                ft.Container(height=12),
                ft.Divider(height=1, color=C_BORDER),
                ft.Container(height=8),
                ft.Row(
                    [prefill_profile_dd, prefill_btn],
                    spacing=8,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=12),
                ft.Row(
                    [file_save_btn, _file_save_status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=0,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        ),
    )

    _profile_editor_section = ft.Container(
        visible=True,
        expand=True,
        content=ft.Column(
            [
                ft.Text("EDIT FOLDER TAGS", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                # El seleccionador de Perfil se encuentra FUERA del cuadro de metadatos
                ft.Row(
                    [
                        ft.Text("Profile:", size=13, color=C_TEXT),
                        profile_dd,
                    ],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=12),
                # Contenedor dinámico que aloja los metadatos de la carpeta
                card_container,
                ft.Container(height=12),
                ft.Container(
                    content=ft.Column(
                        [target_label, obj_count_label],
                        spacing=2,
                    ),
                    bgcolor=C_SURFACE2,
                    border=ft.Border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                ),
                ft.Container(height=12),
                ft.Row(
                    [apply_btn, apply_status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=0,
            expand=True,
        ),
    )

    right_editor = ft.Container(
        visible=False,
        content=ft.Column(
            [_file_editor_section, _profile_editor_section],
            spacing=0,
            expand=True,
        ),
        padding=ft.Padding.only(left=16),
        expand=True,
    )
    
    # ── Layout ────────────────────────────────────────────────────────────
    back_btn = btn_secondary("← Back", on_click=lambda e: on_back())

    content = ft.Column(
        [
            build_header(subtitle="Tag Manager", IS_WEB=IS_WEB),
            ft.Container(
                content=ft.Row(
                    [back_btn, ft.Container(expand=True)],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
            ),
            ft.Container(
                content=ft.Row(
                    [
                        # Left panel: Browser
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text("BROWSE", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                                    ft.Container(height=8),
                                    breadcrumb_row,
                                    ft.Container(height=6),
                                    browser_loading,
                                    browser_error,
                                    ft.Container(
                                        content=ft.Column(
                                            [browser_col],
                                            scroll=ft.ScrollMode.AUTO,
                                            spacing=0,
                                        ),
                                        bgcolor=C_SURFACE,
                                        border=ft.Border.all(1, C_BORDER),
                                        border_radius=6,
                                        height=400,
                                        padding=ft.Padding.all(8),
                                    ),
                                ],
                                spacing=0,
                                width=380,
                            ),
                        ),
                        ft.VerticalDivider(width=1, color=C_BORDER),
                        # Right panel: Editor
                        right_editor,  
                    ],
                    spacing=0,
                    expand=True,
                    vertical_alignment=ft.CrossAxisAlignment.START,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                expand=True,
            ),
            log_section,
        ],
        expand=True,
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    backend.safe_thread(page, _load_browser).start()
    return content

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
    global IS_WEB
    IS_WEB = IS_WEB or page.web
    page.title             = "BIFROST — TRANSFER"
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
        "_cifs_loading":         False,
    }

    import atexit
    
    def _cleanup_on_exit():
        print("[atexit] Cleaning up...")
        backend.desmontar_todos_los_mounts_s3()
        mounts = state.get("mounts_activos", [])
        if mounts and IS_WEB:
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
    # A stop-event is used so the previous task exits immediately when
    # main() is called again on reconnection, preventing task accumulation.
    if IS_WEB:
        _hb_stop = [False]   # mutable flag accessible from the coroutine closure

        async def _ws_heartbeat():
            import asyncio as _aio
            while not _hb_stop[0]:
                await _aio.sleep(20)
                if _hb_stop[0]:
                    return
                try:
                    page.update()
                except Exception:
                    return

        # Signal any previous heartbeat for this page object to stop,
        # then launch a fresh one.
        if hasattr(page, "_bifrost_hb_stop"):
            page._bifrost_hb_stop[0] = True
        page._bifrost_hb_stop = _hb_stop
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
        go_minio()

    def go_minio():
        show_screen(_build_minio_content(page, on_continue=on_minio_selected))

    def on_minio_selected(eleccion: dict):
        state["servidor_minio"] = eleccion["servidor"]
        state["perfil_rclone"]  = eleccion["perfil"]
        state["endpoint"]       = eleccion["endpoint"]

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

    def go_tags():
        print("[tags] Entrando en Tag Manager", flush=True)
        show_screen(_build_tag_manager_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            endpoint=state["endpoint"],
            on_back=go_copy,
        ))

    def _load_and_show_shares(skip_groups: bool = False) -> None:
        """Carga grupos LDAP + credentials SMB + shares en background y muestra la vista."""
        if state.get("_cifs_loading"):
            return
        state["_cifs_loading"] = True
        creds_ldap = state["credenciales_ldap"]

        show_loading("Loading accessible shares...")

        def _bg():
            try:
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

                # Si estamos en modo admin y no hay shares, las credenciales
                # admin son probablemente incorrectas — revertir y mostrar error.
                if skip_groups and not shares:
                    state["usar_privilegios"]   = False
                    state["credenciales_admin"] = None
                    state["credenciales_smb"]   = None
                    backend.ui_call(page, lambda: show_dialog(
                        page,
                        "Admin credentials error",
                        "No shares were found. Check your admin password and try again.",
                        C_ERROR,
                    ))
                    return

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
            finally:
                state["_cifs_loading"] = False

        backend.safe_thread(page, _bg).start()


    def go_cifs() -> None:
        """Navega a la vista de CIFS shares. Carga lazy en el primer acceso."""
        if state["credenciales_smb"] is not None and not state.get("_cifs_loading"):
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
        state["credenciales_smb"]   = None   # forzar recarga, evitar fast-path con datos viejos
        _load_and_show_shares(skip_groups=True)


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

    def do_close():
        if IS_WEB:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario")
            if usuario:
                _ws_clear(usuario)
        if IS_WEB and state["mounts_activos"]:
            usuario = (state["credenciales_smb"] or {}).get("usuario") or getpass.getuser()
            backend.safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()
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

    if IS_WEB:
        go_login()
    else:
        show_screen(build_update_content(page, on_continue=go_login))

# ============================================================================
# WEB VERSION IN OOD
# ============================================================================
if os.environ.get("BIFROST_CLUSTER") == "1":
    from flet.fastapi import FletApp, app_manager
    from fastapi import FastAPI, WebSocket
    import asyncio

    WEBSOCKET_ENDPOINT = os.environ.get("FLET_WEBSOCKET_HANDLER_ENDPOINT")
    WEBPATH = os.environ.get("WEBPATH")
    SECRET_TOKEN = os.environ.get("password") or ""
    if not SECRET_TOKEN:
        print("[WARNING] 'password' environment variable is not set — WebSocket auth disabled", flush=True)

    app = FastAPI()
    flet_asgi_app  = ft.app(main,export_asgi_app=True)
    app.mount(WEBPATH, flet_asgi_app)

    @app.websocket(WEBSOCKET_ENDPOINT)
    async def flet_app(websocket: WebSocket):
        if "--web" not in sys.argv:
            token = websocket.cookies.get("bifrost_auth_token")

            if not SECRET_TOKEN or token != SECRET_TOKEN:
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
