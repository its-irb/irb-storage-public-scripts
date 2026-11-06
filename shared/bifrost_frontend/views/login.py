"""Vista de login LDAP (compartida por mount y transfer)."""

from __future__ import annotations

import getpass
import logging
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.rclone_output import INVALID_CREDENTIALS, ISSUES_BY_CODE, UNEXPECTED

from ..components import btn_primary, build_header, issue_reference, styled_field
from ..theme import C_BORDER, C_ERROR, C_PRIMARY, C_SURFACE, C_TEXT, C_TEXT_DIM, C_WARNING

log = logging.getLogger("bifrost.login")

# Motivo del fallo (validar_credenciales_ldap) → mensaje de esta pantalla y tipo de error. El código no se muestra
# (aquí es ruido), pero se anota en el log técnico ("issue shown") como en las demás pantallas.
_LDAP_ERRORS = {
    "vpn":     ("⚠️ Cannot reach the IRB network. Are you connected to the VPN?", ISSUES_BY_CODE["NETWORK"]),
    "network": ("⚠️ Could not reach the LDAP server. Try again or contact ITS.", ISSUES_BY_CODE["NETWORK"]),
    "error":   ("⚠️ Unexpected error validating credentials. Contact ITS.", UNEXPECTED),
}
# user_not_found / invalid_password no están a propósito: usan el error por defecto, el mismo para no revelar si el
# usuario existe.


def build_login_content(
    page: ft.Page,
    on_success: Callable,
    prefill_user: str = "",
    *,
    no_ldap: bool,
    is_web: bool = False,
) -> ft.Control:

    try:
        default_user = prefill_user or getpass.getuser()
    except Exception:
        default_user = prefill_user or ""

    user_tf, user_col = styled_field(
        "Username",
        value=default_user,
        hint="your.username",
    )

    pass_tf, pass_col = styled_field("Password", password=True)

    error_text = ft.Text("", color=C_ERROR, size=12, visible=False)
    loading    = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                  color=C_PRIMARY, visible=False)
    login_btn  = btn_primary("Authenticate", width=280)

    def _set_busy(busy: bool):
        """Bloquea el formulario mientras se valida (evita doble envío y edición)."""
        login_btn.disabled = user_tf.disabled = pass_tf.disabled = busy
        loading.visible = busy

    def _show_error(msg: str):
        error_text.value   = msg
        error_text.visible = True
        _set_busy(False)
        page.update()

    def do_login(e=None):
        user = (user_tf.value or "").strip()
        pwd  = pass_tf.value or ""
        if not user or not pwd:
            error_text.value   = "Username is required." if not user else "Password is required."
            error_text.visible = True
            page.update()
            return

        _set_busy(True)
        error_text.visible = False
        page.update()

        def _auth():
            creds = {"usuario": user, "password": pwd}
            log.info("LOGIN attempt — user: %s", user)
            if no_ldap:
                log.info("LOGIN bypass LDAP — user: %s", user)
                backend.ui_call(page, lambda: on_success(creds))
                return
            ok, motivo = backend.validar_credenciales_ldap(creds)
            if ok:
                log.info("LOGIN success — user: %s", user)
                backend.ui_call(page, lambda: on_success(creds))
            else:
                log.info("LOGIN failed — user: %s — reason: %s", user, motivo)
                msg, issue = _LDAP_ERRORS.get(motivo, ("Invalid credentials. Please try again.", INVALID_CREDENTIALS))
                issue_reference(issue, "login")             # el código, solo al log técnico
                backend.ui_call(page, lambda: _show_error(msg))

        backend.safe_thread(page, _auth).start()

    login_btn.on_click = do_login
    pass_tf.on_submit  = do_login
    user_tf.on_submit  = lambda e: pass_tf.focus()

    content = ft.Column(
        [
            build_header(subtitle="Authentication", IS_WEB=is_web, no_ldap=no_ldap, page=page),
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
