"""Vista de selección y montaje de shares CIFS (modo cluster)."""

from __future__ import annotations

from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP
from bifrost_frontend.frontend import *

# main.py fija el valor real al arrancar: IS_WEB solo puede calcularse en main.py
# (depende de __name__), y las funciones de este módulo lo leen al ejecutarse.
IS_WEB = False


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
                build_header(subtitle=f"NetApp Shares — {usuario_actual}", IS_WEB=IS_WEB, no_ldap=NO_LDAP),
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
            build_header(subtitle=f"NetApp Shares — {usuario_actual}", IS_WEB=IS_WEB, no_ldap=NO_LDAP),
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
