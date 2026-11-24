"""Diálogo "Renew MinIO credentials" (compartido por mount y transfer): renovar a mano las credenciales de un servidor
durante 1-30 días."""

from __future__ import annotations

from typing import Callable

import flet as ft

from bifrost_backend.common.constants import STS_AUTO_RENEWAL_DAYS
from ..components import ErrorBanner, btn_primary, btn_secondary, open_dialog
from ..theme import C_BORDER, C_PRIMARY, C_SURFACE2, C_TEXT, C_TEXT_DIM


def show_renew_dialog(page: ft.Page, *, perfil: str, usuario: str, on_renew: Callable[[int], None]) -> None:
    """Pide los días y, al confirmar, cierra el diálogo y llama a on_renew(días)."""
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
        text_align=ft.TextAlign.CENTER,
        autofocus=True,
        keyboard_type=ft.KeyboardType.NUMBER,
    )
    err = ErrorBanner(visible=False)
    days_tf.on_submit = lambda e: do_renew()

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
        on_renew(dias_int)

    def cancel(ev):
        page.pop_dialog()

    open_dialog(
        page,
        title="Renew MinIO credentials",
        subtitle=f"Profile {perfil}  ·  user {usuario}",
        color=C_PRIMARY,
        icon=ft.Icons.AUTORENEW,
        body=[
            ft.Row(
                [
                    ft.Text("Renew for:", size=13, color=C_TEXT),
                    days_tf,
                    ft.Text("days", size=13, color=C_TEXT),
                ],
                spacing=10,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            ft.Text("Between 1 and 30 days.", color=C_TEXT_DIM, size=11),
            err,
        ],
        actions=[
            btn_secondary("Cancel", on_click=cancel),
            btn_primary("Renew", icon=ft.Icons.AUTORENEW, on_click=do_renew),
        ],
    )
