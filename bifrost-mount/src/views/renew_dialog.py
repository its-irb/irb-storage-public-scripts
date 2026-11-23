"""Diálogo "Renew MinIO credentials": renovar a mano las credenciales de un servidor durante 1-30 días."""

from __future__ import annotations

from typing import Callable

import flet as ft

from bifrost_backend.common.constants import STS_AUTO_RENEWAL_DAYS
from bifrost_frontend.frontend import *


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
        on_renew(dias_int)

    def cancel(ev):
        page.pop_dialog()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Row(
            [
                ft.Icon(ft.Icons.AUTORENEW, color=C_PRIMARY, size=20),
                ft.Text("Renew MinIO credentials", color=C_TEXT, size=15,
                        weight=ft.FontWeight.W_600),
            ],
            spacing=8,
        ),
        content=ft.Column(
            [
                ft.Text(f"User: {usuario}", color=C_TEXT_DIM, size=12),
                ft.Text(f"Profile: {perfil}", color=C_TEXT_DIM, size=12),
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
    page.show_dialog(dlg)
    page.update()
