"""Tarjeta de un servidor MinIO en la pantalla de montaje: muestra su estado y avisa de lo que pulsa el usuario."""

from __future__ import annotations

from typing import Callable

import flet as ft

from bifrost_backend.common.constants import STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *


class ServerCard:
    """Nombre, dirección, caducidad de las credenciales, dónde está montado y los botones Mount (Open si ya está
    montado), Unmount y Renew credentials. Doble clic = Mount. No llama al backend: `show` pinta el estado que le
    dan y los callbacks avisan de lo que se pulsa. Quien la usa llama a `page.update()`.
    """

    def __init__(self, name: str, endpoint: str, *, on_mount: Callable[[], None], on_unmount: Callable[[], None],
                 on_renew: Callable[[], None]) -> None:
        self._expiry = ft.Text("", size=11, weight=ft.FontWeight.W_600)
        self._expiry_box = ft.Container(content=self._expiry, border_radius=20,
                                        padding=ft.Padding.symmetric(horizontal=10, vertical=4))
        self._icon = ft.Icon(ft.Icons.STORAGE, size=20)
        self._progress = ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY, visible=False)
        self._state = ft.Text("", size=12, selectable=True, font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK)
        self._mount_btn = btn_primary("⊞  Mount", on_click=lambda e: on_mount())
        self._unmount_btn = btn_secondary("⊠  Unmount", on_click=lambda e: on_unmount())
        self._renew_btn = btn_secondary("🔑 Renew credentials", on_click=lambda e: on_renew())

        self._box = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            self._icon,
                            ft.Column(
                                [
                                    ft.Text(name, size=14, weight=ft.FontWeight.W_600, color=C_TEXT),
                                    ft.Text(endpoint, size=11, color=C_TEXT_DIM, font_family=FONT_MONO,
                                            font_family_fallback=MONO_FALLBACK),
                                ],
                                spacing=2, tight=True, expand=True,
                            ),
                            self._expiry_box,
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=12,
                    ),
                    ft.Row([self._progress, self._state], spacing=8,
                           vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    ft.Row([self._mount_btn, self._unmount_btn, ft.Container(expand=True), self._renew_btn],
                           spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ],
                spacing=12,
                tight=True,
            ),
            bgcolor=C_SURFACE,
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=16, vertical=14),
        )
        self.control = ft.GestureDetector(content=self._box, on_double_tap=lambda e: on_mount())

    def show(self, *, mount_point: str | None, session, status: str = "", status_color: str = C_TEXT_DIM,
             busy: bool = False) -> None:
        """Pinta el estado. `mount_point`: dónde está montado (None si no lo está). `session`: el `SessionInfo` del
        perfil (`backend.get_session_info`), o None si no tiene credenciales. `status`: un texto en lugar del
        estado ("Mounting...", "✅ Mounted!"). `busy`: montando o desmontando; los botones se desactivan."""
        mounted = mount_point is not None
        self._expiry.value, expiry_color = _expiry_text(session)
        self._expiry.color = expiry_color
        self._expiry_box.bgcolor = f"{expiry_color}22"
        self._expiry_box.border = ft.Border.all(1, f"{expiry_color}55")

        if status:
            self._state.value, self._state.color = status, status_color
        elif mounted:
            self._state.value, self._state.color = f"Mounted at {mount_point}", C_ACCENT
        else:
            self._state.value, self._state.color = "Not mounted", C_TEXT_DIM
        self._progress.visible = busy

        self._mount_btn.content.value = "📂  Open" if mounted else "⊞  Mount"
        self._unmount_btn.visible = mounted
        for button in (self._mount_btn, self._unmount_btn, self._renew_btn):
            button.disabled = busy

        self._icon.color = C_ACCENT if mounted else C_PRIMARY
        self._box.border = ft.Border.all(2 if mounted else 1, C_ACCENT if mounted else C_BORDER)


def _expiry_text(session) -> tuple[str, str]:
    """El texto y el color de la caducidad de las credenciales (rojo con menos de 1 día, ámbar hasta 3)."""
    if session is None:
        return "🔑 No credentials yet", C_TEXT_DIM
    if session.remaining is None:
        return "🔑 Credentials: unknown expiry", C_TEXT_DIM
    if session.expired:
        return "🔑 Credentials expired", C_ERROR
    dias = session.remaining.days
    color = C_ERROR if dias < 1 else C_WARNING if dias <= STS_RENEWAL_THRESHOLD_DAYS else C_ACCENT
    return f"🔑 Credentials expire in {session.remaining_text()}", color
