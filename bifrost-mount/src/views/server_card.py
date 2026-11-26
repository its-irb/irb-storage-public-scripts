"""Tarjeta de un servidor MinIO en la pantalla de montaje: muestra su estado y avisa de lo que pulsa el usuario."""

from __future__ import annotations

from typing import Callable

import flet as ft

from bifrost_frontend.frontend import *


class ServerCard:
    """Nombre, dirección, caducidad de las credenciales, dónde está montado y los botones Mount (Open si ya está
    montado), Unmount y Renew credentials. Doble clic = Mount. No llama al backend: `show` pinta el estado que le
    dan y los callbacks avisan de lo que se pulsa. Quien la usa llama a `page.update()`.

    Arriba, el servidor y la caducidad de sus credenciales; abajo, separado por una línea, su estado y las acciones.
    """

    def __init__(self, name: str, endpoint: str, *, on_mount: Callable[[], None], on_unmount: Callable[[], None],
                 on_renew: Callable[[], None]) -> None:
        self._mounted = False
        self._hovered = False

        self._expiry_icon = ft.Icon(ft.Icons.KEY, size=13)
        self._expiry = ft.Text("", size=11, weight=ft.FontWeight.W_600)
        self._expiry_box = ft.Container(content=ft.Row([self._expiry_icon, self._expiry], spacing=6, tight=True),
                                        border_radius=20, padding=ft.Padding.symmetric(horizontal=10, vertical=5),
                                        tooltip="MinIO credentials for this server")
        self._tile = icon_tile(ft.Icons.STORAGE_ROUNDED, C_PRIMARY)
        self._progress = ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY, visible=False)
        self._dot = ft.Icon(ft.Icons.CIRCLE, size=10)
        self._state = ft.Text("", size=12, selectable=True, font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK,
                              max_lines=1, overflow=ft.TextOverflow.ELLIPSIS)
        self._mount_btn = btn_primary("Mount", icon=ft.Icons.LINK, on_click=lambda e: on_mount())
        self._unmount_btn = btn_secondary("Unmount", icon=ft.Icons.EJECT, on_click=lambda e: on_unmount())
        self._renew_btn = btn_secondary("Renew credentials", icon=ft.Icons.KEY, on_click=lambda e: on_renew())

        self._box = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            self._tile,
                            ft.Column(
                                [
                                    ft.Text(name, size=15, weight=ft.FontWeight.W_600, color=C_TEXT),
                                    ft.Text(endpoint, size=11, color=C_TEXT_DIM, font_family=FONT_MONO,
                                            font_family_fallback=MONO_FALLBACK, selectable=True),
                                ],
                                spacing=3, tight=True, expand=True,
                            ),
                            self._expiry_box,
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=14,
                    ),
                    ft.Container(height=1, bgcolor=C_BORDER),
                    ft.Row(
                        [
                            ft.Row([self._progress, self._dot, self._state], spacing=8, expand=True,
                                   vertical_alignment=ft.CrossAxisAlignment.CENTER),
                            self._renew_btn,
                            self._unmount_btn,
                            self._mount_btn,
                        ],
                        spacing=8,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                ],
                spacing=14,
                tight=True,
            ),
            bgcolor=C_SURFACE,
            border_radius=10,
            padding=ft.Padding.symmetric(horizontal=18, vertical=16),
            on_hover=self._on_hover,
            animate=ft.Animation(150, ft.AnimationCurve.EASE_OUT),
        )
        self.control = ft.GestureDetector(content=self._box, on_double_tap=lambda e: on_mount(),
                                          mouse_cursor=ft.MouseCursor.CLICK)

    def show(self, *, mount_point: str | None, session, status: str = "", status_color: str = C_TEXT_DIM,
             busy: bool = False) -> None:
        """Pinta el estado. `mount_point`: dónde está montado (None si no lo está). `session`: el `SessionInfo` del
        perfil (`backend.get_session_info`), o None si no tiene credenciales. `status`: un texto en lugar del
        estado ("Mounting...", "Mounted!"). `busy`: montando o desmontando; los botones se desactivan."""
        mounted = self._mounted = mount_point is not None
        self._expiry.value, expiry_color = expiry_label(session)
        self._expiry.color = self._expiry_icon.color = expiry_color
        self._expiry_box.bgcolor = tint(expiry_color, 0.13)
        self._expiry_box.border = ft.Border.all(1, tint(expiry_color, 0.33))

        if status:
            self._state.value, self._state.color = status, status_color
        elif mounted:
            self._state.value, self._state.color = f"Mounted at {mount_point}", C_ACCENT
        else:
            self._state.value, self._state.color = "Not mounted", C_TEXT_DIM
        self._progress.visible = busy
        self._dot.visible = not busy
        self._dot.color = self._state.color

        self._mount_btn.content.value = "Open" if mounted else "Mount"
        self._mount_btn.icon = ft.Icons.FOLDER_OPEN if mounted else ft.Icons.LINK
        self._unmount_btn.visible = mounted
        for button in (self._mount_btn, self._unmount_btn, self._renew_btn):
            button.disabled = busy

        color = C_ACCENT if mounted else C_PRIMARY
        self._tile.bgcolor = tint(color, 0.13)
        self._tile.content.color = color
        self._paint_border()

    def _paint_border(self) -> None:
        if self._mounted:
            color = tint(C_ACCENT, 0.85 if self._hovered else 0.6)
        else:
            color = C_TEXT_DIM if self._hovered else C_BORDER
        self._box.border = ft.Border.all(1, color)

    def _on_hover(self, e) -> None:
        self._hovered = e.data in (True, "true")
        self._paint_border()
        self._box.update()

