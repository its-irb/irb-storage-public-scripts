"""Vista de selección de servidor MinIO (la usa bifrost-transfer; bifrost-mount tiene su propia pantalla de servidores)."""

from __future__ import annotations

from typing import Callable

import flet as ft
from bifrost_backend import backend

from ..components import btn_primary, build_header, expiry_chip, icon_tile, nav_bar, section_title
from ..theme import C_BORDER, C_PRIMARY, C_SURFACE, C_TEXT, C_TEXT_DIM, FONT_MONO, MONO_FALLBACK, tint


def build_minio_content(
    page: ft.Page,
    on_continue: Callable,
    *,
    no_ldap: bool,
    is_web: bool = False,
    on_back: Callable | None = None,
    usuario: str | None = None,
) -> ft.Control:
    """Una tarjeta por servidor, con la caducidad de sus credenciales. Clic = elegir, doble clic = continuar.
    `on_back()` vuelve al login; `usuario` se muestra arriba a la derecha."""
    servers  = list(backend.MINIO_SERVERS.keys())
    selected = {"current": servers[0]}

    server_cards: dict[str, ft.Container] = {}
    tiles: dict[str, ft.Container] = {}

    def _paint(srv: str) -> None:
        is_sel = srv == selected["current"]
        server_cards[srv].bgcolor = tint(C_PRIMARY, 0.06) if is_sel else C_SURFACE
        server_cards[srv].border  = ft.Border.all(1, C_PRIMARY if is_sel else C_BORDER)
        tiles[srv].bgcolor = tint(C_PRIMARY if is_sel else C_TEXT_DIM, 0.13)
        tiles[srv].content.color = C_PRIMARY if is_sel else C_TEXT_DIM

    def _update_card_styles():
        for srv in server_cards:
            _paint(srv)
        page.update()

    def on_radio_change_and_select(srv_name: str):
        rg.value = srv_name
        selected["current"] = srv_name
        _update_card_styles()

    def _eleccion(srv_name: str) -> dict:
        return {
            "servidor": srv_name,
            "perfil":   backend.MINIO_SERVERS[srv_name]["IRB"]["profile"],
            "endpoint": backend.MINIO_SERVERS[srv_name]["IRB"]["endpoint"],
        }

    def make_server_card(srv_name: str) -> ft.GestureDetector:
        info = backend.MINIO_SERVERS[srv_name]["IRB"]
        tiles[srv_name] = icon_tile(ft.Icons.STORAGE_ROUNDED, C_PRIMARY)
        c = ft.Container(
            content=ft.Row(
                [
                    ft.Radio(value=srv_name, active_color=C_PRIMARY),
                    tiles[srv_name],
                    ft.Column(
                        [
                            ft.Text(srv_name, size=15, weight=ft.FontWeight.W_600, color=C_TEXT),
                            ft.Text(info["endpoint"], size=11, color=C_TEXT_DIM, font_family=FONT_MONO,
                                    font_family_fallback=MONO_FALLBACK),
                        ],
                        spacing=3, tight=True, expand=True,
                    ),
                    expiry_chip(backend.get_session_info(info["profile"])),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=14,
            ),
            border_radius=10,
            padding=ft.Padding.only(left=8, right=18, top=14, bottom=14),
        )
        server_cards[srv_name] = c
        _paint(srv_name)
        return ft.GestureDetector(
            content=c,
            on_tap=lambda e, s=srv_name: on_radio_change_and_select(s),
            on_double_tap=lambda e, s=srv_name: on_continue(_eleccion(s)),
            mouse_cursor=ft.MouseCursor.CLICK,
        )

    rg = ft.RadioGroup(
        content=ft.Column([make_server_card(s) for s in servers], spacing=12),
        value=servers[0],
    )

    def on_radio_change(e):
        selected["current"] = rg.value
        _update_card_styles()

    rg.on_change = on_radio_change

    content = ft.Column(
        [
            build_header(subtitle="MinIO Server", IS_WEB=is_web, no_ldap=no_ldap, page=page),
            ft.Container(
                content=ft.Column(
                    [
                        nav_bar("Back to login", on_back, usuario=usuario),
                        ft.Container(height=12),
                        section_title("SELECT DESTINATION SERVER"),
                        ft.Container(height=6),
                        ft.Text("Choose the MinIO server you want to copy to. Double-click a server to continue.",
                                size=12, color=C_TEXT_DIM),
                        ft.Container(height=16),
                        rg,
                        ft.Container(height=24),
                        ft.Row(
                            [btn_primary("Continue", icon=ft.Icons.ARROW_FORWARD,
                                         on_click=lambda e: on_continue(_eleccion(selected["current"])))],
                            alignment=ft.MainAxisAlignment.END,
                        ),
                    ],
                    spacing=0,
                ),
                expand=True,
                padding=ft.Padding.only(left=24, right=24, top=0, bottom=16),
            ),
        ],
        expand=True,
        spacing=0,
    )

    return content
