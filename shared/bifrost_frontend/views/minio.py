"""Vista de selección de servidor MinIO (compartida por mount y transfer)."""

from __future__ import annotations

from typing import Callable

import flet as ft
from bifrost_backend import backend

from ..components import btn_primary, build_header, card, section_title
from ..theme import (
    C_BORDER, C_PRIMARY, C_SURFACE, C_SURFACE2, C_TEXT, C_TEXT_DIM, FONT_MONO,
    MONO_FALLBACK,
)

def build_minio_content(
    page: ft.Page,
    on_continue: Callable,
    *,
    no_ldap: bool,
    is_web: bool = False,
) -> ft.Control:
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
                            ft.Text(srv_name, size=14, weight=ft.FontWeight.W_600, color=C_TEXT),
                            ft.Text(info["endpoint"], size=11, color=C_TEXT_DIM, font_family=FONT_MONO,
                                    font_family_fallback=MONO_FALLBACK),
                        ],
                        spacing=2, tight=True, expand=True,
                    ),
                    ft.Icon(ft.Icons.STORAGE, color=C_PRIMARY if is_sel else C_BORDER, size=20),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=12,
            ),
            bgcolor=C_SURFACE2 if is_sel else C_SURFACE,
            border=ft.Border.all(2 if is_sel else 1, C_PRIMARY if is_sel else C_BORDER),
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
            build_header(subtitle="MinIO Server", IS_WEB=is_web, no_ldap=no_ldap),
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
