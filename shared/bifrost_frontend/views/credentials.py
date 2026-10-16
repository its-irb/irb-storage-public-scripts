"""Vista de renovación de credenciales STS (compartida por mount y transfer)."""

from __future__ import annotations

import time
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import STS_AUTO_RENEWAL_DAYS

from ..components import btn_secondary, build_header, card, section_title
from ..theme import (
    C_ACCENT, C_BG, C_BORDER, C_ERROR, C_PRIMARY, C_SURFACE2, C_TEXT, C_TEXT_DIM,
    C_WARNING, FONT_MONO, MONO_FALLBACK,
)

def build_credentials_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    credenciales_ldap: dict,
    on_continue: Callable,
    extra_config: dict | None = None,
    duracion_dias: int | None = None,
    on_back: Callable | None = None,
    *,
    no_ldap: bool,
    is_web: bool = False,
    done_message: str,
    write_log: Callable[[str], None] | None = None,
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
    back_btn    = btn_secondary("← Back to login", width=200)
    back_btn.visible   = False
    back_btn.on_click  = lambda e: on_back() if on_back else None
    status_text = ft.Text("Renewing credentials...", size=13, color=C_TEXT_DIM,
                           font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK)

    def log(msg: str, color: str = C_TEXT):
        print(msg.rstrip())
        if write_log:
            write_log(msg)
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK, selectable=True)
            )
        backend.ui_call(page, _add)

    def _do_renew():
        duracion_segundos = (duracion_dias or STS_AUTO_RENEWAL_DAYS) * 86400

        info = backend.get_session_info(perfil_rclone)
        if info is None:
            log("⚠️  No credentials found for this profile.", C_WARNING)
        elif info.remaining is None:
            log("⚠️  Could not read expiry from current token.", C_WARNING)
        else:
            log(f"⚠️  Current credentials expire in: {info.remaining_text()}", C_WARNING)

        log(f"\n🔄 Requesting new STS credentials ({duracion_dias or STS_AUTO_RENEWAL_DAYS} days)...", C_PRIMARY)
        log(f"   Profile  : {perfil_rclone}", C_TEXT_DIM)
        log(f"   Endpoint : {endpoint}", C_TEXT_DIM)
        log(f"   User     : {credenciales_ldap['usuario']}", C_TEXT_DIM)

        try:
            creds = backend.get_credentials(
                endpoint,
                credenciales_ldap["usuario"],
                credenciales_ldap["password"],
                duracion_segundos,
            )
        except Exception as exc:
            log(f"\n❌ Cannot connect to MinIO: {exc}", C_ERROR)
            def _show_net_err():
                progress.visible  = False
                status_text.value = "❌ Connection error."
                status_text.color = C_ERROR
                if on_back:
                    back_btn.visible = True
                page.update()
            backend.ui_call(page, _show_net_err)
            return

        if creds is None:
            if on_back:
                log("\n❌ Wrong username or password. Please try again.", C_ERROR)
            else:
                log("\n❌ Failed to obtain credentials. Check your password or contact ITS.", C_ERROR)
            def _show_err():
                progress.visible  = False
                status_text.value = "❌ Wrong username or password." if on_back else "❌ Renewal failed."
                status_text.color = C_ERROR
                if on_back:
                    back_btn.visible = True
                page.update()
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

        new_info = backend.get_session_info(perfil_rclone)
        if new_info and new_info.remaining is not None:
            log(f"   New credentials expire in: {new_info.remaining_text()}", C_ACCENT)
        else:
            log("⚠️  Could not verify the new token in rclone config.", C_WARNING)

        log(f"\n✅ Done. {done_message}", C_ACCENT)

        def _finish():
            progress.visible  = False
            status_text.value = "✓ Credentials renewed. Loading..."
            status_text.color = C_ACCENT

        backend.ui_call(page, _finish)
        time.sleep(1.2)
        backend.ui_call(page, on_continue)

    content = ft.Column(
        [
            build_header(subtitle="S3 Credentials — Auto Renewal", IS_WEB=is_web, no_ldap=no_ldap),
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
                                    ft.Container(height=8),
                                    back_btn,
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
