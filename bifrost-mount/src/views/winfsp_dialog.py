"""Instalación de WinFsp (Windows): sin él no se puede montar."""

from __future__ import annotations

import logging
from typing import Callable

import flet as ft

from bifrost_backend import backend
from bifrost_frontend.frontend import *

log = logging.getLogger("bifrost.mount")


def prompt_install_winfsp(page: ft.Page, on_success: Callable[[], None]) -> None:
    """Ofrece descargar e instalar WinFsp; si se instala, on_success() reintenta el montaje."""
    def _install(_e):
        page.pop_dialog()
        progress_text = ft.Text("Starting...", color=C_TEXT_DIM, size=13)
        page.show_dialog(ft.AlertDialog(
            modal=True,
            title=ft.Text("Installing WinFsp", color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
            content=ft.Column([ft.ProgressRing(), progress_text], tight=True,
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        ))
        page.update()

        def _on_progress(msg: str) -> None:
            def _upd():
                progress_text.value = msg
                page.update()
            backend.ui_call(page, _upd)

        def _worker():
            try:
                installed, error = backend.install_winfsp_windows(on_progress=_on_progress), None
            except Exception as ex:
                log.warning("WinFsp install failed: %s", ex)
                installed, error = False, ex

            def _done():
                page.pop_dialog()
                if error is not None:
                    show_dialog(page, "Error installing WinFsp",
                                f"{error}\n\nYou can install it manually from https://winfsp.dev", C_ERROR)
                elif installed:
                    log.info("WinFsp installed")
                    on_success()
                else:
                    log.info("WinFsp install cancelled")
                    show_dialog(page, "Installation cancelled",
                                "The WinFsp installation was cancelled. You can retry the mount whenever "
                                "you want.", C_WARNING)
            backend.ui_call(page, _done)

        backend.safe_thread(page, _worker).start()

    def _cancel(_e):
        page.pop_dialog()
        show_dialog(page, "WinFsp not detected",
                    "WinFsp is required to mount MinIO folders on Windows. Download it from https://winfsp.dev",
                    C_ERROR)

    show_dialog(page, "WinFsp is not installed",
                "WinFsp is required to mount MinIO folders on Windows.\n\n"
                "Do you want to download and install the latest version now? "
                "Administrator permissions will be required.",
                C_WARNING,
                actions=[btn_secondary("Cancel", on_click=_cancel), btn_primary("Install", on_click=_install)])
