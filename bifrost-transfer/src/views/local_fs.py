"""Navegador del filesystem local del servidor (modo web)."""

from __future__ import annotations

import pathlib
import threading
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_frontend.frontend import *


# ============================================================================
# COMPONENTE: NAVEGADOR DE FICHEROS LOCAL (para modo web)
#
# Lee el filesystem del servidor donde corre BIFROST.
# Usa os.scandir — no necesita rclone.
# Soporta select_mode = "folder" | "file" | "both"
# ============================================================================

def build_local_fs_browser(
    page: ft.Page,
    on_select: Callable[[str], None],
    select_mode: str = "folder",   # "folder" | "file" | "both"
    start_path: str | None = None,
) -> tuple[ft.Column, Callable]:
    """
    Navegador de ficheros del servidor con breadcrumb.

    Returns:
        (widget, refresh_fn) — llama a refresh_fn() después de añadir
        el widget al árbol para arrancar la carga inicial.
    """

    root_path = pathlib.Path(start_path or pathlib.Path.home())
    nav_state = {"current": root_path}

    breadcrumb_row = ft.Row(spacing=2, wrap=True,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER)
    entries_col    = ft.Column(spacing=4, tight=True)
    loading_row    = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8, visible=False,
    )
    error_text = ft.Text("", color=C_ERROR, size=11, visible=False)

    def _rebuild_breadcrumb(path: pathlib.Path):
        breadcrumb_row.controls.clear()
        parts = path.parts
        accumulated = pathlib.Path(parts[0])
        breadcrumb_row.controls.append(
            ft.TextButton(
                content=ft.Text("/"),
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                ),
                on_click=lambda e, p=accumulated: _navigate(p),
            )
        )
        for i, part in enumerate(parts[1:], start=1):
            accumulated = accumulated / part
            acc_snap = accumulated
            is_last  = (i == len(parts) - 1)
            breadcrumb_row.controls.append(ft.Text("/", size=12, color=C_TEXT_DIM))
            if is_last:
                breadcrumb_row.controls.append(
                    ft.Text(part, size=12, color=C_TEXT, weight=ft.FontWeight.W_600)
                )
            else:
                breadcrumb_row.controls.append(
                    ft.TextButton(
                        content=ft.Text(part),
                        style=ft.ButtonStyle(
                            color=C_PRIMARY,
                            padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                        ),
                        on_click=lambda e, p=acc_snap: _navigate(p),
                    )
                )

    def _navigate(path: pathlib.Path):
        print(f"[local-fs] navigate → {path}")
        nav_state["current"] = path
        # Auto-select the current folder when browsing in folder/both mode,
        # so the user can just navigate and press Confirm without needing the ✓ icon.
        if select_mode in ("folder", "both"):
            print(f"[local-fs] auto-select folder (mode={select_mode!r}) → {path}")
            on_select(str(path))
        loading_row.visible  = True
        error_text.visible   = False
        entries_col.controls.clear()
        _rebuild_breadcrumb(path)
        page.update()

        def _load():
            try:
                raw = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
            except PermissionError:
                print(f"[local-fs] PERMISSION DENIED: {path}")
                def _perm():
                    loading_row.visible = False
                    error_text.value    = f"Permission denied: {path}"
                    error_text.visible  = True
                    page.update()
                backend.ui_call(page, _perm)
                return
            except Exception as ex:
                print(f"[local-fs] ERROR listing {path}: {ex}")
                def _err(ex_val=ex):
                    loading_row.visible = False
                    error_text.value    = f"Error: {ex_val}"
                    error_text.visible  = True
                    page.update()
                backend.ui_call(page, _err)
                return

            dirs  = [p for p in raw if p.is_dir()  and not p.name.startswith(".")]
            files = [p for p in raw if p.is_file() and not p.name.startswith(".")]
            print(f"[local-fs] listed {path} → {len(dirs)} dirs, {len(files)} files")

            def _show():
                loading_row.visible = False
                entries_col.controls.clear()

                # Botón ".." para subir (si no estamos en root_path)
                if path != root_path and path.parent >= root_path:
                    parent_snap = path.parent
                    entries_col.controls.append(
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.ARROW_UPWARD, color=C_TEXT_DIM, size=15),
                                    ft.Text("..", size=12, color=C_TEXT_DIM, expand=True),
                                ],
                                spacing=8,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            bgcolor=C_BG,
                            border=ft.Border.all(1, C_BORDER),
                            border_radius=6,
                            padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                            on_click=lambda e, p=parent_snap: _navigate(p),
                            ink=True,
                        )
                    )

                if not dirs and not files:
                    entries_col.controls.append(
                        ft.Text("(empty)", size=11, color=C_TEXT_DIM, italic=True)
                    )

                for entry in dirs + files:
                    is_dir   = entry.is_dir()
                    ep_snap  = entry

                    # ¿Es seleccionable como destino final?
                    selectable = (
                        (select_mode == "folder" and is_dir) or
                        (select_mode == "file"   and not is_dir) or
                        (select_mode == "both")
                    )
                    # Carpetas siempre navegables aunque no sean el modo seleccionado
                    navigable = is_dir

                    def _make_click(ep=ep_snap, nav=navigable, sel=selectable):
                        def _click(e):
                            if nav:
                                _navigate(ep)
                            if sel and not nav:
                                print(f"[local-fs] selected (click) → {ep}")
                                on_select(str(ep))
                        return _click

                    def _select_via_icon(e, ep=ep_snap):
                        print(f"[local-fs] selected (✓ button) → {ep}")
                        on_select(str(ep))

                    # Botón "Select" solo si es seleccionable Y no vamos a navegar
                    select_icon = ft.IconButton(
                        icon=ft.Icons.CHECK_CIRCLE_OUTLINE,
                        icon_color=C_ACCENT,
                        icon_size=16,
                        tooltip="Select this folder" if is_dir else "Select this file",
                        on_click=_select_via_icon,
                        visible=selectable,
                    ) if selectable else ft.Container(width=24)

                    row = ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(
                                    ft.Icons.FOLDER_OUTLINED if is_dir
                                    else ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                    color=C_WARNING if is_dir else C_TEXT_DIM,
                                    size=16,
                                ),
                                ft.Text(
                                    entry.name,
                                    size=12,
                                    color=C_TEXT if is_dir else C_TEXT_DIM,
                                    expand=True,
                                ),
                                select_icon,
                                ft.Icon(
                                    ft.Icons.CHEVRON_RIGHT,
                                    color=C_TEXT_DIM, size=14,
                                ) if is_dir else ft.Container(width=14),
                            ],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        bgcolor=C_SURFACE2 if is_dir else C_BG,
                        border=ft.Border.all(1, C_BORDER),
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                        on_click=_make_click() if navigable else (
                            _select_via_icon if selectable else None
                        ),
                        ink=navigable or selectable,
                    )
                    entries_col.controls.append(row)

                page.update()

            backend.ui_call(page, _show)

        backend.safe_thread(page, _load).start()

    browser_widget = ft.Column(
        [
            ft.Container(
                content=breadcrumb_row,
                bgcolor=C_SURFACE2,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            ),
            loading_row,
            error_text,
            ft.Container(
                content=ft.Column(
                    [entries_col],
                    scroll=ft.ScrollMode.AUTO,
                    spacing=0,
                ),
                bgcolor=C_SURFACE,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=260,
                padding=ft.Padding.all(8),
            ),
        ],
        spacing=6,
        tight=True,
    )

    return browser_widget, lambda: _navigate(root_path), _navigate


def show_local_fs_modal(
    page: ft.Page,
    on_select: Callable[[str], None],
    select_mode: str = "folder",
) -> None:
    """
    Abre un modal con el navegador de ficheros local.
    Al seleccionar, cierra el modal y llama on_select(path).
    """
    selected_label = ft.Text(
        "No selection yet", size=11, color=C_TEXT_DIM, italic=True
    )

    def _on_pick(path: str):
        selected_label.value  = path
        selected_label.color  = C_ACCENT
        selected_label.italic = False
        page.update()

    browser_widget, refresh_fn, navigate_to = build_local_fs_browser(
        page,
        on_select=_on_pick,
        select_mode=select_mode,
    )

    def confirm(e):
        path = selected_label.value
        if path and path != "No selection yet":
            page.pop_dialog()
            on_select(path)
        else:
            selected_label.value  = "⚠ Select something first"
            selected_label.color  = C_WARNING
            selected_label.italic = True
            page.update()

    def cancel(e):
        page.pop_dialog()

    title_text = {
        "folder": "Select Folder",
        "file":   "Select File",
        "both":   "Select File or Folder",
    }.get(select_mode, "Browse")

    # ── Shortcuts ──────────────────────────────────────────────────
    _shortcut_defs = [
        ("~ Home",   ft.Icons.HOME_OUTLINED,          pathlib.Path.home()),
        ("/data",    ft.Icons.STORAGE_OUTLINED,        pathlib.Path("/data")),
        ("/scratch", ft.Icons.FOLDER_SPECIAL_OUTLINED, pathlib.Path("/scratch")),
    ]

    def _make_shortcut(label: str, icon, dest: pathlib.Path) -> ft.TextButton:
        return ft.TextButton(
            content=ft.Row(
                [
                    ft.Icon(icon, size=13, color=C_PRIMARY),
                    ft.Text(label, size=11, color=C_PRIMARY),
                ],
                spacing=4,
                tight=True,
            ),
            style=ft.ButtonStyle(
                padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                bgcolor={ft.ControlState.HOVERED: f"{C_PRIMARY}22"},
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=lambda e, p=dest: navigate_to(p),
        )

    shortcuts_row = ft.Row(
        [_make_shortcut(lbl, ico, dest) for lbl, ico, dest in _shortcut_defs],
        spacing=4,
        wrap=True,
    )

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text(title_text, color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
        content=ft.Column(
            [
                shortcuts_row,
                browser_widget,
                ft.Container(height=8),
                ft.Row(
                    [
                        ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=14),
                        selected_label,
                    ],
                    spacing=6,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=6,
            tight=True,
            width=520,
        ),
        actions=[
            btn_secondary("Cancel",  on_click=cancel),
            btn_primary("Confirm selection", on_click=confirm),
        ],
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    #page.overlay.append(dlg)
    #dlg.open = True
    page.show_dialog(dlg)
    page.update()

    # Arrancar carga inicial después de que el modal esté en el árbol.
    # Route through backend.ui_call so the control mutations run on the asyncio event
    # loop and cannot race with ObjectPatch.from_diff (same fix as main browser).
    threading.Timer(0.1, lambda: backend.ui_call(page, refresh_fn)).start()
