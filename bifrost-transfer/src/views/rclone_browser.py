"""Navegador de buckets y carpetas rclone para el destino de la copia."""

from __future__ import annotations

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_frontend.frontend import *

from meta_fields import WORM_BUCKET_SUFFIX, WORM_FACILITY_DATA_SUBFOLDERS, WORM_ROOT_PREFIXES, build_lab_filter_widget


# ============================================================================
# COMPONENTE: NAVEGADOR DE BUCKETS/CARPETAS RCLONE
#
# FIX: la carga inicial NO se lanza aquí dentro sino que se devuelve como
# callable (dest_browser_refresh) para que _build_copy_content la dispare
# con un Timer de 50ms, después de que show_screen() haya añadido todos los
# controles al árbol de Flet y page.update() haya sido llamado.
# Esto evita el error:
#   AssertionError: Text Control must be added to the page first
# ============================================================================

def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str, bool], None],
    initial_path: str = "",
    lab_filter_enabled: bool = False,
    endpoint: str | None = None,
    allow_mkdir: bool = True,
    show_files: bool = False,
    worm_defaults_enabled: bool = False,
) -> tuple[ft.Column, Callable]:
    """
    Navegador interactivo de carpetas rclone con breadcrumb.
    La creación de carpetas es VIRTUAL — solo actualiza el path de destino,
    no llama a rclone mkdir. S3 crea el prefijo automáticamente al copiar.

    Returns:
        (widget, refresh_fn) — llama a refresh_fn() una vez que el widget
        esté en la página para arrancar la carga inicial.
    """
    nav_state = {"current_path": "", "timeout": 15, "selected_file": None}
    file_row_refs: dict[str, ft.Container] = {}
    filter_state = {"acronym": None}
    bucket_cache: dict = {"list": None, "tags": None}

    if lab_filter_enabled:
        def _on_lab_select(acronym: str | None) -> None:
            previous = filter_state["acronym"]
            if acronym is None:
                print(f"[browser] lab filter cleared (was {previous!r}) → showing all buckets")
            else:
                print(f"[browser] lab filter → {acronym!r} (was {previous!r})")
            filter_state["acronym"] = acronym
            _navigate("")

        filter_widget, _filter_clear_fn = build_lab_filter_widget(page, _on_lab_select)
        filter_row = ft.Container(
            content=filter_widget,
            visible=True,
            padding=ft.Padding.only(bottom=4),
        )
    else:
        filter_row = ft.Container(visible=False)

    breadcrumb_row = ft.Row(spacing=2, wrap=True,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER)
    folder_col     = ft.Column(spacing=4, tight=True)
    loading_row    = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8,
        visible=False,
    )
    error_text = ft.Text("", color=C_ERROR, size=11, visible=False)

    # ── Crear nueva carpeta (virtual) ─────────────────────────────────────
    new_folder_tf = ft.TextField(
        hint_text="new-folder-name",
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        hint_style=ft.TextStyle(color=C_TEXT_DIM),
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
        text_size=12,
        expand=True,
    )
    mkdir_status = ft.Text("", size=11, color=C_TEXT_DIM, visible=False)
    mkdir_btn    = ft.IconButton(
        icon=ft.Icons.CREATE_NEW_FOLDER_OUTLINED,
        icon_color=C_ACCENT,
        icon_size=18,
        tooltip="Add folder to destination path (virtual — created on copy)",
    )

    def _style_file_row(container: ft.Container, selected: bool) -> None:
        if selected:
            container.bgcolor = f"{C_PRIMARY}22"
            container.border  = ft.Border.all(2, C_PRIMARY)
        else:
            container.bgcolor = C_SURFACE2
            container.border  = ft.Border.all(1, C_BORDER)

    def _toggle_file_selection(path: str) -> None:
        previous = nav_state["selected_file"]
        if previous is not None and previous in file_row_refs:
            _style_file_row(file_row_refs[previous], False)

        if previous == path:
            nav_state["selected_file"] = None
            on_select(nav_state["current_path"], False)
        else:
            nav_state["selected_file"] = path
            if path in file_row_refs:
                _style_file_row(file_row_refs[path], True)
            on_select(path, True)

        page.update()

    def _rebuild_breadcrumb():
        breadcrumb_row.controls.clear()
        breadcrumb_row.controls.append(
            ft.TextButton(
                content=ft.Text(f"{perfil_rclone}:"),
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                ),
                on_click=lambda e: _navigate(""),
            )
        )
        parts = [p for p in nav_state["current_path"].split("/") if p]
        accumulated = ""
        for i, part in enumerate(parts):
            accumulated = f"{accumulated}/{part}" if accumulated else part
            path_snap   = accumulated
            is_last     = (i == len(parts) - 1)
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
                        on_click=lambda e, p=path_snap: _navigate(p),
                    )
                )

    def _navigate(path: str):
        print(f"[browser] navigate → perfil={perfil_rclone!r} path={path!r}")
        nav_state["current_path"]  = path
        nav_state["selected_file"] = None
        file_row_refs.clear()
        on_select(path, False)

        loading_row.visible    = True
        error_text.visible     = False
        folder_col.controls.clear()
        filter_row.visible     = lab_filter_enabled and not path
        mkdir_section.visible  = allow_mkdir and bool(path)
        _rebuild_breadcrumb()
        page.update()

        def _load():
            try:
                if not path and bucket_cache["list"] is not None:
                    entries = list(bucket_cache["list"])
                else:
                    if show_files:
                        entries = backend.rclone_lsjson(perfil_rclone, path, timeout=nav_state["timeout"])
                        print(f"[browser] rclone lsjson path={path!r} → {len(entries)} entries: {entries}")
                    else:
                        folders = backend.rclone_lsd(perfil_rclone, path, timeout=nav_state["timeout"])
                        print(f"[browser] rclone lsd path={path!r} → {len(folders)} folders: {folders}")
                        entries = [{"name": f, "is_dir": True} for f in folders]
                    if not path:
                        bucket_cache["list"] = list(entries)
                        bucket_cache["tags"] = None

                if worm_defaults_enabled:
                    path_parts = [p for p in path.split("/") if p]
                    default_names: list[str] | None = None
                    if len(path_parts) == 1 and path_parts[0].endswith(WORM_BUCKET_SUFFIX):
                        default_names = WORM_ROOT_PREFIXES
                    elif (
                        len(path_parts) == 2
                        and path_parts[0].endswith(WORM_BUCKET_SUFFIX)
                        and path_parts[1] == "facility_data"
                    ):
                        default_names = WORM_FACILITY_DATA_SUBFOLDERS
                    if default_names:
                        by_name = {e["name"]: e for e in entries}
                        missing = [n for n in default_names if n not in by_name]
                        if missing:
                            print(f"[browser] worm defaults path={path!r} → adding missing virtual folders: {missing}")
                        ordered = [by_name.pop(n, {"name": n, "is_dir": True}) for n in default_names]
                        rest = [e for e in entries if e["name"] in by_name]
                        entries = ordered + rest

                if lab_filter_enabled and filter_state["acronym"] and not path:
                    active = filter_state["acronym"]
                    bucket_names = [e["name"] for e in bucket_cache["list"]]
                    total = len(bucket_names)
                    if bucket_cache["tags"] is None:
                        print(f"[browser] lab filter {active!r}: scanning S3 'acronym' tag for {total} buckets (one-time per session)...")
                        s3 = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            futs = {pool.submit(backend.get_bucket_tags, s3, b): b for b in bucket_names}
                            tag_map: dict[str, str] = {}
                            for fut in as_completed(futs):
                                b = futs[fut]
                                try:
                                    tag_map[b] = fut.result().get("acronym", "")
                                except Exception:
                                    tag_map[b] = ""
                        bucket_cache["tags"] = tag_map
                        n_tagged = sum(1 for v in tag_map.values() if v)
                        print(f"[browser] lab filter: tag scan done → {n_tagged}/{total} buckets have an 'acronym' tag (cached for this session)")
                    entries = [e for e in entries if bucket_cache["tags"].get(e["name"]) == active]
                    print(f"[browser] lab filter {active!r} → {len(entries)}/{total} buckets match: {[e['name'] for e in entries]}")

                def _show():
                    loading_row.visible = False
                    folder_col.controls.clear()
                    file_row_refs.clear()

                    if not entries:
                        empty_msg = "(empty)" if show_files else "(empty — no subfolders)"
                        folder_col.controls.append(
                            ft.Text(empty_msg, size=11, color=C_TEXT_DIM, italic=True)
                        )
                    else:
                        for entry in entries:
                            name      = entry["name"]
                            is_dir    = entry["is_dir"]
                            full_path = f"{path}/{name}" if path else name
                            fp_snap   = full_path

                            if is_dir:
                                row = ft.Container(
                                    content=ft.Row(
                                        [
                                            ft.Icon(
                                                ft.Icons.STORAGE if not path else ft.Icons.FOLDER_OUTLINED,
                                                color=C_PRIMARY if not path else C_WARNING,
                                                size=16,
                                            ),
                                            ft.Text(name, size=12, color=C_TEXT, expand=True),
                                            ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=14),
                                        ],
                                        spacing=8,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                    bgcolor=C_SURFACE2,
                                    border=ft.Border.all(1, C_BORDER),
                                    border_radius=6,
                                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                    on_click=lambda e, p=fp_snap: _navigate(p),
                                    ink=True,
                                )
                            else:
                                row = ft.Container(
                                    content=ft.Row(
                                        [
                                            ft.Icon(ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                                    color=C_TEXT_DIM, size=16),
                                            ft.Text(name, size=12, color=C_TEXT, expand=True),
                                        ],
                                        spacing=8,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                    bgcolor=C_SURFACE2,
                                    border=ft.Border.all(1, C_BORDER),
                                    border_radius=6,
                                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                    on_click=lambda e, p=fp_snap: _toggle_file_selection(p),
                                    ink=True,
                                )
                                file_row_refs[fp_snap] = row

                            folder_col.controls.append(row)

                    page.update()

                backend.ui_call(page, _show)

            except subprocess.TimeoutExpired:
                print(f"[browser] TIMEOUT path={path!r} after {nav_state['timeout']}s")
                def _timeout_ui():
                    loading_row.visible = False
                    folder_col.controls.clear()

                    # Input para path manual, prefijado con el path actual
                    manual_tf = ft.TextField(
                        value=path,
                        bgcolor=C_SURFACE2,
                        border_color=C_BORDER,
                        focused_border_color=C_PRIMARY,
                        color=C_TEXT,
                        border_radius=6,
                        content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                        text_size=12,
                        expand=True,
                        visible=False,
                    )
                    def confirm_manual(e):
                        new_path = manual_tf.value.strip()
                        print(f"[browser] manual path confirmed → {new_path!r}")
                        nav_state["current_path"]  = new_path
                        nav_state["selected_file"] = None
                        on_select(new_path, False)
                        _rebuild_breadcrumb()
                        manual_tf.visible   = False
                        confirm_btn.visible = False
                        confirmed_badge.visible = True
                        page.update()

                    confirmed_badge = ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=14),
                                ft.Text("Path set!", color=C_ACCENT, size=11, weight=ft.FontWeight.W_600),
                            ],
                            spacing=6,
                        ),
                        visible=False,
                    )

                    confirm_btn = btn_primary("✓ Confirm path", on_click=confirm_manual)
                    confirm_btn.visible = False

                    def show_manual_input(e):
                        manual_tf.visible  = True
                        confirm_btn.visible = True
                        page.update()

                    def retry_60(e):
                        print(f"[browser] retry path={path!r} with timeout=60s")
                        nav_state["timeout"] = 60
                        _navigate(path)

                    folder_col.controls.append(
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Row(
                                        [
                                            ft.Icon(ft.Icons.WARNING_AMBER_OUTLINED, color=C_WARNING, size=16),
                                            ft.Text(
                                                "Listing timed out — this folder has too many objects.",
                                                color=C_WARNING, size=12, weight=ft.FontWeight.W_600,
                                            ),
                                        ],
                                        spacing=8,
                                    ),
                                    ft.Text(
                                        "No worries! You can still copy objects here and mount this folder as a volume.\n"
                                        "To browse subfolders, retry with a longer timeout or enter the path manually.",
                                        color=C_TEXT_DIM, size=11,
                                    ),
                                    ft.Row(
                                        [
                                            btn_primary("↺ Retry (60s)", on_click=retry_60),
                                            btn_secondary("✎ Enter path manually", on_click=show_manual_input),
                                        ],
                                        spacing=8,
                                    ),
                                    ft.Row(
                                        [manual_tf, confirm_btn, confirmed_badge],
                                        spacing=8,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                ],
                                spacing=8,
                                tight=True,
                            ),
                            bgcolor=f"{C_WARNING}11",
                            border=ft.Border.all(1, f"{C_WARNING}44"),
                            border_radius=8,
                            padding=12,
                        )
                    )
                    page.update()

                backend.ui_call(page, _timeout_ui)
            except Exception as ex:
                print(f"[browser] ERROR path={path!r}: {ex}")
                def _err(ex_val=ex):
                    loading_row.visible = False
                    error_text.value    = f"Error: {ex_val}"
                    error_text.visible  = True
                    page.update()
                backend.ui_call(page, _err)

        threading.Thread(target=_load, daemon=True).start()

    def _do_mkdir(e=None):
        """
        Crea una carpeta VIRTUAL: solo actualiza el path de destino en la UI.
        No llama a rclone — S3 creará el prefijo automáticamente al copiar.
        """
        if not nav_state["current_path"]:
            mkdir_status.value   = "⚠ Select a bucket first before adding a subfolder."
            mkdir_status.color   = C_WARNING
            mkdir_status.visible = True
            page.update()
            return

        name = (new_folder_tf.value or "").strip()
        if not name:
            mkdir_status.value   = "⚠ Enter a folder name first."
            mkdir_status.color   = C_WARNING
            mkdir_status.visible = True
            page.update()
            return

        if "/" in name or "\\" in name:
            mkdir_status.value   = "⚠ Folder name cannot contain slashes."
            mkdir_status.color   = C_WARNING
            mkdir_status.visible = True
            page.update()
            return

        base     = nav_state["current_path"]
        new_path = f"{base}/{name}" if base else name
        print(f"[browser] virtual mkdir → {new_path!r} (not created in rclone until copy)")

        new_folder_tf.value = ""

        # Actualizar estado y breadcrumb sin llamar a rclone
        nav_state["current_path"] = new_path
        on_select(new_path, False)
        _rebuild_breadcrumb()

        # Mostrar la carpeta como "nueva/vacía" en la lista
        folder_col.controls.clear()
        folder_col.controls.append(
            ft.Text(
                "(new folder — will be created on copy)",
                size=11, color=C_TEXT_DIM, italic=True,
            )
        )

        #mkdir_status.value   = f"✓ Destination set to: {perfil_rclone}:{new_path}"
        #mkdir_status.color   = C_ACCENT
        #mkdir_status.visible = True

        page.update()

    mkdir_btn.on_click      = _do_mkdir
    new_folder_tf.on_submit = _do_mkdir  # Enter también funciona

    mkdir_section = ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Icon(ft.Icons.CREATE_NEW_FOLDER_OUTLINED,
                                color=C_TEXT_DIM, size=14),
                        ft.Text("Add subfolder to destination:",
                                size=11, color=C_TEXT_DIM),
                    ],
                    spacing=6,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Row(
                    [new_folder_tf, mkdir_btn],
                    spacing=6,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=6,
            tight=True,
        ),
        bgcolor=C_SURFACE2,
        border=ft.Border.all(1, C_BORDER),
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
        visible=False,
    )

    # ── Widget ────────────────────────────────────────────────────────────
    browser_widget = ft.Column(
        [
            filter_row,
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
                    [folder_col],
                    scroll=ft.ScrollMode.AUTO,
                    spacing=0,
                ),
                bgcolor=C_SURFACE,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=200,
                padding=ft.Padding.all(8),
            ),
            # ── Fila "Create folder" ──────────────────────────────────────
            mkdir_section,
        ],
        spacing=6,
        tight=True,
    )

    def _refresh():
        print(f"[browser] refresh() → cache invalidated, initial_path={initial_path!r}")
        bucket_cache["list"] = None
        bucket_cache["tags"] = None
        _navigate(initial_path)

    return browser_widget, _refresh
