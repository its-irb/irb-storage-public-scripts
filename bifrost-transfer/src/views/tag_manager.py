"""Vista del Tag Manager (etiquetado masivo sin volver a subir los datos)."""

from __future__ import annotations

import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP
from bifrost_frontend.frontend import *

from meta_fields import TAG_PROFILES, build_lab_filter_widget, build_meta_fields, check_tag_value, detect_profile, validate_tagset

# main.py fija el valor real al arrancar: IS_WEB solo puede calcularse en main.py
# (depende de __name__), y las funciones de este módulo lo leen al ejecutarse.
IS_WEB = False


# ============================================================================
# VIEW: TAG MANAGER
# ============================================================================

def _build_tag_manager_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    on_back: Callable,
) -> ft.Control:
    # ── State ────────────────────────────────────────────────────────────
    s3  = {"client": None}
    nav = {"bucket": None, "prefix": "", "show_files": False}
    sel = {"type": "none", "key": None, "count": 0, "display": ""}
    active_profile  = {"name": list(TAG_PROFILES.keys())[0]}
    tag_fields: dict[str, ft.TextField] = {}
    _log_buffer: list[str] = []
    _current_items = {"folders": [], "files": []}
    _file_tag_rows: list[dict] = []          # freeform editor rows
    _current_file_tags: dict = {"tags": {}}
    _file_editor_section  = None             # assigned after building widgets
    _profile_editor_section = None           # assigned after building widgets
    right_panel = {"visible": False}

    # ── Log ───────────────────────────────────────────────────────────────
    # NOTA: en Flet, adjuntar on_scroll a un ListView rompe su auto_scroll
    # interno por completo (deja de autoseguir incluso sin tocar el scroll).
    # Además, en Flet 0.84.0 auto_scroll no hace nada si no se define
    # también `scroll` explícitamente (github.com/flet-dev/flet/issues/6397).
    log_list = ft.ListView(
        expand=True, auto_scroll=True, scroll=ft.ScrollMode.ALWAYS, spacing=0,
        padding=ft.Padding.all(12),
    )
    log_section = ft.Container(
        content=ft.Column([
            ft.Text("LOGS", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
            ft.Container(height=6),
            ft.Container(
                content=log_list,
                bgcolor=C_BG,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=180,
            ),
        ], spacing=0),
        padding=ft.Padding.symmetric(horizontal=24, vertical=8),
        visible=False,
    )

    def _log(msg: str, color: str = C_TEXT) -> None:
        _log_buffer.append(msg)
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK, selectable=True)
            )
        backend.ui_call(page, _add)

    def _autosave_tag_log() -> None:
        content = "".join(_log_buffer)
        if not content.strip():
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = pathlib.Path.home() / "bifrost-logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fpath = log_dir / f"bifrost-tags-{ts}.log"
            fpath.write_text(content, encoding="utf-8")
            _log(f"\n📄 Log saved to: {fpath}", C_TEXT_DIM)
        except Exception as ex:
            _log(f"\n⚠️  Could not save log file: {ex}", C_WARNING)

    def _get_client():
        if s3["client"] is None:
            s3["client"] = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
        return s3["client"]

    # ── Browser ───────────────────────────────────────────────────────────
    breadcrumb_row = ft.Row(spacing=2, wrap=True)
    browser_col    = ft.Column(spacing=4, tight=True)
    browser_loading = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8, visible=False,
    )
    browser_error = ft.Text("", color=C_ERROR, size=11, visible=False)

    tm_filter_state = {"acronym": None}
    tm_bucket_cache: dict = {"list": None, "tags": None}

    def _on_tm_lab_select(acronym: str | None) -> None:
        previous = tm_filter_state["acronym"]
        if acronym is None:
            print(f"[tag-manager] lab filter cleared (was {previous!r}) → showing all buckets")
        else:
            print(f"[tag-manager] lab filter → {acronym!r} (was {previous!r})")
        tm_filter_state["acronym"] = acronym
        _navigate(None, "")

    tm_filter_widget, _tm_filter_clear_fn = build_lab_filter_widget(page, _on_tm_lab_select)
    tm_filter_row = ft.Container(
        content=tm_filter_widget,
        visible=True,
        padding=ft.Padding.only(bottom=4),
    )

    def _rebuild_breadcrumb() -> None:
        breadcrumb_row.controls.clear()

        def _crumb(label: str, on_click_fn):
            return ft.TextButton(
                label,
                on_click=on_click_fn,
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.Padding.symmetric(horizontal=4, vertical=0),
                ),
            )

        breadcrumb_row.controls.append(
            _crumb(perfil_rclone, lambda e: _navigate(None, ""))
        )
        if nav["bucket"]:
            breadcrumb_row.controls.append(ft.Text("/", color=C_TEXT_DIM, size=12))
            bname = nav["bucket"]
            breadcrumb_row.controls.append(
                _crumb(bname, lambda e, b=bname: _navigate(b, ""))
            )
            accumulated = ""
            for part in nav["prefix"].split("/"):
                if not part:
                    continue
                accumulated += part + "/"
                acc_copy = accumulated
                breadcrumb_row.controls.append(ft.Text("/", color=C_TEXT_DIM, size=12))
                breadcrumb_row.controls.append(
                    _crumb(part, lambda e, p=acc_copy: _navigate(nav["bucket"], p))
                )
        page.update()

    def _render_browser_contents() -> None:
        if hasattr(browser_col.controls, "clear"):
            browser_col.controls.clear()
        else:
            browser_col.controls = []

        if nav["bucket"] is None:
            for bname in _current_items["folders"]:
                arrow = ft.IconButton(
                    icon=ft.Icons.CHEVRON_RIGHT,
                    icon_color=C_TEXT_DIM,
                    icon_size=16,
                    tooltip="Enter bucket",
                    on_click=lambda e, b=bname: _navigate(b, ""),
                )

                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.STORAGE_OUTLINED, color=C_PRIMARY, size=16),
                        ft.Text(bname, size=13, color=C_TEXT, expand=True),
                        arrow,
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=C_SURFACE2,
                    border=ft.Border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                    ink=True,
                )

                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_tap=lambda e, b=bname: _navigate(b, ""),
                    )
                )
        else:
            for prefix in _current_items["folders"]:
                name = prefix.rstrip("/").split("/")[-1] + "/"
                is_sel = sel["type"] == "prefix" and sel["key"] == prefix

                tag_btn = ft.IconButton(
                    icon=ft.Icons.LABEL_OUTLINED,
                    icon_color=C_ACCENT,
                    icon_size=16,
                    tooltip="Edit tags for all files in this folder",
                    on_click=lambda e, p=prefix: _select_prefix_and_open(p),
                )

                arrow = ft.IconButton(
                    icon=ft.Icons.CHEVRON_RIGHT,
                    icon_color=C_TEXT_DIM,
                    icon_size=16,
                    tooltip="Enter folder",
                    on_click=lambda e, p=prefix: _navigate(nav["bucket"], p),
                )

                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
                        ft.Text(name, size=13, color=C_TEXT, expand=True),
                        tag_btn,
                        arrow,
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=f"{C_ACCENT}18" if is_sel else C_SURFACE,
                    border=ft.Border.all(
                        2 if is_sel else 1,
                        C_ACCENT if is_sel else C_BORDER,                     
                    ),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                    ink=True,
                )

                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_tap=lambda e, p=prefix: _navigate(nav["bucket"], p),
                    )
                )

            files = _current_items["files"]

            if not nav["show_files"]:
                view_files_btn = ft.TextButton(
                    "View files in this folder",
                    icon=ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                    style=ft.ButtonStyle(color=C_TEXT_DIM),
                )

                def _on_view_files(e):
                    bucket_snap, prefix_snap = nav["bucket"], nav["prefix"]
                    print(f"[tag-manager] view files → {bucket_snap}/{prefix_snap}")
                    view_files_btn.disabled = True
                    view_files_btn.text = "Loading files..."
                    browser_loading.visible = True
                    page.update()

                    def _async_load():
                        real_files = backend.rclone_list_files_only(
                            perfil_rclone, nav["bucket"], nav["prefix"]
                        )
                        print(f"[tag-manager] view files → {bucket_snap}/{prefix_snap} → {len(real_files)} files")
                        _current_items["files"] = real_files
                        nav["show_files"] = True
                        browser_loading.visible = False
                        backend.ui_call(page, _render_browser_contents)

                    import threading
                    threading.Thread(target=_async_load, daemon=True).start()

                view_files_btn.on_click = _on_view_files
                browser_col.controls.append(
                    ft.Container(
                        content=view_files_btn,
                        padding=ft.Padding.symmetric(horizontal=4, vertical=2),
                    )
                )

            elif nav["show_files"]:
                for key in files:
                    name = key.split("/")[-1]
                    is_sel = sel["type"] == "file" and sel["key"] == key

                    c = ft.Container(
                        content=ft.Row([
                            ft.Icon(
                                ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                color=C_ACCENT if is_sel else C_TEXT_DIM,
                                size=16,
                            ),
                            ft.Text(name, size=12, color=C_TEXT, expand=True),
                        ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                        bgcolor=f"{C_ACCENT}18" if is_sel else C_SURFACE,
                        border=ft.Border.all(
                            2 if is_sel else 1,
                            C_ACCENT if is_sel else C_BORDER,
                        ),
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                        ink=True,
                    )

                    browser_col.controls.append(
                        ft.GestureDetector(
                            content=c,
                            on_tap=lambda e, k=key: _select_file(k),
                        )
                    )

        if not _current_items["folders"] and not _current_items["files"]:
            browser_col.controls.append(
                ft.Text("(empty content)", size=11, color=C_TEXT_DIM, italic=True)
            )

        page.update()
        
    def _select_prefix_and_open(prefix: str) -> None:
        # nav["show_files"] = False
        right_panel["visible"] = True
        right_editor.visible = True

        def _show_panel():
            right_editor.visible = True
            if _file_editor_section is not None:
                _file_editor_section.visible = False
                _profile_editor_section.visible = True
            page.update()

        backend.ui_call(page, _show_panel)

        bucket = nav["bucket"]
        if not bucket:
            return
        
        label   = f"📁 {prefix or (bucket + '/')}"
        note    = "(Will be recursively applied to all objects within this folder)"

        def _upd():
            sel["type"]    = "prefix"
            sel["key"]     = prefix
            sel["count"]   = 0
            sel["display"] = label
            target_label.value    = label
            obj_count_label.value = note
            apply_btn.disabled    = False
            _rebuild_tag_fields(profile_dd.value)
            _render_browser_contents() 
        backend.ui_call(page, _upd)

    def _select_prefix(prefix: str) -> None:
        nav["show_files"] = False
        right_panel["visible"] = True
        right_editor.visible = True

        def _show_panel():
            right_editor.visible = True
            if _file_editor_section is not None:
                _file_editor_section.visible = False
                _profile_editor_section.visible = True
            page.update()

        backend.ui_call(page, _show_panel)

        old_prefix = nav["prefix"]
        nav["prefix"] = prefix
        _update_prefix_selection()
        nav["prefix"] = old_prefix

    def _navigate(bucket: str | None, prefix: str) -> None:
        print(f"[tag-manager] navigate → bucket={bucket!r} prefix={prefix!r}")
        nav["bucket"]     = bucket
        nav["prefix"]     = prefix
        nav["show_files"] = False
        right_editor.visible = False
        right_panel["visible"] = False
        sel["type"]   = "none"
        sel["key"]    = None
        sel["count"]  = 0
        sel["display"] = ""
        _current_items["folders"] = []
        _current_items["files"]   = []

        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Select a folder or a file"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            if _file_editor_section is not None:
                _file_editor_section.visible  = False
                _profile_editor_section.visible = True
                _file_save_status.visible = False
            _rebuild_breadcrumb()
            tm_filter_row.visible = (bucket is None)

        backend.ui_call(page, _reset_editor)
        backend.safe_thread(page, _load_browser).start()

    def _navigate_to_prefix(bucket: str, prefix: str) -> None:
        _navigate(bucket, prefix)

    def _load_browser() -> None:
        def _set_loading():
            browser_loading.visible = True
            browser_error.visible   = False
            if hasattr(browser_col.controls, "clear"):
                browser_col.controls.clear()
            else:
                browser_col.controls = []
            page.update()
        backend.ui_call(page, _set_loading)

        try:
            client = _get_client()
            if nav["bucket"] is None:
                if tm_bucket_cache["list"] is not None:
                    buckets = list(tm_bucket_cache["list"])
                else:
                    buckets = backend.rclone_lsd(perfil=perfil_rclone, path="")
                    tm_bucket_cache["list"] = list(buckets)
                    tm_bucket_cache["tags"] = None
                    print(f"[tag-manager] bucket list fetched: {len(buckets)} buckets")
                if tm_filter_state["acronym"]:
                    active = tm_filter_state["acronym"]
                    total = len(tm_bucket_cache["list"])
                    if tm_bucket_cache["tags"] is None:
                        print(f"[tag-manager] lab filter {active!r}: scanning S3 'acronym' tag for {total} buckets (one-time per session)...")
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            futs = {pool.submit(backend.get_bucket_tags, client, b): b for b in tm_bucket_cache["list"]}
                            tm_tag_map: dict[str, str] = {}
                            for fut in as_completed(futs):
                                b = futs[fut]
                                try:
                                    tm_tag_map[b] = fut.result().get("acronym", "")
                                except Exception:
                                    tm_tag_map[b] = ""
                        tm_bucket_cache["tags"] = tm_tag_map
                        n_tagged = sum(1 for v in tm_tag_map.values() if v)
                        print(f"[tag-manager] lab filter: tag scan done → {n_tagged}/{total} buckets have an 'acronym' tag (cached for this session)")
                    buckets = [b for b in buckets if tm_bucket_cache["tags"].get(b) == active]
                    print(f"[tag-manager] lab filter {active!r} → {len(buckets)}/{total} buckets match: {buckets}")
                _current_items["folders"] = buckets
                _current_items["files"]   = []
            else:
                folders, files = backend.list_prefix_contents(
                    perfil_rclone, nav["bucket"], nav["prefix"]
                )
                print(
                    f"[tag-manager] listed bucket={nav['bucket']!r} prefix={nav['prefix']!r} "
                    f"→ {len(folders)} subfolders"
                )
                _current_items["folders"] = folders
                _current_items["files"]   = files

            def _show():
                browser_loading.visible = False
                _render_browser_contents()
            backend.ui_call(page, _show)

        except Exception as ex:
            print(f"[tag-manager] ERROR bucket={nav['bucket']!r} prefix={nav['prefix']!r}: {ex}")
            def _err(ex_val=ex):
                browser_loading.visible = False
                browser_error.value     = f"Error: {ex_val}"
                browser_error.visible   = True
                page.update()
            backend.ui_call(page, _err)

    def _update_prefix_selection() -> None:
        bucket = nav["bucket"]
        prefix = nav["prefix"]
        if not bucket:
            return
        print(f"[tag-manager] select prefix → {bucket}/{prefix}")

        label   = f"📁 {prefix or (bucket + '/')}"
        note    = "(Tag scanning and counting disabled for speed)"
        tags_cp = {}
        cnt_cp  = 0

        def _upd():
            sel["type"]    = "prefix"
            sel["key"]     = None
            sel["count"]   = cnt_cp
            sel["display"] = label
            target_label.value    = label
            obj_count_label.value = note
            apply_btn.disabled    = False
            _prefill_fields(tags_cp)
        backend.ui_call(page, _upd)

    def _select_file(key: str) -> None:
        print(f"[tag-manager] select file → {nav['bucket']}/{key}")
        def _do():
            client = _get_client()
            right_panel["visible"] = True
            right_editor.visible = True
            try:
                tags = backend.get_object_tags(client, nav["bucket"], key)
            except Exception as ex:
                tags = {}
                resp = getattr(ex, "response", None)
                error_code = (resp or {}).get("Error", {}).get("Code", "") if isinstance(resp, dict) else ""
                if error_code != "NoSuchKey":
                    ex_str = str(ex)
                    print(f"[tag-manager] ERROR reading tags for {nav['bucket']}/{key}: {ex_str}")
                    def _err():
                        browser_error.value   = f"Error reading tags: {ex_str}"
                        browser_error.visible = True
                        page.update()
                    backend.ui_call(page, _err)

            display = f"📄 {key}"
            tags_cp = dict(tags)

            def _upd():
                sel["type"]    = "file"
                sel["key"]     = key
                sel["count"]   = 1
                sel["display"] = display
                target_label.value    = display
                obj_count_label.value = ""
                apply_btn.disabled    = False
                #_prefill_fields(tags_cp)
                _file_name_label.value = key
                _populate_file_editor(tags_cp)
                if _file_editor_section is not None:
                    _file_editor_section.visible  = True
                _profile_editor_section.visible = False
                _render_browser_contents()
            backend.ui_call(page, _upd)
        backend.safe_thread(page, _do).start()

    # ── Editor ────────────────────────────────────────────────────────────
    profile_names = list(TAG_PROFILES.keys())
    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        width=220,
        #on_change=_on_profile_change,
    )

    # Contenedor raíz para los campos dinámicos
    card_container = ft.Container()
    target_label    = ft.Text("Select a folder or a file", size=12, color=C_TEXT_DIM, italic=True)
    obj_count_label = ft.Text("", size=11, color=C_TEXT_DIM)
    apply_btn       = btn_primary("Apply tags →")
    apply_btn.disabled = True
    apply_status    = ft.Text("", size=12, color=C_TEXT_DIM, visible=False)
        
    def _rebuild_tag_fields(profile_name: str, target_container=None, target_fields=None, prefill_values=None) -> None:
        container = target_container if target_container is not None else card_container
        fields    = target_fields    if target_fields    is not None else tag_fields
        active_profile["name"] = profile_name
        col = build_meta_fields(profile_name, page, fields, prefill_values=prefill_values)
        container.content = card(col, padding=16)
        page.update()

    def _on_profile_change(e):
        new_profile = e.control.value
        if new_profile == active_profile["name"]:
            return

        def _ask():
            def _do_switch():
                _rebuild_tag_fields(new_profile)
                page.update()

            def _cancel():
                profile_dd.value = active_profile["name"]
                page.update()

            has_data = any((tf.value or "").strip() for tf in tag_fields.values())
            if has_data:
                show_confirm(
                    page,
                    "Change profile",
                    "Changing the profile will clear all metadata. Continue?",
                    on_yes=_do_switch,
                    on_no=_cancel,
                )
            else:
                _do_switch()

        backend.ui_call(page, _ask)
    
    def _prefill_fields(tags: dict[str, str]) -> None:
        for key, tf in tag_fields.items():
            if key in tags:
                tf.value = tags[key]
        page.update()

    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        width=220
    )

    profile_dd.on_select = _on_profile_change
    _rebuild_tag_fields(profile_names[0])

    def do_apply(e) -> None:
        tagset = {k: (tf.value or "").strip() for k, tf in tag_fields.items()}

        tag_errors = validate_tagset(tagset)
        if tag_errors:
            show_dialog(page, "Caracteres no permitidos en los tags",
                        "\n".join(tag_errors), C_ERROR)
            return

        apply_btn.disabled  = True
        apply_status.value  = "Applying tags..."
        apply_status.color  = C_TEXT_DIM
        apply_status.visible = True
        log_section.visible  = True
        page.update()

        def _do():
            client = _get_client()
            bucket = nav["bucket"]
            target = sel["key"] if sel["type"] == "file" else f"{sel['key'] or ''} (prefix, recursive)"
            non_empty_tags = {k: v for k, v in tagset.items() if v}
            print(f"[tag-manager] applying tags to {bucket}/{target} → {non_empty_tags}")
            ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _log(f"### Tags applied — {ts} ###\n")
            _log(f"Profile: {active_profile['name']}\n", C_TEXT_DIM)
            for k, v in tagset.items():
                if v:
                    _log(f"  {k}: {v}\n", C_TEXT_DIM)
            _log("\n")

            try:
                if sel["type"] == "file":
                    _log(f"📄 File: {sel['key']}\n")
                    backend.apply_tags_to_object(client, bucket, sel["key"], tagset)
                    _log(f"  ✓ {sel['key']}\n", C_ACCENT)
                    n_ok = 1
                else:
                    prefix = sel["key"] if sel["key"] is not None else ""
                    _log(f"📁 Bulk Prefix S3/MinIO: {bucket}/{prefix}\n")
                    _log(f"⏳ Searching recursively for all objects inside this prefix...\n", C_TEXT_DIM)
                    n_ok = backend.apply_tags_to_prefix(
                        client, bucket, prefix, tagset,
                        log_fn=lambda msg: _log(msg),
                    )

                print(f"[tag-manager] tags applied OK → {n_ok} object(s) updated in {bucket}/{target}")
                _log(f"\n✅ {n_ok} object(s) tagged successfully.\n", C_ACCENT)

                def _ok():
                    apply_btn.disabled   = False
                    apply_status.value   = f"✅ {n_ok} object(s) updated"
                    apply_status.color   = C_ACCENT
                    page.update()
                backend.ui_call(page, _ok)

            except Exception as ex:
                err_str = str(ex)
                print(f"[tag-manager] tags apply FAILED for {bucket}/{target}: {err_str}")
                _log(f"\n❌ Error: {err_str}\n", C_ERROR)
                def _err():
                    apply_btn.disabled   = False
                    apply_status.value   = "❌ Error applying tags"
                    apply_status.color   = C_ERROR
                    page.update()
                backend.ui_call(page, _err)

            _autosave_tag_log()

        backend.safe_thread(page, _do).start()

    apply_btn.on_click = do_apply

    # ── Freeform Editor (Individual File) ────────────────────────────
    _add_btn_ref  = {"btn": None}   
    _save_btn_ref = {"btn": None}   

    _file_name_label  = ft.Text("", size=12, color=C_TEXT_DIM, italic=True)
    _file_tags_col    = ft.Column(spacing=6, tight=True)
    _file_save_status = ft.Text("", size=12, visible=False)
    file_card_container = ft.Container(visible=False, expand=True)
    file_editor_mode = {"mode": "list"}  # "list" o "profile"
    file_tag_fields: dict = {}    

    file_list_headers = ft.Row(
            [
                ft.Text("Key", size=11, color=C_TEXT_DIM, expand=1),
                ft.Text("Value", size=11, color=C_TEXT_DIM, expand=2),
                ft.Container(width=40),
            ],
            spacing=6,
        )

    def _refresh_add_btn_state() -> None:
        if _add_btn_ref["btn"] is not None:
            _add_btn_ref["btn"].disabled = len(_file_tag_rows) >= 10

    def _build_file_editor_row(key: str = "", value: str = "") -> dict:
        
        key_tf = ft.TextField(
            value=key, hint_text="Key",
            bgcolor=C_SURFACE2, border_color=C_BORDER,
            focused_border_color=C_PRIMARY, color=C_TEXT,
            hint_style=ft.TextStyle(color=C_TEXT_DIM),
            border_radius=6,
            content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            text_size=12, max_length=128, expand=1,
        )
        
        val_container = ft.Container(expand=2)
        key_err = ft.Text("", size=11, color=C_ERROR, visible=False, expand=1)
        val_err = ft.Text("", size=11, color=C_ERROR, visible=False, expand=2)
        row_dict: dict = {"key_tf": key_tf, "val_tf": None, "row": None, "val_container": val_container}

        def update_value_field_type(current_key: str, current_val: str):
            field_tf = ft.TextField(
                value=current_val, hint_text="Value",
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                hint_style=ft.TextStyle(color=C_TEXT_DIM),
                border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                text_size=12, max_length=256, expand=True
            )
            def _on_val_change(e):
                err = check_tag_value(row_dict["val_tf"].value or "")
                row_dict["val_tf"].border_color = C_ERROR if err else C_BORDER
                val_err.value = err or ""
                val_err.visible = bool(err)
                page.update()
            field_tf.on_change = _on_val_change
            row_dict["val_tf"] = field_tf
            val_container.content = field_tf  # siempre simple, sin dropdown

        update_value_field_type(key, value)

        def on_key_change(e):
            err = check_tag_value(key_tf.value or "")
            key_tf.border_color = C_ERROR if err else C_BORDER
            key_err.value = err or ""
            key_err.visible = bool(err)
            old_val = row_dict["val_tf"].value or ""
            update_value_field_type(key_tf.value, old_val)
            page.update()

        key_tf.on_change = on_key_change

        def _delete(e, rd=row_dict):
            if rd in _file_tag_rows:
                _file_tag_rows.remove(rd)
            if rd["row"] in _file_tags_col.controls:
                _file_tags_col.controls.remove(rd["row"])
            _refresh_add_btn_state()
            page.update()

        inner_row = ft.Row(
            [
                key_tf, val_container,
                ft.IconButton(
                    icon=ft.Icons.CLOSE, icon_size=16, icon_color=C_TEXT_DIM,
                    tooltip="Remove", on_click=_delete,
                ),
            ],
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        row = ft.Column(
            [inner_row, ft.Row([key_err, val_err], spacing=6)],
            spacing=2,
        )
        row_dict["row"] = row
        return row_dict

    def _populate_file_editor(tags: dict[str, str]) -> None:
        _current_file_tags["tags"] = dict(tags)
        detected = detect_profile(tags)
        if detected:
            _switch_to_profile_mode(detected, prefill_values=tags)
            return
        _populate_raw_list(tags)

    def _on_add_tag_row(e) -> None:
        if len(_file_tag_rows) >= 10:
            return
        rd = _build_file_editor_row()
        _file_tag_rows.append(rd)
        _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()

    def _switch_to_profile_mode(profile_name: str, prefill_values: dict | None = None) -> None:
        active_profile["name"] = profile_name
        file_editor_mode["mode"] = "profile"
        prefill_profile_dd.value    = profile_name
        _file_tags_col.visible      = False
        add_tag_btn.visible         = False
        file_list_headers.visible   = False
        file_card_container.visible = True
        view_raw_btn.visible        = True
        _rebuild_tag_fields(profile_name, target_container=file_card_container,
                            target_fields=file_tag_fields, prefill_values=prefill_values)

    def _populate_raw_list(tags: dict[str, str]) -> None:
        _file_tag_rows.clear()
        _file_tags_col.controls = []
        _file_save_status.visible = False
        for k, v in tags.items():
            rd = _build_file_editor_row(k, v)
            _file_tag_rows.append(rd)
            _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        file_editor_mode["mode"] = "list"
        file_card_container.visible = False
        _file_tags_col.visible      = True
        add_tag_btn.visible         = True
        file_list_headers.visible   = True
        view_raw_btn.visible        = False
        page.update()

    def _on_prefill_from_profile(e) -> None:
        _switch_to_profile_mode(prefill_profile_dd.value)

    def _on_save_file_tags(e) -> None:
        if file_editor_mode["mode"] == "profile":
            tagset = {k: (c.value or "").strip() for k, c in file_tag_fields.items()}
        else:
            tagset = {
                rd["key_tf"].value.strip(): rd["val_tf"].value.strip()
                for rd in _file_tag_rows
                if rd["key_tf"].value.strip()
            }

        tag_errors = validate_tagset(tagset)
        if tag_errors:
            show_dialog(page, "Caracteres no permitidos en los tags",
                        "\n".join(tag_errors), C_ERROR)
            return

        if _save_btn_ref["btn"] is not None:
            _save_btn_ref["btn"].disabled = True
        _file_save_status.value   = "Saving..."
        _file_save_status.color   = C_TEXT_DIM
        _file_save_status.visible = True
        page.update()

        def _do():
            client = _get_client()
            try:
                backend.apply_tags_to_object(client, nav["bucket"], sel["key"], tagset)
                def _ok():
                    if _save_btn_ref["btn"] is not None:
                        _save_btn_ref["btn"].disabled = False
                    _file_save_status.value = "✅ Tags saved successfully"
                    _file_save_status.color = C_ACCENT
                    page.update()
                backend.ui_call(page, _ok)
            except Exception as ex:
                err_str = str(ex)
                def _err():
                    if _save_btn_ref["btn"] is not None:
                        _save_btn_ref["btn"].disabled = False
                    _file_save_status.value = f"❌ Error: {err_str}"
                    _file_save_status.color = C_ERROR
                    page.update()
                backend.ui_call(page, _err)

        backend.safe_thread(page, _do).start()

    def _on_show_raw(e) -> None:
        _populate_raw_list(_current_file_tags["tags"])

    view_raw_btn = ft.TextButton(
        "Ver tags raw",
        on_click=_on_show_raw,
        style=ft.ButtonStyle(color=C_TEXT_DIM),
        visible=False,
    )

    add_tag_btn = btn_secondary("+ Add tag", on_click=_on_add_tag_row)
    _add_btn_ref["btn"] = add_tag_btn

    prefill_profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=12,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        width=175,
    )
    prefill_profile_dd.on_change = lambda e: active_profile.update({"name": e.control.value})
    prefill_btn   = btn_secondary("Pre-fill", on_click=_on_prefill_from_profile)
    file_save_btn = btn_primary("Save tags")
    file_save_btn.on_click = _on_save_file_tags
    _save_btn_ref["btn"]   = file_save_btn

    _file_editor_section = ft.Container(
        visible=False,
        expand=True,
        content=ft.Column(
            [
                ft.Text("FILE TAGS EDITOR", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                ft.Row(
                    [_file_name_label, view_raw_btn],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=8),
                file_list_headers,
                ft.Container(height=4),
                _file_tags_col,
                file_card_container, 
                ft.Container(height=8),
                add_tag_btn,
                ft.Container(height=12),
                ft.Divider(height=1, color=C_BORDER),
                ft.Container(height=8),
                ft.Row(
                    [prefill_profile_dd, prefill_btn],
                    spacing=8,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=12),
                ft.Row(
                    [file_save_btn, _file_save_status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=0,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        ),
    )

    _profile_editor_section = ft.Container(
        visible=True,
        expand=True,
        content=ft.Column(
            [
                ft.Text("APPLY TAGS TO ALL FILES IN FOLDER", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                # El seleccionador de Perfil se encuentra FUERA del cuadro de metadatos
                ft.Row(
                    [
                        ft.Text("Profile:", size=13, color=C_TEXT),
                        profile_dd,
                    ],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=12),
                # Contenedor dinámico que aloja los metadatos de la carpeta
                card_container,
                ft.Container(height=12),
                ft.Container(
                    content=ft.Column(
                        [target_label, obj_count_label],
                        spacing=2,
                    ),
                    bgcolor=C_SURFACE2,
                    border=ft.Border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                ),
                ft.Container(height=12),
                ft.Row(
                    [apply_btn, apply_status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=0,
            expand=True,
        ),
    )

    right_editor = ft.Container(
        visible=False,
        content=ft.Column(
            [_file_editor_section, _profile_editor_section],
            spacing=0,
            expand=True,
        ),
        padding=ft.Padding.only(left=16),
        expand=True,
    )
    
    # ── Layout ────────────────────────────────────────────────────────────
    back_btn = btn_secondary("← Back", on_click=lambda e: on_back())

    content = ft.Column(
        [
            build_header(subtitle=f"Tag Manager — {perfil_rclone}", IS_WEB=IS_WEB, no_ldap=NO_LDAP),
            ft.Container(
                content=ft.Row(
                    [back_btn, ft.Container(expand=True)],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
            ),
            ft.Container(
                content=ft.Row(
                    [
                        # Left panel: Browser
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text("BROWSE", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                                    ft.Container(height=8),
                                    breadcrumb_row,
                                    ft.Container(height=6),
                                    tm_filter_row,
                                    browser_loading,
                                    browser_error,
                                    ft.Container(
                                        content=ft.Column(
                                            [browser_col],
                                            scroll=ft.ScrollMode.AUTO,
                                            spacing=0,
                                        ),
                                        bgcolor=C_SURFACE,
                                        border=ft.Border.all(1, C_BORDER),
                                        border_radius=6,
                                        height=400,
                                        padding=ft.Padding.all(8),
                                    ),
                                ],
                                spacing=0,
                                width=380,
                            ),
                        ),
                        ft.VerticalDivider(width=1, color=C_BORDER),
                        # Right panel: Editor
                        right_editor,  
                    ],
                    spacing=0,
                    expand=True,
                    vertical_alignment=ft.CrossAxisAlignment.START,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                expand=True,
            ),
            log_section,
        ],
        expand=True,
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    backend.safe_thread(page, _load_browser).start()
    return content
