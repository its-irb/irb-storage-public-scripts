"""Vista del Tag Manager (etiquetado masivo sin volver a subir los datos)."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP
from bifrost_frontend.frontend import *

from meta_fields import TAG_PROFILES, build_lab_filter_widget, build_meta_fields, check_tag_value, detect_profile, validate_tagset

log = logging.getLogger("bifrost.tags")

# main.py fija el valor real al arrancar: IS_WEB solo puede calcularse en main.py
# (depende de __name__), y las funciones de este módulo lo leen al ejecutarse.
IS_WEB = False

# Texto corto junto al botón Apply al terminar, según TagRun.outcome.
_APPLY_STATUS = {
    "ok":        ("✅ Tags set", C_ACCENT),
    "partial":   ("⚠️ Some files could not be changed", C_WARNING),
    "stopped":   ("❌ Stopped (see LOGS)", C_ERROR),
    "cancelled": ("⏹ Stopped", C_WARNING),
    "empty":     ("No files found in this folder", C_TEXT_DIM),
}


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
    # tags_loaded: las etiquetas del fichero seleccionado se leyeron bien. Sin eso no se puede guardar: se
    # sustituirían las que tiene sin saber cuáles son.
    sel = {"type": "none", "key": None, "tags_loaded": False}
    apply_op = {"stop": None}                # threading.Event de la aplicación a carpeta en curso (Cancel)
    active_profile  = {"name": list(TAG_PROFILES.keys())[0]}
    tag_fields: dict[str, ft.TextField] = {}
    _current_items = {"folders": [], "files": []}
    _file_tag_rows: list[dict] = []          # freeform editor rows
    _current_file_tags: dict = {"tags": {}}

    # ── Log ───────────────────────────────────────────────────────────────
    # Cada operación (guardar un fichero, aplicar a una carpeta) escribe aquí y en su informe, que se guarda
    # al terminar en reports/tags-<fecha>.log. Como en copy: recuentos, nunca listas de ficheros.
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
    )

    def _log(msg: str) -> None:
        texts = [log_text(line) for line in msg.splitlines() if line.strip()]
        def _add():
            log_list.controls.extend(texts)
            page.update()
        backend.ui_call(page, _add)

    def _new_operation(title: str) -> tuple[list[str], Callable[[str], None]]:
        """Operación nueva: op_log escribe en LOGS y guarda la línea para el informe de esta operación."""
        lines: list[str] = []

        def op_log(msg: str) -> None:
            lines.append(msg + "\n")
            _log(msg)

        op_log(f"\n### {title} at {datetime.now():%Y-%m-%d %H:%M:%S} ###")
        return lines, op_log

    def _log_tags(op_log: Callable[[str], None], title: str, tags: dict[str, str]) -> None:
        """Todas las etiquetas, también las vacías (también se escriben en MinIO)."""
        op_log(f"{title}:" if tags else f"{title}: (none)")
        for k, v in tags.items():
            op_log(f"  {k}: {v}")

    def _save_report(lines: list[str], problems: list[str] | None = None) -> Path | None:
        """Escribe el informe de la operación y deja su ruta en LOGS. Nunca rompe el final de la operación."""
        try:
            path = backend.write_report("tags", lines, problems)
        except Exception as ex:
            log.exception("tags report could not be saved")
            _log(f"⚠️ Could not save the report: {ex}")
            return None
        log.info("tags report saved: %s", path)
        _log(f"📄 Report saved: {path}")
        return path

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
        log.info("lab filter: %s (was %s)", acronym or "cleared", tm_filter_state["acronym"])
        tm_filter_state["acronym"] = acronym
        _navigate(None, "")

    tm_filter_widget, _ = build_lab_filter_widget(page, _on_tm_lab_select)
    tm_filter_row = ft.Container(
        content=tm_filter_widget,
        visible=True,
        padding=ft.Padding.only(bottom=4),
    )

    def _show_browser_error(issue) -> None:
        """Error al listar, traducido. Solo desde el hilo de la UI."""
        browser_loading.visible = False
        _render_browser_contents()
        hint = issue.hint_for(IS_WEB, screen="tags")
        browser_error.value   = f"⚠️ {issue.title}. {hint}" if hint else f"⚠️ {issue.title}."
        browser_error.visible = True
        page.update()

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
        browser_col.controls.clear()

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

            if not nav["show_files"]:
                view_files_btn = ft.TextButton(
                    "View files in this folder",
                    icon=ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                    style=ft.ButtonStyle(color=C_TEXT_DIM),
                )

                def _on_view_files(e):
                    view_files_btn.disabled = True
                    view_files_btn.text = "Loading files..."
                    _load_files()

                view_files_btn.on_click = _on_view_files
                browser_col.controls.append(
                    ft.Container(
                        content=view_files_btn,
                        padding=ft.Padding.symmetric(horizontal=4, vertical=2),
                    )
                )
            else:
                for key in _current_items["files"]:
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

    def _reset_selection() -> None:
        """Nada seleccionado: el panel derecho se oculta. Solo desde el hilo de la UI (no llama a update)."""
        sel.update(type="none", key=None, tags_loaded=False)
        right_editor.visible  = False
        apply_btn.disabled    = True
        target_label.value    = "Select a folder or a file"
        obj_count_label.value = ""
        apply_status.visible  = False
        _file_save_status.visible       = False
        _file_editor_section.visible    = False
        _profile_editor_section.visible = True

    def _select_prefix_and_open(prefix: str) -> None:
        if not nav["bucket"]:
            return
        label = f"📁 {prefix or (nav['bucket'] + '/')}"
        sel.update(type="prefix", key=prefix, tags_loaded=False)
        right_editor.visible = True
        _file_editor_section.visible    = False
        _profile_editor_section.visible = True
        target_label.value    = label
        obj_count_label.value = "(Will be recursively applied to all objects within this folder)"
        apply_btn.disabled    = apply_op["stop"] is not None
        _rebuild_tag_fields(profile_dd.value)
        _render_browser_contents()

    def _navigate(bucket: str | None, prefix: str) -> None:
        log.info("navigate: bucket=%s prefix=%s", bucket, prefix)
        nav["bucket"]     = bucket
        nav["prefix"]     = prefix
        nav["show_files"] = False
        _current_items["folders"] = []
        _current_items["files"]   = []
        _reset_selection()
        tm_filter_row.visible = bucket is None
        _rebuild_breadcrumb()
        backend.safe_thread(page, _load_browser).start()

    def _load_browser() -> None:
        def _set_loading():
            browser_loading.visible = True
            browser_error.visible   = False
            browser_col.controls.clear()
            page.update()
        backend.ui_call(page, _set_loading)

        try:
            if nav["bucket"] is None:
                if tm_bucket_cache["list"] is not None:
                    buckets = list(tm_bucket_cache["list"])
                else:
                    buckets = backend.rclone_lsd(perfil=perfil_rclone, path="")
                    tm_bucket_cache["list"] = list(buckets)
                    tm_bucket_cache["tags"] = None
                    log.info("bucket list: %d buckets", len(buckets))
                if tm_filter_state["acronym"]:
                    buckets = _filter_buckets_by_lab(buckets, tm_filter_state["acronym"])
                _current_items["folders"] = buckets
                _current_items["files"]   = []
            else:
                folders = backend.list_prefix_folders(perfil_rclone, nav["bucket"], nav["prefix"])
                log.info("listed %s/%s: %d subfolders", nav["bucket"], nav["prefix"], len(folders))
                _current_items["folders"] = folders
                _current_items["files"]   = []

            def _show():
                browser_loading.visible = False
                _render_browser_contents()
            backend.ui_call(page, _show)

        except Exception as ex:
            log.warning("listing %s/%s failed: %s", nav["bucket"], nav["prefix"], ex)
            issue = backend.issue_for_exception(ex)
            backend.ui_call(page, lambda: _show_browser_error(issue))

    def _filter_buckets_by_lab(buckets: list[str], acronym: str) -> list[str]:
        """Buckets cuya etiqueta 'acronym' coincide. Las etiquetas se leen una vez por sesión."""
        total = len(tm_bucket_cache["list"])
        if tm_bucket_cache["tags"] is None:
            log.info("lab filter %s: reading the 'acronym' tag of %d buckets (once per session)", acronym, total)
            client = _get_client()
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
            log.info("lab filter: %d/%d buckets have an 'acronym' tag",
                     sum(1 for v in tm_tag_map.values() if v), total)
        matching = [b for b in buckets if tm_bucket_cache["tags"].get(b) == acronym]
        log.info("lab filter %s: %d/%d buckets match", acronym, len(matching), total)
        return matching

    def _load_files() -> None:
        """Lista, bajo demanda, los ficheros de la carpeta abierta (sin subcarpetas)."""
        bucket, prefix = nav["bucket"], nav["prefix"]
        browser_loading.visible = True
        browser_error.visible   = False
        page.update()

        def _do():
            try:
                files = backend.rclone_list_files_only(perfil_rclone, bucket, prefix)
            except Exception as ex:
                log.warning("listing the files of %s/%s failed: %s", bucket, prefix, ex)
                issue = backend.issue_for_exception(ex)
                backend.ui_call(page, lambda: _show_browser_error(issue))
                return
            log.info("view files: %s/%s → %d files", bucket, prefix, len(files))

            def _show():
                if (nav["bucket"], nav["prefix"]) != (bucket, prefix):
                    return                                  # el usuario ya está en otra carpeta
                _current_items["files"] = files
                nav["show_files"] = True
                browser_loading.visible = False
                _render_browser_contents()
            backend.ui_call(page, _show)

        backend.safe_thread(page, _do).start()

    # ── Fichero seleccionado: leer sus etiquetas antes de abrir el editor ──
    def _select_file(key: str) -> None:
        bucket = nav["bucket"]
        log.info("select file: %s/%s", bucket, key)

        def _do():
            try:
                tags, uploaded = backend.read_object_tags(_get_client(), bucket, key)
            except Exception as ex:
                issue = backend.issue_for_exception(ex)
                log.warning("reading the tags of %s/%s failed: %s", bucket, key, issue.code)
                backend.ui_call(page, lambda: _on_tags_unreadable(key, issue))
                return
            backend.ui_call(page, lambda: _open_file_editor(key, tags, uploaded))

        backend.safe_thread(page, _do).start()

    def _open_file_editor(key: str, tags: dict[str, str], uploaded: datetime | None) -> None:
        sel.update(type="file", key=key, tags_loaded=True)
        target_label.value    = f"📄 {key}"
        obj_count_label.value = ""
        _file_name_label.value    = key
        # Fecha de subida de la versión actual (LastModified), en la hora local; no cambia con las etiquetas.
        _file_uploaded_label.value   = f"Uploaded to MinIO: {uploaded.astimezone():%Y-%m-%d %H:%M}" if uploaded else ""
        _file_uploaded_label.visible = uploaded is not None
        _file_save_status.visible = False
        _populate_file_editor(tags)
        _file_editor_section.visible    = True
        _profile_editor_section.visible = False
        right_editor.visible = True
        _render_browser_contents()

    def _on_tags_unreadable(key: str, issue) -> None:
        """No se abre el editor: sin las etiquetas actuales, guardar las sustituiría a ciegas (pendiente 11)."""
        _log(f"⚠️ Could not read the tags of {key} — {issue.title}")
        _reset_selection()
        _render_browser_contents()
        if issue.code == "OBJECT_GONE":
            show_issue(page, issue, is_web=IS_WEB, context=key, screen="tags",
                       buttons=[("OK", _load_files)], color=C_WARNING)
        else:
            show_issue(page, issue, is_web=IS_WEB, title="Could not read the tags of this file", context=key,
                       screen="tags", buttons=[("Cancel", None), ("Try again", lambda: _select_file(key))])

    # ── Editor ────────────────────────────────────────────────────────────
    profile_names = list(TAG_PROFILES.keys())

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

    # ── Aplicar a una carpeta ─────────────────────────────────────────────
    def do_apply(e) -> None:
        if sel["type"] != "prefix":
            return
        tagset = {k: (tf.value or "").strip() for k, tf in tag_fields.items()}
        tag_errors = validate_tagset(tagset)
        if tag_errors:
            show_dialog(page, "Invalid characters in tags", "\n".join(tag_errors), C_ERROR)
            return
        _run_folder_apply(nav["bucket"], sel["key"] or "", tagset, active_profile["name"])

    def _run_folder_apply(bucket: str, prefix: str, tagset: dict[str, str], profile: str,
                          keys: list[str] | None = None) -> None:
        """Aplica tagset a toda la carpeta o, con `keys`, solo a esos ficheros ("Try again" tras fallos)."""
        stop = threading.Event()
        apply_op["stop"] = stop
        _set_applying(True)

        def _do():
            lines, op_log = _new_operation("Tags applied" if keys is None else "Tags applied again")
            op_log(f"📁 Folder in MinIO: {bucket}/{prefix} (all files inside)")
            if keys is not None:
                op_log(f"   Only the {len(keys)} file(s) whose tags could not be set before.")
            op_log(f"Profile: {profile}")
            _log_tags(op_log, "Tags", tagset)
            # Al log técnico, solo los nombres de los campos: los valores son metadatos personales.
            log.info("applying tags: %s/%s files=%s fields=%s", bucket, prefix,
                     "all" if keys is None else len(keys), [k for k, v in tagset.items() if v])
            try:
                client = _get_client()
                if keys is None:
                    run = backend.apply_tags_to_prefix(client, bucket, prefix, tagset,
                                                       stop=stop, on_progress=_show_progress)
                else:
                    run = backend.apply_tags_to_keys(client, bucket, keys, tagset,
                                                     stop=stop, on_progress=_show_progress)
            except Exception as ex:                  # no se pudo ni empezar (p. ej. sin acceso a MinIO)
                log.exception("tags could not be applied")
                run = backend.TagRun(stopped=backend.issue_for_exception(ex))
            log.info("tags finished: %s", run.log_line())
            for line in run.final_lines(IS_WEB):
                op_log(line)
            report = _save_report(lines, run.problem_lines())
            backend.ui_call(page, lambda: _after_folder_apply(run, bucket, prefix, tagset, profile, report))

        backend.safe_thread(page, _do).start()

    def _set_applying(running: bool) -> None:
        """Botones mientras se aplican etiquetas a una carpeta. Solo desde el hilo de la UI."""
        apply_btn.disabled         = running or sel["type"] != "prefix"
        cancel_apply_btn.visible   = running
        cancel_apply_btn.disabled  = False
        profile_dd.disabled        = running
        if running:
            apply_status.value   = "Finding the files in the folder…"
            apply_status.color   = C_TEXT_DIM
            apply_status.visible = True
        page.update()

    def _show_progress(done: int) -> None:
        def _upd():
            if apply_op["stop"] is not None and not apply_op["stop"].is_set():
                apply_status.value = f"Setting tags: {done} files done so far"
                page.update()
        backend.ui_call(page, _upd)

    def _on_cancel_apply(e) -> None:
        if apply_op["stop"] is not None:
            apply_op["stop"].set()
            cancel_apply_btn.disabled = True
            apply_status.value = "Stopping… (waiting for the files in progress)"
            page.update()

    def _after_folder_apply(run, bucket: str, prefix: str, tagset: dict[str, str], profile: str,
                            report: Path | None) -> None:
        apply_op["stop"] = None
        _set_applying(False)
        apply_status.value, apply_status.color = _APPLY_STATUS[run.outcome]
        apply_status.visible = True
        page.update()
        if run.outcome not in ("partial", "stopped"):
            return

        # Try again: tras fallos sueltos, solo esos ficheros (si se guardaron todos); si no, toda la carpeta
        # (los que ya tienen las etiquetas nuevas quedan igual).
        retry_keys = list(run.failed) if run.outcome == "partial" and run.can_retry_failed_only else None
        if run.outcome == "stopped":
            title = "Tags could not be applied"
            context = f"{run.ok} file(s) have the new tags; the rest of the folder was not changed."
        else:
            title = "Tags were not set on some files"
            context = f"Tags set on {run.ok} file(s); {run.failed_count} could not be changed: {run.causes_text}."
            if retry_keys is None:
                context += "\nTry again will apply the tags to the whole folder again."
        context = f"{bucket}/{prefix}\n{context}" + (f"\nReport: {report}" if report else "")
        show_issue(page, run.main_issue, is_web=IS_WEB, title=title, context=context, screen="tags",
                   buttons=[("Cancel", None),
                            ("Try again", lambda: _run_folder_apply(bucket, prefix, tagset, profile, retry_keys))],
                   color=C_ERROR if run.outcome == "stopped" else C_WARNING)

    apply_btn.on_click = do_apply
    cancel_apply_btn = btn_secondary("Cancel", on_click=_on_cancel_apply)
    cancel_apply_btn.visible = False

    # ── Freeform Editor (Individual File) ────────────────────────────
    _file_name_label  = ft.Text("", size=12, color=C_TEXT_DIM, italic=True)
    _file_uploaded_label = ft.Text("", size=11, color=C_TEXT_DIM, visible=False)
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
        add_tag_btn.disabled = len(_file_tag_rows) >= 10

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

        def update_value_field_type(current_val: str):
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

        update_value_field_type(value)

        def on_key_change(e):
            err = check_tag_value(key_tf.value or "")
            key_tf.border_color = C_ERROR if err else C_BORDER
            key_err.value = err or ""
            key_err.visible = bool(err)
            old_val = row_dict["val_tf"].value or ""
            update_value_field_type(old_val)
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

    # ── Guardar las etiquetas de un fichero ───────────────────────────────
    def _on_save_file_tags(e) -> None:
        if sel["type"] != "file" or not sel["tags_loaded"]:
            return                     # sin las etiquetas actuales, guardar las sustituiría a ciegas
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
            show_dialog(page, "Invalid characters in tags", "\n".join(tag_errors), C_ERROR)
            return

        bucket, key, before = nav["bucket"], sel["key"], dict(_current_file_tags["tags"])
        file_save_btn.disabled    = True
        _file_save_status.value   = "Saving..."
        _file_save_status.color   = C_TEXT_DIM
        _file_save_status.visible = True
        page.update()

        def _do():
            lines, op_log = _new_operation("Tags saved")
            op_log(f"📄 File: {bucket}/{key}")
            _log_tags(op_log, "Tags before", before)
            _log_tags(op_log, "New tags", tagset)
            issue = None
            try:
                backend.apply_tags_to_object(_get_client(), bucket, key, tagset)
            except Exception as ex:
                issue = backend.issue_for_exception(ex)
                log.warning("saving the tags of %s/%s failed: %s", bucket, key, issue.code)
                op_log(f"❌ Tags not saved — {issue.title}.")
            else:
                log.info("tags saved: %s/%s fields=%s", bucket, key, list(tagset))
                op_log("✅ Tags saved.")
            report = _save_report(lines)
            backend.ui_call(page, lambda: _after_file_save(key, tagset, issue, report))

        backend.safe_thread(page, _do).start()

    def _after_file_save(key: str, tagset: dict[str, str], issue, report: Path | None) -> None:
        file_save_btn.disabled = False
        if issue is None:
            if sel["key"] == key:
                _current_file_tags["tags"] = dict(tagset)
            _file_save_status.value, _file_save_status.color = "✅ Tags saved", C_ACCENT
            page.update()
            return
        _file_save_status.value, _file_save_status.color = "❌ Tags not saved", C_ERROR
        page.update()
        report_line = f"\nReport: {report}" if report else ""
        show_issue(page, issue, is_web=IS_WEB, title="Tags were not saved", context=f"{key}{report_line}",
                   screen="tags", buttons=[("Close", None)])

    def _on_show_raw(e) -> None:
        _populate_raw_list(_current_file_tags["tags"])

    # Botón con borde, como "+ Add tag" y "Pre-fill": que se vea que se puede pulsar.
    view_raw_btn = btn_secondary("Show raw tags", on_click=_on_show_raw)
    view_raw_btn.visible = False

    add_tag_btn = btn_secondary("+ Add tag", on_click=_on_add_tag_row)

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

    _file_editor_section = ft.Container(
        visible=False,
        expand=True,
        content=ft.Column(
            [
                ft.Text("FILE TAGS EDITOR", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                ft.Row(
                    [ft.Column([_file_name_label, _file_uploaded_label], spacing=2, tight=True), view_raw_btn],
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
                    [apply_btn, cancel_apply_btn, apply_status],
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
