"""Vista principal de copia de datos a MinIO."""

from __future__ import annotations

import pathlib
import threading
from datetime import datetime
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_AUTO_RENEWAL_DAYS, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *

from meta_fields import TAG_PROFILES, build_meta_fields, validate_tagset
from views.local_fs import show_local_fs_modal
from views.rclone_browser import build_rclone_browser

# main.py fija el valor real al arrancar: IS_WEB solo puede calcularse en main.py
# (depende de __name__), y las funciones de este módulo lo leen al ejecutarse.
IS_WEB = False


# ============================================================================
# VISTA: INTERFAZ PRINCIPAL DE COPIA
# ============================================================================

def _build_copy_content(
    page: ft.Page,
    perfil_rclone: str,
    mounts_activos: list,
    on_close: Callable,
    endpoint: str,
    credenciales_ldap: dict,
    extra_config: dict | None,
    on_renew_complete: Callable,
    show_screen: Callable,
    web_session: dict | None = None,
    on_back: Callable | None = None,
    on_tags: Callable | None = None,
    on_cifs: Callable | None = None,
    on_login: Callable | None = None,
) -> ft.Control:
    usuario_actual = credenciales_ldap["usuario"]

    num_cores = backend.obtener_num_cpus()
    rclone_config_path = str(backend.obtener_ruta_rclone_conf())

    # ── Badge de expiración de credenciales ───────────────────────────────
    info = backend.get_session_info(perfil_rclone)

    if info and info.remaining is not None:
        dias = info.remaining.days
        color_badge = C_ERROR if dias < 1 else C_WARNING if dias <= STS_RENEWAL_THRESHOLD_DAYS else C_ACCENT
        expiry_text = "🔑 Credentials expired" if info.expired else f"🔑 Credentials expire in {info.remaining_text()}"
    else:
        color_badge = C_TEXT_DIM
        expiry_text = "🔑 Credentials: unknown expiry"

    expiry_badge = ft.Container(
        content=ft.Text(expiry_text, size=11, color=color_badge, weight=ft.FontWeight.W_600),
        bgcolor=f"{color_badge}22",
        border=ft.Border.all(1, f"{color_badge}55"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
    )

    def show_renew_dialog(e):
        days_tf = ft.TextField(
            value=str(STS_AUTO_RENEWAL_DAYS),
            bgcolor=C_SURFACE2,
            border_color=C_BORDER,
            focused_border_color=C_PRIMARY,
            color=C_TEXT,
            border_radius=6,
            content_padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            text_size=13,
            width=80,
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        err = ft.Text("", color=C_ERROR, size=12, visible=False)

        def do_renew(ev=None):
            try:
                dias_int = int(days_tf.value or "0")
                if dias_int < 1 or dias_int > 30:
                    err.value   = "Enter a value between 1 and 30 days."
                    err.visible = True
                    page.update()
                    return
            except ValueError:
                err.value   = "Invalid number."
                err.visible = True
                page.update()
                return

            page.pop_dialog()

            show_screen(build_credentials_content(
                page,
                perfil_rclone=perfil_rclone,
                endpoint=endpoint,
                credenciales_ldap=credenciales_ldap,
                on_continue=on_renew_complete,
                extra_config=extra_config,
                duracion_dias=dias_int,
                on_back=on_login if NO_LDAP else None,
                no_ldap=NO_LDAP,
                is_web=IS_WEB,
                done_message="Continuing to copy interface...",
            ))

        def cancel(ev):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Row(
                [
                    ft.Icon(ft.Icons.AUTORENEW, color=C_PRIMARY, size=20),
                    ft.Text("Renew S3 Credentials", color=C_TEXT, size=15,
                            weight=ft.FontWeight.W_600),
                ],
                spacing=8,
            ),
            content=ft.Column(
                [
                    ft.Text(f"User: {credenciales_ldap['usuario']}", color=C_TEXT_DIM, size=12),
                    ft.Text(f"Profile: {perfil_rclone}", color=C_TEXT_DIM, size=12),
                    ft.Container(height=12),
                    ft.Row(
                        [
                            ft.Text("Renew for:", size=13, color=C_TEXT),
                            days_tf,
                            ft.Text("days", size=13, color=C_TEXT),
                        ],
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    err,
                ],
                spacing=8,
                tight=True,
                width=320,
            ),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                btn_primary("🔄 Renew", on_click=do_renew),
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        #page.overlay.append(dlg)
        #dlg.open = True
        page.show_dialog(dlg)
        page.update()

    renew_btn = btn_secondary("🔑 Renew credentials", on_click=show_renew_dialog)
    def _back_with_sftp_cleanup(e):
        _sftp_disconnect(clear_origen=False)
        on_back()

    back_btn  = btn_secondary("← Back", on_click=_back_with_sftp_cleanup) if on_back else None
    tags_btn  = btn_secondary("🏷️ Tags", on_click=lambda e: on_tags()) if on_tags else None
    cifs_btn = (
        btn_secondary("⊞  Mount NetApp", on_click=lambda e: on_cifs())
        if IS_WEB and on_cifs is not None
        else None
    )

    # ── Origen ────────────────────────────────────────────────────────────
    origen_tf, origen_col = styled_field(
        "Source path" + (" (server path)" if IS_WEB else " (local path or rclone remote)"),
        hint="/path/to/data" if IS_WEB else "/local/path  or  profile:/path",
    )
    flags_tf, flags_col = styled_field(
        "Additional rclone flags (advanced)",
        value=f"--transfers={num_cores} --checkers={num_cores} --s3-no-check-bucket",
    )

    # ── Metadatos ──────────────────────────────────────────────────────────
    _initial_profile = (
        web_session.get("copy_tag_profile") if (IS_WEB and web_session) else None
    ) or list(TAG_PROFILES.keys())[0]
    active_copy_profile = {"name": _initial_profile}

    meta_fields: dict = {}
    meta_container = ft.Container()

    def _rebuild_meta(profile_name: str):
        col = build_meta_fields(profile_name, page, meta_fields)
        meta_container.content = col

    _rebuild_meta(active_copy_profile["name"])

    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in TAG_PROFILES.keys()],
        value=active_copy_profile["name"],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        width=220,
    )

    def _on_profile_change(e):
        new_profile = e.control.value
        if new_profile == active_copy_profile["name"]:
            return

        def _ask():
            def _do_switch():
                _rebuild_meta(new_profile)
                active_copy_profile["name"] = new_profile
                if IS_WEB and web_session is not None:
                    web_session["copy_tag_profile"] = new_profile
                page.update()

            def _cancel():
                profile_dd.value = active_copy_profile["name"]
                page.update()

            has_data = any((tf.value or "").strip() for tf in meta_fields.values())
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

    profile_dd.on_select = _on_profile_change

    profile_row = ft.Row(
        [
            ft.Text("Metadata profile", size=12, color=C_TEXT_DIM, width=130),
            profile_dd,
        ],
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=8,
    )

    # ── Log ────────────────────────────────────────────────────────────────
    # NOTA: en Flet 0.84.0, auto_scroll en ListView no hace nada si no se
    # define también `scroll` explícitamente — bug conocido
    # (github.com/flet-dev/flet/issues/6397), arreglado en 0.85.0 pero aún
    # no lo usamos. `scroll=ALWAYS` es el workaround oficial del propio
    # equipo de Flet mientras tanto.
    log_list = ft.ListView(
        expand=True,
        auto_scroll=True,
        scroll=ft.ScrollMode.ALWAYS,
        spacing=0,
        padding=ft.Padding.all(12),
    )

    _log_lock = threading.Lock()

    log_container = ft.Container(
        content=log_list,
        bgcolor=C_BG,
        border=ft.Border.all(1, C_BORDER),
        border_radius=6,
        height=280,
    )

    def log(msg: str):
        """Append *msg* to the visible log list in this UI page."""
        lines_to_add = []
        for line in msg.splitlines(keepends=True):
            if line.strip():
                color = (
                    C_ACCENT  if line.startswith("✅") else
                    C_ERROR   if line.startswith("❌") else
                    C_WARNING if line.startswith("⚠️") else
                    C_PRIMARY if line.startswith("🔍") or line.startswith("🧾") else
                    C_TEXT
                )
                lines_to_add.append(
                    ft.Text(line.rstrip("\n"),
                            size=11, color=color,
                            font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK, selectable=True)
                )

        def _add():
            with _log_lock:
                log_list.controls.extend(lines_to_add)
                page.update()

        backend.ui_call(page, _add)

    # ── Session-level log dispatcher (web only) ───────────────────────────
    # _dispatch_log accumulates every line in the session buffer AND forwards
    # to every registered UI callback (current page + any future reconnect).
    #
    # Throttling: instead of calling page.update() for every rclone output
    # line (up to 15+/s with 8 parallel transfers), we batch pending lines and
    # flush to callbacks at most every 150 ms. This keeps the Hypercorn asyncio
    # event loop free to accept new WebSocket connections, which was the root
    # cause of the "checking for updates" hang when reconnecting mid-transfer.
    import time as _time

    # Lock to prevent concurrent execution of the flush from both the
    # event-handler thread and a threading.Timer callback simultaneously.
    _dispatch_lock = threading.Lock()

    def _flush_log_callbacks() -> None:
        """Push all pending lines to live UI callbacks in one batched call."""
        with _dispatch_lock:
            if web_session is None:
                return
            pending = web_session.get("_dispatch_pending")
            if not pending:
                return
            web_session["_dispatch_pending"] = []
            web_session["_dispatch_last"]    = _time.monotonic()
            web_session["_dispatch_timer"]   = None
            combined = "".join(pending)
            dead = []
            for cb in list(web_session.get("copy_log_callbacks", [])):
                try:
                    cb(combined)   # one call → one page.update()
                except Exception:
                    dead.append(cb)
            for cb in dead:
                try:
                    web_session["copy_log_callbacks"].remove(cb)
                except ValueError:
                    pass

    def _dispatch_log(msg: str) -> None:
        if IS_WEB and web_session is not None:
            with _dispatch_lock:
                buf = web_session["copy_log_buffer"]
                buf.append(msg)
                # Cap buffer at 5 000 entries — on overflow drop the oldest 1 000.
                if len(buf) > 5000:
                    del buf[:-4000]

                web_session.setdefault("_dispatch_pending", []).append(msg)

                now  = _time.monotonic()
                last = web_session.get("_dispatch_last", 0.0)

            # Schedule / flush outside the lock (cb() calls page.run_thread
            # which must not be called while holding _dispatch_lock).
            if now - last >= 0.15:
                old_timer = web_session.get("_dispatch_timer")
                if old_timer:
                    old_timer.cancel()
                _flush_log_callbacks()
            elif not web_session.get("_dispatch_timer"):
                t = threading.Timer(0.2, _flush_log_callbacks)
                t.daemon = True
                t.start()
                web_session["_dispatch_timer"] = t
        else:
            log(msg)

    # Register this page's log() as a callback so live output reaches the UI
    if IS_WEB and web_session is not None:
        if log not in web_session["copy_log_callbacks"]:
            web_session["copy_log_callbacks"].append(log)



    # ── Estado del proceso activo ─────────────────────────────────────────
    # _active_proceso guarda el Popen de rclone en curso (copy o check).
    # En modo web se reutiliza el dict de la sesión para que sobreviva a
    # un cierre/reapertura de pestaña (el hilo background ya tiene ref al mismo objeto).
    if IS_WEB and web_session is not None:
        _active_proceso: dict = web_session.setdefault("copy_proceso", {"proc": None})
    else:
        _active_proceso: dict = {"proc": None}

    # ── Botones ────────────────────────────────────────────────────────────
    copy_btn   = btn_primary("▶  Copy data")
    check_btn  = btn_primary("✓  Check data", disabled=False)
    cancel_btn = ft.Button(
        content=ft.Row(
            [ft.Icon(ft.Icons.STOP_CIRCLE_OUTLINED, size=16), ft.Text("Cancel")],
            spacing=6, tight=True,
        ),
        visible=False,
        style=ft.ButtonStyle(
            bgcolor={
                ft.ControlState.DEFAULT: C_ERROR,
                ft.ControlState.HOVERED: "#FF6B6B",
            },
            color={ft.ControlState.DEFAULT: "#0D1117"},
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
        ),
    )
    
    save_btn  = btn_secondary("↓  Save log")

    _cancelling: list = [False]   # mutable flag; reset each time a new operation starts

    _cancelling: list = [False]   # mutable flag; reset each time a new operation starts

    def _set_running(running: bool):
        """Show/hide cancel button and toggle copy/check buttons."""
        if running:
            _cancelling[0] = False   # new operation — reset cancel guard
        def _do():
            cancel_btn.visible  = running
            copy_btn.disabled   = running
            check_btn.disabled  = running
            page.update()
        backend.ui_call(page, _do)

    def do_cancel(e):
        if _cancelling[0]:
            return   # already cancelling — ignore duplicate clicks
        proc = _active_proceso["proc"]
        if proc and proc.poll() is None:
            _cancelling[0] = True
            proc.terminate()
            _dispatch_log("\n⚠️  Transfer cancelled by user.\n")
            if IS_WEB and web_session is not None:
                web_session["copy_status"] = "error"
            # Update buttons directly here — we are already in the Flet event
            # handler context so page.update() is safe to call without
            # spawning a new thread (which could race with the log-dispatch
            # timer thread and cause concurrent page.update() calls inside
            # Flet's control-tree walker).
            cancel_btn.visible = False
            copy_btn.disabled  = False
            check_btn.disabled = False
            page.update()
        else:
            _dispatch_log("\n⚠️  No active process to cancel.\n")

    cancel_btn.on_click = do_cancel

    # ── Origen SFTP (perfil rclone efímero) ─────────────────────────────────
    sftp_state: dict = {"perfil": None, "host": None, "user": None}

    sftp_status_label = ft.Text("", size=12, color=C_ACCENT, font_family=FONT_MONO)
    sftp_disconnect_btn = ft.IconButton(
        icon=ft.Icons.CLOSE,
        icon_color=C_TEXT_DIM,
        icon_size=16,
        tooltip="Disconnect SFTP",
        on_click=lambda e: _sftp_disconnect(),
    )
    sftp_status_row = ft.Row(
        [sftp_status_label, sftp_disconnect_btn],
        spacing=4,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        visible=False,
    )

    def _sftp_disconnect(clear_origen: bool = True) -> None:
        perfil = sftp_state["perfil"]
        if not perfil:
            return

        def _bg():
            backend.eliminar_perfil_rclone(perfil)

        backend.safe_thread(page, _bg).start()
        sftp_state["perfil"] = None
        sftp_state["host"]   = None
        sftp_state["user"]   = None
        sftp_status_row.visible = False
        if clear_origen:
            origen_tf.value = ""
        page.update()

    def _open_sftp_browser_modal() -> None:
        _sftp_dest_path = {"value": "", "is_file": False}

        def _on_sftp_select(path: str, is_file: bool = False) -> None:
            _sftp_dest_path["value"]   = path
            _sftp_dest_path["is_file"] = is_file
            confirm_btn.content.value = "Select this file" if is_file else "Select this folder"
            page.update()

        browser_widget, browser_refresh = build_rclone_browser(
            page, sftp_state["perfil"], on_select=_on_sftp_select, lab_filter_enabled=False,
            allow_mkdir=False, show_files=True,
        )

        def confirm(e):
            path = _sftp_dest_path["value"]
            origen_tf.value = f"{sftp_state['perfil']}:{path}"
            page.pop_dialog()
            page.update()

        def cancel(e):
            page.pop_dialog()

        confirm_btn = btn_primary("Select this folder", on_click=confirm)

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text(
                f"SFTP — {sftp_state['user']}@{sftp_state['host']}",
                color=C_TEXT, size=15, weight=ft.FontWeight.W_600,
            ),
            content=ft.Column([browser_widget], spacing=6, tight=True, width=520),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                confirm_btn,
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()
        threading.Timer(0.1, lambda: backend.ui_call(page, browser_refresh)).start()

    def _open_sftp_dialog(e) -> None:
        if sftp_state["perfil"]:
            _open_sftp_browser_modal()
            return

        host_tf, host_col = styled_field("Host")
        port_tf, port_col = styled_field("Port", value="22")
        user_tf, user_col = styled_field("Username")
        pass_tf, pass_col = styled_field("Password", password=True)
        err = ft.Text("", color=C_ERROR, size=12, visible=False)
        loading_indicator = ft.ProgressRing(
            width=16, height=16, stroke_width=2, color=C_PRIMARY, visible=False
        )
        confirm_btn = btn_primary("Connect")

        def connect(ev):
            host = (host_tf.value or "").strip()
            port = (port_tf.value or "").strip() or "22"
            user = (user_tf.value or "").strip()
            pwd  = (pass_tf.value or "").strip()
            if not host or not user:
                err.value   = "Host and username are required."
                err.visible = True
                page.update()
                return

            confirm_btn.disabled      = True
            loading_indicator.visible = True
            err.visible               = False
            page.update()

            def _validate():
                perfil = backend.generar_nombre_perfil_sftp()
                backend.crear_perfil_rclone_sftp(perfil, host, port, user, pwd)
                ok, motivo = backend.validar_conexion_sftp(perfil)
                if ok:
                    sftp_state["perfil"] = perfil
                    sftp_state["host"]   = host
                    sftp_state["user"]   = user

                    def _success():
                        page.pop_dialog()
                        sftp_status_label.value = f"🌐 Connected to {user}@{host}"
                        sftp_status_row.visible = True
                        page.update()
                        _open_sftp_browser_modal()

                    backend.ui_call(page, _success)
                else:
                    backend.eliminar_perfil_rclone(perfil)
                    mensajes = {
                        "auth":        "Incorrect username or password.",
                        "unreachable": f"Could not connect to {host}:{port}. Check the address and make sure the server is reachable from your network.",
                        "timeout":     f"Connection to {host}:{port} timed out.",
                    }
                    msg = mensajes.get(motivo, "Could not connect. Check the details and try again.")

                    def _fail():
                        err.value                 = msg
                        err.visible               = True
                        confirm_btn.disabled      = False
                        loading_indicator.visible = False
                        page.update()

                    backend.ui_call(page, _fail)

            backend.safe_thread(page, _validate).start()

        confirm_btn.on_click = connect

        def cancel(ev):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Connect to SFTP", color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
            content=ft.Column(
                [
                    host_col, port_col, user_col, pass_col, err,
                    ft.Row([loading_indicator], alignment=ft.MainAxisAlignment.CENTER),
                ],
                spacing=6, tight=True, width=320,
            ),
            actions=[btn_secondary("Cancel", on_click=cancel), confirm_btn],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()

    sftp_btn = btn_secondary("🌐 SFTP", on_click=_open_sftp_dialog)

    # ── FilePicker (solo desktop) ──────────────────────────────────────────
    if not IS_WEB:
        file_picker   = ft.FilePicker()
        folder_picker = ft.FilePicker()
        save_picker   = ft.FilePicker()
        page.services.extend([file_picker, folder_picker, save_picker])

        async def _pick_file(e):
            result = await file_picker.pick_files()
            if result:
                ruta = backend.traducir_ruta_a_remote(result[0].path, mounts_activos)
                print(f"[file-picker] file picked → raw={result[0].path!r} translated={ruta!r}")
                origen_tf.value = ruta
                page.update()
            else:
                print("[file-picker] file pick cancelled")

        async def _pick_folder(e):
            result = await folder_picker.get_directory_path()
            if result:
                ruta = backend.traducir_ruta_a_remote(result, mounts_activos)
                print(f"[file-picker] folder picked → raw={result!r} translated={ruta!r}")
                origen_tf.value = ruta
                page.update()
            else:
                print("[file-picker] folder pick cancelled")

        async def _save_log_picker(file_name: str):
            result = await save_picker.save_file(file_name=file_name)
            # no hace el save log bien, flet devuelve str y no path
            path = result.path if hasattr(result, "path") else result
            if path:
                contenido = "\n".join(
                    c.value for c in log_list.controls
                    if isinstance(c, ft.Text) and c.value
                )
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(contenido)
                    show_dialog(page, "Log saved", f"Saved to:\n{path}", C_ACCENT)
                except Exception as ex:
                    err_str = str(ex)
                    show_dialog(page, "Error", err_str, C_ERROR)

        pick_file_btn   = btn_secondary("📄 File",
                            on_click=lambda e: page.run_task(_pick_file, e))
        pick_folder_btn = btn_secondary("📁 Folder",
                            on_click=lambda e: page.run_task(_pick_folder, e))

        pick_row = ft.Row([pick_file_btn, pick_folder_btn, sftp_btn], spacing=8)
    else:
        # Modo WEB: browsers propios que leen el filesystem del servidor
        def _open_folder_browser(e):
            def _picked(path: str):
                print(f"[file-picker] web folder picked → {path}")
                origen_tf.value = path
                page.update()
            show_local_fs_modal(page, on_select=_picked, select_mode="folder")

        def _open_file_browser(e):
            def _picked(path: str):
                print(f"[file-picker] web file picked → {path}")
                origen_tf.value = path
                page.update()
            show_local_fs_modal(page, on_select=_picked, select_mode="file")

        pick_row    = ft.Row(
            [
                btn_secondary("📁 Folder", on_click=_open_folder_browser),
                btn_secondary("📄 File",   on_click=_open_file_browser),
                sftp_btn,
            ],
            spacing=8,
        )
        save_picker = None

    # ── Destino: navegador rclone ──────────────────────────────────────────
    _dest_path = {"value": ""}

    # FIX: ruta_label se actualiza solo via page.update(), nunca via .update()
    # individual, para evitar el error "Control must be added to the page first"
    ruta_label = ft.Text(
        f"→ {perfil_rclone}: (root — select a folder above)",
        size=12,
        color=C_WARNING,
        font_family=FONT_MONO,
        font_family_fallback=MONO_FALLBACK,
    )

    def on_browser_select(path: str, is_file: bool = False):
        print(f"[copy] destination selected → {perfil_rclone}:{path}" if path
              else "[copy] destination cleared (root)")
        _dest_path["value"] = path
        # Persist non-empty selections to session.
        # Do NOT wipe copy_destino on empty path: the browser refresh timer
        # calls on_select("") on load — that must not overwrite a destination
        # the user already selected.
        if IS_WEB and web_session is not None and path:
            web_session["copy_destino"] = path
        if path:
            display = f"{perfil_rclone}:{path}"
            ruta_label.value = f"→ All files from source will be copied into: {display}"
            ruta_label.color = C_ACCENT
        else:
            ruta_label.value = f"→ {perfil_rclone}: (root — select a folder above)"
            ruta_label.color = C_WARNING
        # NO llamamos ruta_label.update() aquí porque este callback puede
        # ejecutarse antes de que el control esté en el árbol (carga inicial).
        # page.update() lo llama _navigate() justo después de on_select().
        should_be_visible = bool(path)
        if bottom_col.visible != should_be_visible:
            bottom_col.visible = should_be_visible
            # page.update() is called by _navigate() right after on_select()

    # build_rclone_browser devuelve (widget, refresh_fn)
    # refresh_fn se llama con Timer después de show_screen() para la carga inicial
    _initial_dest = web_session.get("copy_destino", "") if (IS_WEB and web_session) else ""
    dest_browser, dest_browser_refresh = build_rclone_browser(
        page, perfil_rclone,
        on_select=on_browser_select,
        initial_path=_initial_dest,
        lab_filter_enabled=True,
        worm_defaults_enabled=True,
        endpoint=endpoint,
    )
    dest_browser_col = ft.Column(
        [field_label(f"Destination path (bucket in {perfil_rclone})"), dest_browser],
        spacing=4,
        tight=True,
    )

    # ── Copiar ─────────────────────────────────────────────────────────────
    def do_copy(e):
        origen  = (origen_tf.value or "").strip()
        destino = _dest_path["value"].strip()
        if not origen or not destino:
            show_dialog(page, "Error", "Source and destination are required.", C_ERROR)
            return

        metadatos = {k: (tf.value or "").strip() for k, tf in meta_fields.items()}
        flags     = (flags_tf.value or "").strip().split()

        tag_errors = validate_tagset(metadatos)
        if tag_errors:
            show_dialog(page, "Invalid characters in tags",
                        "\n".join(tag_errors), C_ERROR)
            return

        _set_running(True)

        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _dispatch_log(f"### Copy started at {ahora} ###\n")
        _dispatch_log("### Metadata ###\n")
        for k, v in metadatos.items():
            _dispatch_log(f"  {k}: {v}\n")
        _dispatch_log("\n")

        # Persist copy state so reconnecting sessions can see it
        if IS_WEB and web_session is not None:
            web_session["copy_status"]  = "running"
            web_session["copy_origen"]  = origen
            web_session["copy_destino"] = destino

        def _on_copy_success():
            if IS_WEB and web_session is not None:
                web_session["copy_status"] = "done"

        def _on_copy_finish():
            _active_proceso["proc"] = None
            _set_running(False)
            if IS_WEB and web_session is not None:
                if web_session["copy_status"] == "running":
                    web_session["copy_status"] = "error"
            if IS_WEB:
                _autosave_log()

        def _run_copy():
            proc = backend.ejecutar_rclone_copy(
                origen=origen,
                destino_perfil=perfil_rclone,
                destino_path=destino,
                rclone_config_path=rclone_config_path,
                metadatos_dict=metadatos,
                flags_adicionales=flags,
                num_cores=num_cores,
                log_fn=_dispatch_log,
                on_success=_on_copy_success,
                on_finish=_on_copy_finish,
                expose_proceso=_active_proceso,
            )

        backend.safe_thread(page, _run_copy).start()

    # ── Check ──────────────────────────────────────────────────────────────
    def do_check(e):
        origen  = (origen_tf.value or "").strip()
        destino = _dest_path["value"].strip()
        if not origen or not destino:
            show_dialog(page, "Error", "Source and destination are required.", C_ERROR)
            return

        flags = (flags_tf.value or "").strip().split()
        _set_running(True)
        _dispatch_log(f"\n🔍 Verifying: rclone check {origen} → {perfil_rclone}:/{destino}\n\n")

        # Persist state so a reconnecting session can restore form + cancel btn
        if IS_WEB and web_session is not None:
            web_session["copy_status"]  = "running"
            web_session["copy_origen"]  = origen
            web_session["copy_destino"] = destino

        def _on_check_finish():
            _active_proceso["proc"] = None
            _set_running(False)
            if IS_WEB and web_session is not None:
                if web_session.get("copy_status") == "running":
                    web_session["copy_status"] = "done"
            if IS_WEB:
                _autosave_log()

        def _run_check():
            backend.ejecutar_rclone_check(
                origen=origen,
                destino_perfil=perfil_rclone,
                destino_path=destino,
                rclone_config_path=rclone_config_path,
                flags_adicionales=flags,
                mounts_activos=mounts_activos,
                log_fn=_dispatch_log,
                on_finish=_on_check_finish,
                expose_proceso=_active_proceso,
            )

        backend.safe_thread(page, _run_check).start()

    # ── Guardar log ────────────────────────────────────────────────────────
    def _log_content_from_buffer() -> str:
        """Return log text from the session buffer (web) or the visible list (desktop)."""
        if IS_WEB and web_session is not None:
            return "".join(web_session.get("copy_log_buffer", []))
        return "\n".join(
            c.value for c in log_list.controls
            if isinstance(c, ft.Text) and c.value
        )

    def _autosave_log() -> str | None:
        """
        Automatically save the log to ~/bifrost-logs/ at end of copy/check.
        Returns the saved path, or None on failure.
        Only runs in web (OOD) mode.
        """
        if not IS_WEB:
            return None
        contenido = _log_content_from_buffer()
        if not contenido.strip():
            return None
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = pathlib.Path.home() / "bifrost-logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fpath = log_dir / f"bifrost-{ts}.log"
            fpath.write_text(contenido, encoding="utf-8")
            _dispatch_log(f"\n📄 Log auto-saved to: {fpath}\n")

            # Log rotation: keep only the most recent 50 files
            try:
                log_files = sorted(
                    [f for f in log_dir.glob("bifrost-*.log")],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                )
                MAX_LOG_FILES = 50
                if len(log_files) > MAX_LOG_FILES:
                    deleted_count = 0
                    for old_log in log_files[MAX_LOG_FILES:]:
                        old_log.unlink()
                        deleted_count += 1
                    if deleted_count > 0:
                        _dispatch_log(f"    (cleaned up {deleted_count} old log file(s))\n")
            except Exception as cleanup_ex:
                print(f"[log-rotation] Cleanup warning: {cleanup_ex}", flush=True)

            return str(fpath)
        except Exception as ex:
            _dispatch_log(f"\n⚠️  Could not auto-save log: {ex}\n")
            return None

    def do_save_log(e):
        contenido = _log_content_from_buffer()
        if not contenido.strip():
            show_dialog(page, "Save log", "No log content to save.", C_WARNING)
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if IS_WEB:
            log_dir = pathlib.Path.home() / "bifrost-logs"
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                fpath = log_dir / f"bifrost-{ts}.log"
                fpath.write_text(contenido, encoding="utf-8")
                show_dialog(page, "Log saved", f"Saved to:\n{fpath}", C_ACCENT)
            except Exception as ex:
                err_str = str(ex)
                show_dialog(page, "Error", err_str, C_ERROR)
        else:
            page.run_task(_save_log_picker, f"bifrost-{ts}.log")

 
    copy_btn.on_click  = do_copy
    check_btn.on_click = do_check
    save_btn.on_click  = do_save_log
    # cancel_btn.on_click already wired above

    bottom_col = ft.Column(
        [
            ft.Container(height=16),
            section_title("METADATA"),
            ft.Container(height=6),
            profile_row,
            ft.Container(height=10),
            card(meta_container),
            ft.Container(height=16),
            ft.Row(
                [copy_btn, check_btn, cancel_btn, save_btn],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                wrap=True,
            ),
            ft.Container(height=12),
            section_title("LOG OUTPUT"),
            ft.Container(height=8),
            log_container,
            ft.Container(height=16),
        ],
        spacing=0,
        visible=False,
    )

    # ── Layout ────────────────────────────────────────────────────────────
    content = ft.Column(
        [
            build_header(subtitle=f"Copy & Verify — {perfil_rclone}", IS_WEB=IS_WEB, no_ldap=NO_LDAP),
            ft.Container(
                content=ft.Row(
                    [c for c in [back_btn, tags_btn, cifs_btn, expiry_badge, ft.Container(expand=True), renew_btn] if c is not None],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                margin=ft.Margin.only(bottom=4),
            ),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("PATHS"),
                        ft.Container(height=10),
                        card(
                            ft.Column(
                                [
                                    origen_col,
                                    ft.Container(height=4),
                                    pick_row,
                                    sftp_status_row,
                                    ft.Container(height=12),
                                    dest_browser_col,
                                    ft.Container(height=6),
                                    ruta_label,
                                    ft.Container(height=12),
                                    flags_col,
                                ],
                                spacing=0,
                            ),
                        ),
                        bottom_col,
                    ],
                    spacing=0,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    # FIX: lanzar la carga inicial del browser con un pequeño delay para que
    # show_screen() haya procesado el widget y page.update() se haya ejecutado
    # antes de que _navigate("") intente hacer page.update() sobre controles
    # ya registrados en el árbol de Flet.
    # The timer fires on a threading.Timer thread; routing through backend.ui_call keeps
    # all control mutations on the asyncio event loop (same fix as backend.ui_call above).
    threading.Timer(0.1, lambda: backend.ui_call(page, dest_browser_refresh)).start()

    # ── Replay historical log + show reconnect banner (web session restore) ─
    if IS_WEB and web_session is not None:
        buffer = list(web_session.get("copy_log_buffer", []))
        # Snapshot origin/dest/status NOW, before the browser-refresh timer
        # fires at t=0.1s and calls on_browser_select(""). Without the `and path`
        # guard in on_browser_select that call would wipe copy_destino; with it,
        # it doesn't — but we snapshot here as an extra safety net.
        _snap_origen  = web_session.get("copy_origen", "")
        _snap_destino = web_session.get("copy_destino", "")
        _snap_status  = web_session.get("copy_status", "idle")

        def _replay():
            import time
            time.sleep(0.2)   # wait for page tree to settle
            # Re-read status after sleep in case the process finished during reconnect.
            status = web_session.get("copy_status", _snap_status)
            # Check whether rclone is actually alive, regardless of copy_status.
            # copy_status can be "error" after the user clicked Cancel while the
            # process is still winding down (SIGTERM sent, proc not yet exited).
            # It can also be "running" while proc was already None (race between
            # the backend finally block and the copy_status update).
            _proc = web_session.get("copy_proceso", {}).get("proc")
            proc_alive = _proc is not None and _proc.poll() is None
            if proc_alive:
                status = "running"   # override — process is actually alive
            elif status == "running":
                status = "done"      # proc cleared before copy_status was updated
            if buffer:
                banner = (
                    f"\n{'─'*60}\n"
                    f"↩  Reconnected to existing session\n"
                    f"   Status: {status.upper()}\n"
                    f"   Origin:  {_snap_origen}\n"
                    f"   Dest:    {_snap_destino}\n"
                    f"{'─'*60}\n\n"
                )
                log(banner)
                # Batch all buffered lines into ONE log() call to avoid
                # flooding the event loop with thousands of page.update()
                # calls on reconnect (which caused the "checking for updates"
                # hang). Display only the last 200 lines; anything older is
                # already saved in ~/bifrost-logs/.
                MAX_REPLAY = 200
                if len(buffer) > MAX_REPLAY:
                    log(f"[… {len(buffer) - MAX_REPLAY} earlier lines omitted — see ~/bifrost-logs/ for the full log …]\n")
                log("".join(buffer[-MAX_REPLAY:]))
                if status == "running":
                    log("\n⚠️  Process is still running — new output will appear below\n")
                elif status == "done":
                    log("\n✅  Process finished while you were away\n")
                elif status == "error":
                    log("\n❌  Process ended with errors while you were away\n")

            # Always restore cancel button and form fields regardless of log
            if status == "running":
                _set_running(True)
                # The finish callback (_on_copy/check_finish) was created on
                # the PREVIOUS page and calls the OLD _set_running, so it
                # won't hide the cancel button on THIS (new) page. Poll until
                # the process ends and update the new page's buttons then.
                def _watch_proc_end():
                    import time as _t
                    while True:
                        _t.sleep(0.5)
                        if _active_proceso.get("proc") is None:
                            _set_running(False)
                            return
                threading.Thread(target=_watch_proc_end, daemon=True).start()

            def _prefill():
                if _snap_origen:
                    origen_tf.value = _snap_origen
                if _snap_destino:
                    _dest_path["value"] = _snap_destino
                    ruta_label.value = (
                        f"→ All files from source will be copied into: "
                        f"{perfil_rclone}:{_snap_destino}"
                    )
                    ruta_label.color = C_ACCENT
                page.update()
            backend.ui_call(page, _prefill)

        threading.Thread(target=_replay, daemon=True).start()

    return content
