"""Vista principal de bifrost-mount: selector de buckets y montaje."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import flet as ft

from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_AUTO_RENEWAL_DAYS, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *

log = logging.getLogger("bifrost.mount")
rclone_log = logging.getLogger("bifrost.rclone")      # el texto de rclone, aparte de lo que hace BIFROST


# ============================================================================
# COMPONENTE: SELECTOR DE BUCKETS RCLONE
#
# Lista los buckets disponibles en el perfil rclone configurado.
# No navega carpetas — solo muestra los buckets del root y permite
# seleccionar para montarlo.
# ============================================================================

def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str], None],
    mounted_state: dict,
    on_busy: Callable[[bool, str], None],
    on_double_tap_mount: Callable[[str], None] | None = None,
) -> tuple[ft.Column, Callable, ft.OutlinedButton]:
    """
    Lista los buckets disponibles en el perfil rclone.
    Al seleccionar uno, llama on_select(bucket_name).
    Doble click monta directamente si on_double_tap_mount está definido.
    mounted_state: dict compartido {bucket_name: mount_point} para trackear mounts.
    on_busy(ocupado, texto): la pantalla desactiva Mount y "Unmount all" mientras se desmonta (y al revés).
    Devuelve (widget, refresh, unmount_all_btn): el widget con la lista de buckets,
    una función que recarga la lista, y el botón "Unmount all" para colocarlo en el layout.
    """
    selected_state = {"bucket": None}

    # Flag to detect mounts from previous sessions only on the initial load.
    # Subsequent refreshes (triggered after each mount) must NOT re-add buckets
    # that were just unmounted — that would create a race with _unmount_all.
    _first_load_done = {"value": False}

    # Una sola carga de la lista a la vez: si se pide otra mientras tanto (⟳, recarga tras montar), se hace una más
    # al terminar. Sin VPN cada carga espera hasta 15 s; así no se acumulan y la lista refleja la última petición.
    _loads = {"running": False, "again": False}
    _loads_lock = threading.Lock()

    bucket_col  = ft.Column(spacing=6, tight=True)
    loading_row = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Loading buckets...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8,
        visible=False,
    )
    error_text = ft.Text("", color=C_ERROR, size=11, visible=False)

    def _select_bucket(bucket_name: str):
        selected_state["bucket"] = bucket_name
        on_select(bucket_name)
        _render_buckets(selected_state.get("_all_buckets", []))

    def _select_and_mount(bucket_name: str):
        _select_bucket(bucket_name)
        if on_double_tap_mount:
            on_double_tap_mount(bucket_name)

    unmount_all_btn = btn_secondary("⊠  Unmount all")
    unmount_all_btn.visible = False


    def _unmount_all():
        """Desmonta todos los buckets y deja en mounted_state solo los que siguen montados de verdad."""
        on_busy(True, "Unmounting...")

        def _do():
            log.info("unmount all: %d mounts", len(mounted_state))
            still_mounted = []
            for bname, mp in list(mounted_state.items()):
                try:
                    unmounted = backend.desmontar_punto_montaje(mp)
                except Exception:
                    log.exception("unmount %s failed", bname)
                    unmounted = False
                if unmounted:
                    mounted_state.pop(bname, None)
                else:
                    still_mounted.append(bname)

            def _done():
                selected_state["bucket"] = None
                on_select("")
                on_busy(False, "")
                _render_buckets(selected_state.get("_all_buckets", []))
                if still_mounted:
                    show_issue(page, backend.UNMOUNT_FAILED, is_web=False, context=", ".join(still_mounted),
                               screen="mount")
            backend.ui_call(page, _done)

        backend.safe_thread(page, _do).start()

    unmount_all_btn.on_click = lambda e: _unmount_all()


    def _render_buckets(buckets: list):
        selected_state["_all_buckets"] = buckets
        bucket_col.controls.clear()

        if not buckets:
            bucket_col.controls.append(
                ft.Text("(no buckets found)", size=11, color=C_TEXT_DIM, italic=True)
            )
        else:
            for bname in buckets:
                is_sel     = bname == selected_state["bucket"]
                is_mounted = bname in mounted_state

                if is_mounted:
                    bg_color     = f"{C_BORDER}55"   # gris semitransparente
                    border_color = C_TEXT_DIM        # gris oscuro
                    border_width = 1
                    icon         = ft.Icons.CHECK_CIRCLE_OUTLINE
                    icon_color   = C_TEXT_DIM
                    text_weight  = ft.FontWeight.W_400
                elif is_sel:
                    bg_color     = f"{C_PRIMARY}18"
                    border_color = C_PRIMARY
                    border_width = 2
                    icon         = ft.Icons.STORAGE_OUTLINED
                    icon_color   = C_PRIMARY
                    text_weight  = ft.FontWeight.W_600
                else:
                    bg_color     = C_SURFACE2
                    border_color = C_BORDER
                    border_width = 1
                    icon         = ft.Icons.STORAGE_OUTLINED
                    icon_color   = C_PRIMARY
                    text_weight  = ft.FontWeight.W_400


                row = ft.GestureDetector(
                    content=ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(icon, color=icon_color, size=16),
                                ft.Text(
                                    bname,
                                    size=13,
                                    color=C_TEXT,
                                    weight=text_weight,
                                    expand=True,
                                ),
                                ft.Container(
                                    content=ft.Text("mounted", size=10, color=C_TEXT_DIM),
                                    bgcolor=f"{C_BORDER}88",
                                    border_radius=4,
                                    padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                                    visible=is_mounted,
                                ),
                            ],
                            spacing=10,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        bgcolor=bg_color,
                        border=ft.Border.all(border_width, border_color),
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
                        ink=True,
                    ),
                    on_tap=lambda e, b=bname: _select_bucket(b),
                    on_double_tap=lambda e, b=bname: _select_and_mount(b),
                )
                bucket_col.controls.append(row)

        unmount_all_btn.visible = len(mounted_state) > 0
        page.update()

    def _load():
        def _set_loading():
            loading_row.visible = True
            error_text.visible  = False
            page.update()
        backend.ui_call(page, _set_loading)

        # Montajes que el sistema ha quitado (p. ej. macOS al cortarse la red): dejan de marcarse. Su rclone se para
        # al volver a montar el bucket o al cerrar la app.
        for bname, mp in list(mounted_state.items()):
            if not backend.is_mounted(mp):
                log.info("mount: %s is no longer mounted", bname)
                mounted_state.pop(bname, None)

        try:
            buckets = backend.rclone_lsd(perfil_rclone, "", timeout=15)
            # Detectar mounts activos de sesiones anteriores — solo en la carga inicial.
            # En recargas posteriores (después de montar un bucket) no re-añadimos entradas:
            # evita una race condition donde _load sobreescribe mounted_state tras un unmount.
            if not _first_load_done["value"]:
                for bname in buckets:
                    mp = backend.resolver_mount_point_destino(perfil_rclone, bname)
                    if backend.is_mounted(mp):
                        mounted_state[bname] = mp
                        log.info("mounted from a previous session: %s", mp)
                _first_load_done["value"] = True

            def _show():
                loading_row.visible = False
                _render_buckets(buckets)
            backend.ui_call(page, _show)

        except Exception as ex:
            issue = backend.issue_for_exception(ex)
            log.error("bucket list failed: profile=%s code=%s", perfil_rclone, issue.code)
            rclone_log.error("lsd %s: %s", perfil_rclone, ex)

            def _err():
                loading_row.visible = False
                error_text.value    = issue_line(issue, is_web=False, screen="mount")
                error_text.visible  = True
                if "_all_buckets" in selected_state:
                    _render_buckets(selected_state["_all_buckets"])   # la lista anterior, con los montajes al día
                page.update()
            backend.ui_call(page, _err)

    browser_widget = ft.Column(
        [
            loading_row,
            error_text,
            ft.Container(
                content=ft.Column(
                    [bucket_col],
                    scroll=ft.ScrollMode.AUTO,
                    spacing=0,
                ),
                bgcolor=C_SURFACE,
                border=ft.Border.all(1, C_BORDER),
                border_radius=6,
                height=220,
                padding=ft.Padding.all(8),
            ),
        ],
        spacing=6,
        tight=True,
    )

    def _refresh():
        with _loads_lock:
            if _loads["running"]:
                _loads["again"] = True
                return
            _loads["running"] = True
        threading.Thread(target=_load_until_current, daemon=True).start()

    def _load_until_current():
        while True:
            try:
                _load()
            except Exception:                  # que un fallo no deje la lista sin poder recargarse nunca más
                log.exception("bucket list load failed")
            with _loads_lock:
                if not _loads["again"]:
                    _loads["running"] = False
                    return
                _loads["again"] = False

    return browser_widget, _refresh, unmount_all_btn


# ============================================================================
# VISTA: INTERFAZ PRINCIPAL DE MONTADO — SELECCIÓN DE BUCKET
# ============================================================================

def _build_mount_bucket(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    credenciales_ldap: dict,
    extra_config: dict | None,
    on_renew_complete: Callable,
    show_screen: Callable,
    mounted_state: dict,
    on_back: Callable | None = None,
) -> ft.Control:
    
    # ── Badge de expiración de credenciales ───────────────────────────────
    info = backend.get_session_info(perfil_rclone)

    if info and info.remaining is not None:
        dias        = info.remaining.days
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
                no_ldap=NO_LDAP,
                done_message="Loading mount interface...",
            ))

        def cancel(ev):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Row(
                [
                    ft.Icon(ft.Icons.AUTORENEW, color=C_PRIMARY, size=20),
                    ft.Text("Renew MinIO credentials", color=C_TEXT, size=15,
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
        page.show_dialog(dlg)
        page.update()

    renew_btn = btn_secondary("🔑 Renew credentials", on_click=show_renew_dialog)
    back_btn  = btn_secondary("← Back", on_click=lambda e: on_back()) if on_back else None

    # ── Destino: selector de buckets ──────────────────────────────────────
    _dest_path = {"value": ""}

    def on_browser_select(path: str):
        _dest_path["value"] = path

    # ── Montar bucket ─────────────────────────────────────────────────────
    mount_btn = btn_secondary("⊞  Mount bucket")
    mount_status = ft.Text("", size=12, color=C_TEXT_DIM, visible=False)
    reload_btn = ft.IconButton(icon=ft.Icons.REFRESH, icon_color=C_PRIMARY, icon_size=18,
                               tooltip="Reload the bucket list")
    busy = {"on": False}             # montando o desmontando: no se puede empezar otra operación

    def _set_busy(on: bool, text: str = "") -> None:
        """Mientras se monta o desmonta, Mount, "Unmount all" y recargar la lista quedan desactivados (pendiente 4:
        un montaje que terminaba durante "Unmount all" dejaba el estado mal). Solo desde el hilo de la UI."""
        busy["on"] = on
        mount_btn.disabled       = on
        unmount_all_btn.disabled = on
        reload_btn.disabled      = on
        mount_status.value       = text
        mount_status.color       = C_TEXT_DIM
        mount_status.visible     = bool(text)
        page.update()

    def _prompt_install_winfsp(on_success: Callable[[], None]) -> None:
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

    def do_mount(e, ruta: str | None = None):
        ruta = (ruta or _dest_path["value"]).strip()
        if not ruta:
            show_dialog(page, "Error", "Select a bucket first.", C_ERROR)
            return
        if busy["on"]:
            return
        if ruta in mounted_state and backend.is_mounted(mounted_state[ruta]):
            log.info("mount: %s is already mounted, opening the folder", ruta)
            backend.open_in_file_browser(mounted_state[ruta])
            return
        _set_busy(True, "Mounting...")

        def _do():
            # Montaje perdido (p. ej. macOS lo desconecta al cortarse la red): el backend para su rclone antes de montar
            lost = mounted_state.pop(ruta, None)
            if lost:
                log.info("mount: %s is no longer mounted, mounting again", ruta)
            log.info("mount: bucket=%s profile=%s", ruta, perfil_rclone)
            try:
                mp = backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
            except backend.WinFspMissingError:
                log.info("mount: WinFsp missing")
                def _ask():
                    _set_busy(False)
                    _prompt_install_winfsp(on_success=lambda: do_mount(None, ruta))
                backend.ui_call(page, _ask)
                return
            except backend.MountError as ex:
                error = ex
            except Exception as ex:
                log.exception("mount %s failed", ruta)
                error = backend.MountError(backend.issue_for_exception(ex))
            else:
                # Solo ahora: el montaje se ha comprobado listando la carpeta.
                mounted_state[ruta] = mp
                backend.open_in_file_browser(mp)
                error = None
            backend.ui_call(page, lambda: _after_mount(ruta, error, was_mounted=bool(lost)))

        backend.safe_thread(page, _do).start()

    def _after_mount(ruta: str, error, *, was_mounted: bool) -> None:
        if error is not None:
            _set_busy(False)
            show_issue(page, error.issue, is_web=False, title="Could not mount the bucket", context=ruta,
                       screen="mount")
            if was_mounted:
                dest_browser_refresh()       # la lista aún lo marcaba como montado
            return
        _set_busy(False, "✅ Mounted!")
        mount_status.color = C_ACCENT
        page.update()

        def _clear_status():
            time.sleep(3)
            def _hide():
                if not busy["on"]:
                    mount_status.visible = False
                    page.update()
            backend.ui_call(page, _hide)
        threading.Thread(target=_clear_status, daemon=True).start()
        dest_browser_refresh()

    mount_btn.on_click = do_mount

    dest_browser, dest_browser_refresh, unmount_all_btn = build_rclone_browser(
        page, perfil_rclone,
        on_select=on_browser_select,
        mounted_state=mounted_state,
        on_busy=_set_busy,
        on_double_tap_mount=lambda path: do_mount(None, path),
    )

    def _reload(_e):
        log.info("bucket list: reload")
        dest_browser_refresh()
    reload_btn.on_click = _reload

    dest_browser_col = ft.Column(
        [
            ft.Row([field_label(f"Bucket in {perfil_rclone}"), reload_btn],
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                   vertical_alignment=ft.CrossAxisAlignment.CENTER),
            dest_browser,
        ],
        spacing=4,
        tight=True,
    )

    # ── Layout ────────────────────────────────────────────────────────────
    content = ft.Column(
        [
            build_header(no_ldap=NO_LDAP, subtitle=f"Mount — {perfil_rclone}", page=page),
            ft.Container(
                content=ft.Row(
                    [back_btn, expiry_badge, ft.Container(expand=True), renew_btn],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                margin=ft.Margin.only(bottom=4),
            ),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("SELECT BUCKET"),
                        ft.Container(height=10),
                        card(
                            ft.Column(
                                [
                                    dest_browser_col,
                                    ft.Container(height=12),
                                ],
                                spacing=0,
                            ),
                        ),
                        ft.Container(height=16),
                        ft.Row(
                            [mount_btn, unmount_all_btn, mount_status],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Container(height=12),
                    ],
                    spacing=0,
                ),
                padding=ft.Padding.symmetric(horizontal=24, vertical=8),
            ),
        ],
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    threading.Timer(0.1, dest_browser_refresh).start()
    return content
