"""Vista principal de bifrost-mount: selector de buckets y montaje."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import sys
import threading
import time
from typing import Callable

import flet as ft

from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_AUTO_RENEWAL_DAYS, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *

log = logging.getLogger("bifrost.mount")


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
    on_double_tap_mount: Callable[[str], None] | None = None,
) -> tuple[ft.Column, Callable, ft.OutlinedButton]:
    """
    Lista los buckets disponibles en el perfil rclone.
    Al seleccionar uno, llama on_select(bucket_name).
    Doble click monta directamente si on_double_tap_mount está definido.
    mounted_state: dict compartido {bucket_name: mount_point} para trackear mounts.
    Devuelve (widget, refresh, unmount_all_btn): el widget con la lista de buckets,
    una función que recarga la lista, y el botón "Unmount all" para colocarlo en el layout.
    """
    selected_state = {"bucket": None}

    # Flag to detect mounts from previous sessions only on the initial load.
    # Subsequent refreshes (triggered after each mount) must NOT re-add buckets
    # that were just unmounted — that would create a race with _unmount_all.
    _first_load_done = {"value": False}

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
        log.info(f"BUCKET selected — {bucket_name}")
        on_select(bucket_name)
        _render_buckets(selected_state.get("_all_buckets", []))

    def _select_and_mount(bucket_name: str):
        _select_bucket(bucket_name)
        if on_double_tap_mount:
            on_double_tap_mount(bucket_name)

    unmount_all_btn = btn_secondary("⊠  Unmount all")
    unmount_all_btn.visible = False


    def _unmount_all():
        def _do():
            log.info(f"UNMOUNT ALL — {len(mounted_state)} mounts")
            for bname, mp in list(mounted_state.items()):
                try:
                    backend.desmontar_punto_montaje(mp)
                except OSError as ex:
                    log.info(f"UNMOUNT error — bucket: {bname} — {ex}")
                    # WinError 1005: WinFSP volume already in inconsistent state
                    # El proceso rclone probablemente ya no existe (perdido tras rebuild)
                    # Forzar taskkill por nombre como fallback
                    print(f"[unmount_all] OSError {bname}: {ex} — trying taskkill fallback")
                    if sys.platform == "win32":
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/IM", "rclone.exe"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            )
                        except Exception:
                            pass
                except Exception as ex:
                    log.info(f"UNMOUNT error — bucket: {bname} — {ex}")
                    print(f"[unmount_all] Error {bname}: {ex}")
                finally:
                    mounted_state.pop(bname, None)
            def _refresh():
                selected_state["bucket"] = None
                on_select("")
                _render_buckets(selected_state.get("_all_buckets", []))
            backend.ui_call(page, _refresh)
        threading.Thread(target=_do, daemon=True).start()

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

        try:
            buckets = backend.rclone_lsd(perfil_rclone, "", timeout=15)
            # Detectar mounts activos de sesiones anteriores — solo en la carga inicial.
            # En recargas posteriores (después de montar un bucket) no re-añadimos entradas:
            # evita una race condition donde _load sobreescribe mounted_state tras un unmount.
            if not _first_load_done["value"]:
                for bname in buckets:
                    mp = backend.resolver_mount_point_destino(perfil_rclone, bname)
                    if sys.platform == "win32":
                        if os.path.isdir(mp):
                            try:
                                os.listdir(mp)
                                mounted_state[bname] = mp
                            except OSError:
                                pass
                    else:
                        if os.path.ismount(mp):
                            mounted_state[bname] = mp
                _first_load_done["value"] = True

            def _show():
                loading_row.visible = False
                _render_buckets(buckets)
            backend.ui_call(page, _show)

        except Exception as ex:
            log.error("BUCKET list failed — profile: %s — %s", perfil_rclone, ex)
            def _err(ex_val=ex):
                loading_row.visible = False
                error_text.value    = f"Error loading buckets: {ex_val}"
                error_text.visible  = True
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

    return browser_widget, lambda: threading.Thread(target=_load, daemon=True).start(), unmount_all_btn


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

    def _prompt_install_winfsp(on_success):
        """Pregunta al usuario si quiere descargar e instalar WinFsp.
        Si acepta y la instalación termina OK, ejecuta on_success() para reintentar el mount.
        """
        def _close(dlg):
            dlg.open = False
            page.update()

        def _do_install(_e):
            _close(confirm_dlg)

            progress_text = ft.Text("Starting...")
            progress_dlg = ft.AlertDialog(
                modal=True,
                title=ft.Text("Installing WinFsp"),
                content=ft.Column(
                    [ft.ProgressRing(), progress_text],
                    tight=True,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            )
            page.overlay.append(progress_dlg)
            progress_dlg.open = True
            page.update()

            def _on_progress(msg):
                def _upd():
                    progress_text.value = msg
                    page.update()
                backend.ui_call(page, _upd)

            def _worker():
                try:
                    ok = backend.install_winfsp_windows(on_progress=_on_progress)
                except Exception as ex:
                    err = str(ex)
                    log.info(f"WINFSP install error — {err}")
                    def _err():
                        _close(progress_dlg)
                        show_dialog(
                            page,
                            "Error installing WinFsp",
                            f"{err}\n\nYou can install it manually from https://winfsp.dev",
                            C_ERROR,
                        )
                    backend.ui_call(page, _err)
                    return

                def _done():
                    _close(progress_dlg)
                    if ok:
                        log.info("WINFSP install success")
                        on_success()
                    else:
                        log.info("WINFSP install cancelled")
                        show_dialog(
                            page,
                            "Installation cancelled",
                            "The WinFsp installation was cancelled. You can retry the mount whenever you want.",
                            C_ERROR,
                        )
                backend.ui_call(page, _done)

            backend.safe_thread(page, _worker).start()

        def _do_cancel(_e):
            _close(confirm_dlg)
            show_dialog(
                page,
                "WinFsp not detected",
                "WinFsp is required to mount S3 folders on Windows. Download it from https://winfsp.dev",
                C_ERROR,
            )

        confirm_dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("WinFsp is not installed"),
            content=ft.Text(
                "WinFsp is required to mount S3 folders on Windows.\n\n"
                "Do you want to download and install the latest version now? "
                "Administrator permissions will be required."
            ),
            actions=[
                ft.TextButton("Install", on_click=_do_install),
                ft.TextButton("Cancel", on_click=_do_cancel),
            ],
        )
        page.overlay.append(confirm_dlg)
        confirm_dlg.open = True
        page.update()

    def do_mount(e, ruta: str | None = None):
        ruta = ruta or _dest_path["value"].strip()
        if not ruta:
            show_dialog(page, "Error", "Select a bucket first.", C_ERROR)
            return

        mount_btn.disabled   = True
        mount_status.value   = "Mounting..."
        mount_status.color   = C_TEXT_DIM
        mount_status.visible = True
        page.update()

        def _do():
            log.info(f"MOUNT start — bucket: {ruta}, profile: {perfil_rclone}")
            try:
                backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
                mp = backend.resolver_mount_point_destino(perfil_rclone, ruta)

                # Esperar a que el mount esté listo (máx 30s: 150 × 0.2s)
                sistema = platform.system()
                for _ in range(150):
                    time.sleep(0.2)
                    try:
                        os.listdir(mp)
                        break
                    except OSError:
                        pass

                time.sleep(2)  # espera extra antes de abrir el explorador

                mounted_state[ruta] = mp
                log.info(f"MOUNT success — bucket: {ruta}, path: {mp}")

                # Abrir explorador
                try:
                    if sistema == "Windows":
                        os.startfile(mp)
                    else:
                        subprocess.Popen({"Darwin": ["open"], "Linux": ["xdg-open"]}[sistema] + [mp])
                except Exception as ex:
                    print(f"[mount] Could not open explorer: {ex}")

                def _ok():
                    mount_btn.disabled   = False
                    mount_status.value   = "✅ Mounted!"
                    mount_status.color   = C_ACCENT
                    def _clear_status():
                        time.sleep(3)
                        def _hide():
                            mount_status.value   = ""
                            mount_status.visible = False
                            page.update()
                        backend.ui_call(page, _hide)
                    threading.Thread(target=_clear_status, daemon=True).start()
                    threading.Timer(0.2, dest_browser_refresh).start()
                    page.update()
                backend.ui_call(page, _ok)
            except backend.WinFspMissingError:
                log.info(f"MOUNT error (WinFsp missing) — bucket: {ruta}")
                def _ask():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    _prompt_install_winfsp(on_success=lambda: do_mount(e, ruta))
                backend.ui_call(page, _ask)
            except EnvironmentError as ex:
                err_str = str(ex)
                log.info(f"MOUNT error (FUSE/WinFSP) — bucket: {ruta} — {err_str}")
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
                backend.ui_call(page, _err)
            except Exception as ex:
                err_str = str(ex)
                log.info(f"MOUNT error — bucket: {ruta} — {err_str}")
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "Mount error", err_str, C_ERROR)
                backend.ui_call(page, _err)

        backend.safe_thread(page, _do).start()

    mount_btn.on_click = do_mount

    dest_browser, dest_browser_refresh, unmount_all_btn  = build_rclone_browser(
        page, perfil_rclone,
        on_select=on_browser_select,
        on_double_tap_mount=lambda path: do_mount(None, path),
        mounted_state=mounted_state
    )
    dest_browser_col = ft.Column(
        [field_label(f"Bucket in {perfil_rclone}"), dest_browser],
        spacing=4,
        tight=True,
    )

    # ── Layout ────────────────────────────────────────────────────────────
    content = ft.Column(
        [
            build_header(no_ldap=NO_LDAP, subtitle=f"Mount — {perfil_rclone}"),
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
