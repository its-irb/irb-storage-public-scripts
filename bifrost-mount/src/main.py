"""
BIFROST MOUNT — IRB MinIO Mount Tool — FRONTEND (Flet)
======================================================

Migración de tkinter a Flet.
Soporta modo desktop (Mac, Windows, Linux).

Uso:
    python main.py             # desktop

Flujo de vistas:
    view_update → view_login → view_minio → view_credentials (auto) → view_mount

Notas sobre credenciales STS:
  - Si quedan MÁS de 3 días → se salta la renovación y va directo a view_mount
  - Si quedan MENOS de 3 días (o no hay credenciales) → renueva automáticamente
    por 7 días, mostrando el progreso en un log en pantalla

"""

from __future__ import annotations

import os
import sys
import io
import getpass
import subprocess
import threading
import time
import platform
import atexit
import signal
from typing import Callable
import pathlib
from datetime import datetime

import flet as ft

from bifrost_backend import backend
from bifrost_frontend.frontend import *
from version import __version__

# ============================================================================
# MODO DE EJECUCIÓN
# ============================================================================

# Máquinas sin acceso a LDAP pero con acceso a MinIO (ej. IVIS).
# Setear BIFROST_NO_LDAP=1 como variable de sistema para saltarse la validación LDAP.
NO_LDAP = os.environ.get("BIFROST_NO_LDAP") == "1"

# Umbral (en días) por debajo del cual se renuevan las credenciales STS automáticamente
STS_RENEWAL_THRESHOLD_DAYS = 3
# Duración (en días) de las credenciales STS renovadas automáticamente
STS_AUTO_RENEWAL_DAYS = 7


# ============================================================================
# PARA EVITAR PROBLEMAS DE CODIFICACIÓN EN CONSOLA (ESPECIALMENTE EN WINDOWS)
# ============================================================================
try:
    if sys.stdout and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    if sys.stderr and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
except Exception:
    pass



# ── Log persistente ───────────────────────────────────────────────────────
_LOG_DIR  = pathlib.Path.home() / "bifrost-mount-logs"
_LOG_FILE = _LOG_DIR / f"bifrost-mount-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

def _write_to_log_file(msg: str) -> None:
    """Escribe msg en el fichero de log de sesión con timestamp. Falla silenciosamente."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            line = msg if msg.endswith("\n") else msg + "\n"
            f.write(f"[{timestamp}] {line}")
    except Exception:
        pass


def _log_event(msg: str) -> None:
    """Registra un evento de usuario en el log de sesión."""
    _write_to_log_file(msg)



# ============================================================================
# VISTA: LOGIN LDAP
# ============================================================================

_LDAP_ERROR_MESSAGES = {
    "vpn":     "⚠️ Cannot reach the IRB network. Are you connected to the VPN?",
    "network": "⚠️ Could not reach the LDAP server. Try again or contact ITS.",
    "error":   "⚠️ Unexpected error validating credentials. Contact ITS.",
}
# user_not_found / invalid_password no están a propósito: usan el mensaje por defecto.


def _build_login_content(
    page: ft.Page,
    on_success: Callable,
) -> ft.Control:

    try:
        default_user = getpass.getuser()
    except Exception:
        default_user = ""

    user_tf, user_col = styled_field(
        "Username",
        value=default_user,
        hint="your.username",
    )
    pass_tf, pass_col = styled_field("Password", password=True)

    error_text = ft.Text("", color=C_ERROR, size=12, visible=False)
    loading    = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                  color=C_PRIMARY, visible=False)
    login_btn  = btn_primary("Authenticate", width=280)

    def _set_busy(busy: bool):
        """Bloquea el formulario mientras se valida (evita doble envío y edición)."""
        login_btn.disabled = user_tf.disabled = pass_tf.disabled = busy
        loading.visible = busy

    def _show_error(msg: str):
        error_text.value   = msg
        error_text.visible = True
        _set_busy(False)
        page.update()

    def do_login(e=None):
        user = (user_tf.value or "").strip()
        pwd  = pass_tf.value or ""
        if not user or not pwd:
            error_text.value   = "Username is required." if not user else "Password is required."
            error_text.visible = True
            page.update()
            return

        _set_busy(True)
        error_text.visible = False
        page.update()

        def _auth():
            creds = {"usuario": user, "password": pwd}
            _log_event(f"LOGIN attempt — user: {user}")
            if NO_LDAP:
                _log_event(f"LOGIN bypass LDAP — user: {user}")
                backend.ui_call(page, lambda: on_success(creds))
                return
            ok, motivo = backend.validar_credenciales_ldap(creds)
            if ok:
                _log_event(f"LOGIN success — user: {user}")
                backend.ui_call(page, lambda: on_success(creds))
            else:
                msg = _LDAP_ERROR_MESSAGES.get(motivo, "Invalid credentials. Please try again.")
                _log_event(f"LOGIN failed — user: {user} — reason: {motivo}")
                backend.ui_call(page, lambda: _show_error(msg))

        backend.safe_thread(page, _auth).start()

    login_btn.on_click = do_login
    pass_tf.on_submit  = do_login
    user_tf.on_submit  = lambda e: pass_tf.focus()

    content = ft.Column(
        [
            build_header(no_ldap=NO_LDAP, subtitle="Authentication"),
            ft.Container(expand=True),
            ft.Row(
                [
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Icon(ft.Icons.LOCK_OUTLINE, color=C_PRIMARY, size=32),
                                ft.Container(height=8),
                                ft.Text("LDAP Authentication", size=18,
                                        weight=ft.FontWeight.W_600, color=C_TEXT),
                                ft.Text("Use your IRB network credentials",
                                        size=12, color=C_TEXT_DIM),
                                ft.Container(height=24),
                                user_col,
                                ft.Container(height=12),
                                pass_col,
                                ft.Container(height=8),
                                error_text,
                                ft.Container(height=16),
                                ft.Row(
                                    [loading, login_btn],
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=12,
                                ),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=0,
                            width=360,
                        ),
                        bgcolor=C_SURFACE,
                        border=ft.Border.all(1, C_BORDER),
                        border_radius=12,
                        padding=36,
                    )
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            ft.Container(expand=True),
        ],
        expand=True,
        spacing=0,
    )

    return content


# ============================================================================
# VISTA: SELECCIÓN DE SERVIDOR MINIO
# ============================================================================

def _build_minio_content(page: ft.Page, on_continue: Callable) -> ft.Control:
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
            build_header(no_ldap=NO_LDAP, subtitle="MinIO Server"),
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


# ============================================================================
# VISTA: CREDENCIALES STS — RENOVACIÓN AUTOMÁTICA
# ============================================================================

def _build_credentials_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    credenciales_ldap: dict,
    on_continue: Callable,
    extra_config: dict | None = None,
    duracion_dias: int | None = None,
    on_back: Callable | None = None,
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
        _write_to_log_file(msg) 
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

        log("\n✅ Done. Loading mount interface...", C_ACCENT)

        def _finish():
            progress.visible  = False
            status_text.value = "✓ Credentials renewed. Loading..."
            status_text.color = C_ACCENT

        backend.ui_call(page, _finish)
        time.sleep(1.2)
        backend.ui_call(page, on_continue)

    content = ft.Column(
        [
            build_header(no_ldap=NO_LDAP, subtitle="S3 Credentials — Auto Renewal"),
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
        _log_event(f"BUCKET selected — {bucket_name}")
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
            _log_event(f"UNMOUNT ALL — {len(mounted_state)} mounts")
            for bname, mp in list(mounted_state.items()):
                try:
                    backend.desmontar_punto_montaje(mp)
                except OSError as ex:
                    _log_event(f"UNMOUNT error — bucket: {bname} — {ex}")
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
                    _log_event(f"UNMOUNT error — bucket: {bname} — {ex}")
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
            def _err():
                loading_row.visible = False
                error_text.value    = f"Error loading buckets: {ex}"
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
            show_screen(_build_credentials_content(
                page,
                perfil_rclone=perfil_rclone,
                endpoint=endpoint,
                credenciales_ldap=credenciales_ldap,
                on_continue=on_renew_complete,
                extra_config=extra_config,
                duracion_dias=dias_int,
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
                    ok = backend.install_winfsp_windows(page=page, on_progress=_on_progress)
                except Exception as ex:
                    err = str(ex)
                    _log_event(f"WINFSP install error — {err}")
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
                        _log_event("WINFSP install success")
                        on_success()
                    else:
                        _log_event("WINFSP install cancelled")
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
            _log_event(f"MOUNT start — bucket: {ruta}, profile: {perfil_rclone}")
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
                _log_event(f"MOUNT success — bucket: {ruta}, path: {mp}")

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
                _log_event(f"MOUNT error (WinFsp missing) — bucket: {ruta}")
                def _ask():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    _prompt_install_winfsp(on_success=lambda: do_mount(e, ruta))
                backend.ui_call(page, _ask)
            except EnvironmentError as ex:
                err_str = str(ex)
                _log_event(f"MOUNT error (FUSE/WinFSP) — bucket: {ruta} — {err_str}")
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "FUSE / WinFSP not detected", err_str, C_ERROR)
                backend.ui_call(page, _err)
            except Exception as ex:
                err_str = str(ex)
                _log_event(f"MOUNT error — bucket: {ruta} — {err_str}")
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



# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
    _log_event(f"APP start — bifrost-mount v{__version__}")
    apply_theme(page)

    state = {
        "credenciales_ldap": None,
        "servidor_minio":    None,
        "perfil_rclone":     None,
        "endpoint":          None,
        "mounted_per_perfil": {},
    }

    _cleanup_done = {"value": False}

    def _cleanup_on_exit():
        # Puede llegar por atexit normal Y por señal — evitar doble desmontaje.
        if _cleanup_done["value"]:
            return
        _cleanup_done["value"] = True
        print("[atexit] Cleaning up...")
        backend.desmontar_todos_los_mounts_s3()

    atexit.register(_cleanup_on_exit)

    def _handle_termination_signal(signum, frame):
        # DCV/Open OnDemand puede matar la sesión con SIGTERM/SIGINT al cerrarse
        # abruptamente. Sin este handler, atexit no llega a ejecutarse y el
        # mount FUSE queda colgado para la siguiente sesión.
        nombre_senal = signal.Signals(signum).name
        print(f"[signal] Received {nombre_senal}, cleaning up before exit...")
        _cleanup_on_exit()
        sys.exit(0)

    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, _handle_termination_signal)
        except (ValueError, OSError):
            pass  # solo se puede registrar en el hilo principal; en otros contextos se ignora

    async def on_window_event(e: ft.WindowEvent):
        if e.type == ft.WindowEventType.CLOSE:
            print("[close] Starting cleanup...")
            _cleanup_on_exit()
            print("[close] Cleanup done, destroying window...")
            await page.window.destroy()
            print("[close] Window destroyed")
            os._exit(0)

    page.window.on_event   = on_window_event
    page.window.prevent_close = True

    body = ft.Container(expand=True, bgcolor=C_BG)
    page.scroll = ft.ScrollMode.AUTO
    page.add(body)
    page.update()

    def show_screen(content: ft.Control):
        body.content = content
        page.update()

    def go_login():
        show_screen(_build_login_content(page, on_success=on_login_success))

    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds
        go_minio()

    def go_minio():
        show_screen(_build_minio_content(page, on_continue=on_minio_selected))

    def on_minio_selected(eleccion: dict):
        state["servidor_minio"] = eleccion["servidor"]
        state["perfil_rclone"]  = eleccion["perfil"]
        state["endpoint"]       = eleccion["endpoint"]
        _log_event(f"PROFILE selected — {eleccion['perfil']} ({eleccion['endpoint']})")
        _go_credentials_or_mount()

    def _go_credentials_or_mount():
        perfil         = state["perfil_rclone"]
        usuario_actual = state["credenciales_ldap"]["usuario"]

        info          = backend.get_session_info(perfil)
        needs_renewal = info is None or info.needs_renewal(usuario_actual, STS_RENEWAL_THRESHOLD_DAYS)
        if info is not None:
            print(f"[credentials] {'Renewal needed' if needs_renewal else 'Token valid → skipping renewal'} — "
                  f"token user: {info.usuario!r}, login user: {usuario_actual!r}, "
                  f"expiry: {info.remaining_text()}")

        if needs_renewal:
            servidor     = state["servidor_minio"]
            extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")
            show_screen(_build_credentials_content(
                page,
                perfil_rclone=perfil,
                endpoint=state["endpoint"],
                credenciales_ldap=state["credenciales_ldap"],
                on_continue=go_mount,
                extra_config=extra_config,
                on_back=go_login if NO_LDAP else None,
            ))
        else:
            go_mount()

    def go_mount():
        servidor     = state["servidor_minio"]
        perfil       = state["perfil_rclone"]
        extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")

        # Recuperar o crear el mounted_state para este perfil
        mounted_state = state["mounted_per_perfil"].setdefault(perfil, {})

        show_screen(_build_mount_bucket(
            page,
            perfil_rclone=perfil,
            endpoint=state["endpoint"],
            credenciales_ldap=state["credenciales_ldap"],
            extra_config=extra_config,
            on_renew_complete=go_mount,
            show_screen=show_screen,
            mounted_state=mounted_state,
            on_back=go_minio,
        ))


    show_screen(build_update_content(page, on_continue=go_login))

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    ft.run(main)