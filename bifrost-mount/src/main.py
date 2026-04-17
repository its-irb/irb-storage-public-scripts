from __future__ import annotations
import time


"""
IRB MinIO Rclone Data Transfer Tool — FRONTEND (Flet)
=====================================================

Migración de tkinter a Flet.
Soporta modo desktop (Mac, Windows, Linux).

Uso:
    python main.py             # desktop
    BIFROST_LINUX=1 python main.py  # simular modo Linux cluster

Flujo de vistas:
    view_update → view_login → view_minio → view_credentials (auto) → view_mount

Notas sobre credenciales STS:
  - Si quedan MÁS de 3 días → se salta la renovación y va directo a view_mount
  - Si quedan MENOS de 3 días (o no hay credenciales) → renueva automáticamente
    por 7 días, mostrando el progreso en un log en pantalla

En Linux cluster (IS_LINUX_CLUSTER=True):
  - La vista de montado incluye una sección CIFS con checkboxes para montar shares
  - Botón opcional para usar credenciales de admin (admin_<usuario>)
"""

import os
import sys
import io
import stat
import getpass
import tempfile
import subprocess
import threading
import traceback
from typing import Callable

import flet as ft

import sys, os
# Dev: añadir shared/ al path si no está ya en él
_shared = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
if os.path.isdir(_shared):
    sys.path.insert(0, os.path.abspath(_shared))

import backend


# ============================================================================
# MODO DE EJECUCIÓN
# ============================================================================

# En Linux cluster el flujo incluye CIFS; en el resto se omite
# Para desarrollo local: BIFROST_LINUX = "1"
IS_LINUX_CLUSTER = (sys.platform == "linux" and "_linux_cluster" in os.path.basename(
    sys.argv[0] if sys.argv else ""
)) or os.environ.get("BIFROST_LINUX") == "1"

# Umbral (en días) por debajo del cual se renuevan las credenciales STS automáticamente
STS_RENEWAL_THRESHOLD_DAYS = 3
# Duración (en días) de las credenciales STS renovadas automáticamente
STS_AUTO_RENEWAL_DAYS = 7

# ============================================================================
# HELPER THREAD-SAFE PARA ACTUALIZAR UI
# ============================================================================

def ui_call(page: ft.Page, fn: Callable) -> None:
    page.run_thread(fn)

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


# ============================================================================
# WRAPPER SEGURO PARA HILOS — captura excepciones y las muestra en diálogo
# ============================================================================

def safe_thread(page: ft.Page, target: Callable, daemon: bool = True) -> threading.Thread:
    def _wrapper():
        try:
            target()
        except Exception as exc:
            tb = traceback.format_exc()
            print(f"[safe_thread] Unhandled exception:\n{tb}")
            def _show():
                show_dialog(
                    page,
                    "Unexpected error",
                    f"{type(exc).__name__}: {exc}\n\nCheck console or contact ITS.",
                    C_ERROR,
                )
            ui_call(page, _show)

    t = threading.Thread(target=_wrapper, daemon=daemon)
    return t

# ============================================================================
# PALETA DE COLORES Y HELPERS DE ESTILO
# ============================================================================

C_BG       = "#0D1117"
C_SURFACE  = "#161B22"
C_SURFACE2 = "#21262D"
C_BORDER   = "#30363D"
C_PRIMARY  = "#58A6FF"
C_ACCENT   = "#3FB950"
C_WARNING  = "#D29922"
C_ERROR    = "#F85149"
C_TEXT     = "#E6EDF3"
C_TEXT_DIM = "#8B949E"
C_OVERLAY  = "#1C2027"
FONT_MONO  = "Courier New"


def btn_primary(text: str, on_click=None, width=None, disabled=False) -> ft.Button:
    return ft.Button(
        content=ft.Text(text),
        on_click=on_click,
        disabled=disabled,
        width=width,
        style=ft.ButtonStyle(
            bgcolor={
                ft.ControlState.DEFAULT:  C_PRIMARY,
                ft.ControlState.HOVERED:  "#79B8FF",
                ft.ControlState.DISABLED: C_BORDER,
            },
            color={
                ft.ControlState.DEFAULT:  "#0D1117",
                ft.ControlState.DISABLED: C_TEXT_DIM,
            },
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.Padding.symmetric(horizontal=20, vertical=12),
        ),
    )


def btn_secondary(text: str, on_click=None, width=None) -> ft.OutlinedButton:
    return ft.OutlinedButton(
        content=ft.Text(text),
        on_click=on_click,
        width=width,
        style=ft.ButtonStyle(
            color=C_TEXT,
            side=ft.BorderSide(1, C_BORDER),
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.Padding.symmetric(horizontal=20, vertical=12),
        ),
    )


def card(content: ft.Control, padding=20) -> ft.Container:
    return ft.Container(
        content=content,
        bgcolor=C_SURFACE,
        border=ft.Border.all(1, C_BORDER),
        border_radius=10,
        padding=padding,
    )


def section_title(text: str) -> ft.Text:
    return ft.Text(
        text,
        size=11,
        weight=ft.FontWeight.W_600,
        color=C_TEXT_DIM,
        font_family=FONT_MONO,
    )


def field_label(text: str) -> ft.Text:
    return ft.Text(text, size=12, color=C_TEXT_DIM, weight=ft.FontWeight.W_500)


def styled_field(
    label: str,
    password: bool = False,
    value: str = "",
    disabled: bool = False,
    hint: str = "",
    on_change=None,
    multiline: bool = False,
    min_lines: int = 1,
    max_lines: int = 1,
) -> tuple[ft.TextField, ft.Column]:
    tf = ft.TextField(
        value=value,
        password=password,
        can_reveal_password=password,
        disabled=disabled,
        hint_text=hint,
        on_change=on_change,
        multiline=multiline,
        min_lines=min_lines,
        max_lines=max_lines,
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        hint_style=ft.TextStyle(color=C_TEXT_DIM),
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=10),
        text_size=13,
    )
    col = ft.Column([field_label(label), tf], spacing=4, tight=True)
    return tf, col


def status_badge(text: str, color: str) -> ft.Container:
    return ft.Container(
        content=ft.Text(text, size=11, color=color, weight=ft.FontWeight.W_600),
        bgcolor=f"{color}22",
        border=ft.Border.all(1, f"{color}55"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
    )


# ============================================================================
# HEADER COMÚN
# ============================================================================

def build_header(subtitle: str = "") -> ft.Container:
    version_str = f"v{backend.__version__}" if hasattr(backend, "__version__") else ""
    return ft.Container(
        content=ft.Row(
            [
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(
                                    "BIFROST - MOUNT",
                                    size=22,
                                    weight=ft.FontWeight.W_700,
                                    color=C_PRIMARY,
                                    font_family=FONT_MONO,
                                ),
                                ft.Container(width=8),
                                status_badge("DESKTOP", C_WARNING),
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Text(subtitle or "IRB MinIO Mount Tool", size=12, color=C_TEXT_DIM),
                    ],
                    spacing=2,
                    expand=True,
                ),
                ft.Text(version_str, size=11, color=C_TEXT_DIM, font_family=FONT_MONO),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE,
        border=ft.Border.only(bottom=ft.BorderSide(1, C_BORDER)),
        padding=ft.Padding.symmetric(horizontal=24, vertical=16),
        margin=ft.Margin.only(bottom=24),
    )


# ============================================================================
# DIÁLOGOS GENÉRICOS
# ============================================================================

def show_dialog(
    page: ft.Page,
    title: str,
    message: str,
    color: str = C_TEXT,
    actions: list | None = None,
):
    def close(e=None):
        page.pop_dialog()

    if not actions:
        actions = [btn_primary("OK", on_click=close)]

    icon = (
        ft.Icons.CHECK_CIRCLE_OUTLINE   if color == C_ACCENT  else
        ft.Icons.ERROR_OUTLINE          if color == C_ERROR   else
        ft.Icons.WARNING_AMBER_OUTLINED if color == C_WARNING else
        ft.Icons.INFO_OUTLINE
    )

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Row(
            [
                ft.Icon(icon, color=color, size=20),
                ft.Text(title, color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
            ],
            spacing=8,
        ),
        content=ft.Text(message, color=C_TEXT_DIM, size=13),
        actions=actions,
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.show_dialog(dlg)
    page.update()


def show_confirm(
    page: ft.Page,
    title: str,
    message: str,
    on_yes: Callable,
    on_no: Callable | None = None,
):
    def yes(e):
        page.pop_dialog()
        on_yes()

    def no(e):
        page.pop_dialog()
        if on_no:
            on_no()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Text(title, color=C_TEXT, size=15, weight=ft.FontWeight.W_600),
        content=ft.Text(message, color=C_TEXT_DIM, size=13),
        actions=[btn_secondary("No", on_click=no), btn_primary("Yes", on_click=yes)],
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.show_dialog(dlg)
    page.update()


# ============================================================================
# VISTA: ACTUALIZACIÓN
# ============================================================================

def _build_update_content(page: ft.Page, on_continue: Callable) -> ft.Control:
    status_text = ft.Text("Checking for updates...", color=C_TEXT_DIM, size=13)
    progress    = ft.ProgressBar(color=C_PRIMARY, bgcolor=C_SURFACE2, width=300)
    update_btn  = btn_primary("Update now")
    skip_btn    = btn_secondary("Continue anyway")
    update_btn.visible = False
    skip_btn.visible   = False

    def check():
        try:
            ultima = backend.check_update_version(force_update="--update" in sys.argv)
            if ultima:
                def _show_update():
                    status_text.value  = f"New version available: {ultima}"
                    status_text.color  = C_WARNING
                    progress.visible   = False
                    update_btn.visible = True
                    skip_btn.visible   = True
                ui_call(page, _show_update)
            else:
                def _show_ok():
                    status_text.value = "✓ You are using the latest version."
                    status_text.color = C_ACCENT
                    progress.visible  = False
                ui_call(page, _show_ok)
                import time; time.sleep(1)
                ui_call(page, on_continue)
        except Exception as e:
            def _show_err():
                status_text.value = f"Could not check updates: {e}"
                status_text.color = C_TEXT_DIM
                progress.visible  = False
            ui_call(page, _show_err)
            import time; time.sleep(0.5)
            ui_call(page, on_continue)

    def do_update(e):
        update_btn.disabled = True
        progress.visible    = True
        status_text.value   = "Downloading update..."
        status_text.color   = C_TEXT_DIM
        page.update()

        def _download():
            try:
                nueva_ruta  = backend.download_new_binary("bifrost")
                ruta_actual = os.path.abspath(sys.argv[0])
                if sys.platform == "win32":
                    _escribir_y_lanzar_updater_windows(ruta_actual, nueva_ruta)
                else:
                    os.replace(nueva_ruta, ruta_actual)
                    os.chmod(ruta_actual, os.stat(ruta_actual).st_mode | stat.S_IEXEC)
                    ui_call(page, lambda: show_dialog(
                        page, "Updated",
                        "Restart the application to use the new version.",
                        C_ACCENT,
                    ))
            except Exception as ex:
                ui_call(page, lambda: show_dialog(page, "Update failed", str(ex), C_ERROR))

        safe_thread(page, _download).start()

    skip_btn.on_click   = lambda e: ui_call(page, on_continue)
    update_btn.on_click = do_update

    content = ft.Column(
        [
            build_header("Checking for updates"),
            ft.Container(expand=True),
            ft.Column(
                [
                    ft.Icon(ft.Icons.SYNC, color=C_PRIMARY, size=48),
                    ft.Text("BIFROST MOUNT", size=32, weight=ft.FontWeight.W_700,
                            color=C_TEXT, font_family=FONT_MONO),
                    ft.Text("IRB MinIO Mount Tool", size=14, color=C_TEXT_DIM),
                    ft.Container(height=24),
                    progress,
                    status_text,
                    ft.Container(height=16),
                    ft.Row([update_btn, skip_btn],
                           alignment=ft.MainAxisAlignment.CENTER, spacing=12),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8,
            ),
            ft.Container(expand=True),
        ],
        expand=True,
        spacing=0,
    )

    if backend.should_check_for_updates():
        safe_thread(page, check).start()
    else:
        def _skip():
            import time
            time.sleep(0.1)
            ui_call(page, on_continue)
        safe_thread(page, _skip).start()

    return content


# ============================================================================
# VISTA: LOGIN LDAP
# ============================================================================

def _build_login_content(
    page: ft.Page,
    on_success: Callable,
    allow_custom_user: bool = True,
) -> ft.Control:

    try:
        default_user = getpass.getuser()
    except Exception:
        default_user = ""

    user_tf, user_col = styled_field(
        "Username",
        value=default_user,
        disabled=False,
        hint="your.username",
    )
    pass_tf, pass_col = styled_field("Password", password=True)

    error_text = ft.Text("", color=C_ERROR, size=12, visible=False)
    loading    = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                  color=C_PRIMARY, visible=False)
    login_btn  = btn_primary("Authenticate", width=280)

    def do_login(e=None):
        user = (user_tf.value or "").strip()
        pwd  = (pass_tf.value or "").strip()
        if not user or not pwd:
            error_text.value   = "Username and password are required."
            error_text.visible = True
            page.update()
            return

        login_btn.disabled = True
        loading.visible    = True
        error_text.visible = False
        page.update()

        def _auth():
            creds = {"usuario": user, "password": pwd}
            ok    = backend.validar_credenciales_ldap(creds)
            if ok:
                ui_call(page, lambda: on_success(creds))
            else:
                def _fail():
                    error_text.value   = "Invalid credentials. Please try again."
                    error_text.visible = True
                    login_btn.disabled = False
                    loading.visible    = False
                ui_call(page, _fail)

        safe_thread(page, _auth).start()

    login_btn.on_click = do_login
    pass_tf.on_submit  = do_login
    user_tf.on_submit  = lambda e: pass_tf.focus()

    content = ft.Column(
        [
            build_header("Authentication"),
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
                            ft.Text(info["endpoint"], size=11, color=C_TEXT_DIM, font_family=FONT_MONO),
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
            build_header("MinIO Server"),
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
    status_text = ft.Text("Renewing credentials...", size=13, color=C_TEXT_DIM,
                           font_family=FONT_MONO)

    def log(msg: str, color: str = C_TEXT):
        print(msg.rstrip())
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, selectable=True)
            )
        ui_call(page, _add)

    def _do_renew():
        import time
        from datetime import timedelta

        duracion_segundos = (duracion_dias or STS_AUTO_RENEWAL_DAYS) * 86400

        token_actual = backend.get_rclone_session_token(perfil_rclone)
        if token_actual:
            tiempo = backend.get_expiration_from_session_token(token_actual)
            if tiempo:
                log(f"⚠️  Current credentials expire in: {tiempo}", C_WARNING)
                log(f"    (threshold: {STS_RENEWAL_THRESHOLD_DAYS} days → renewal required)", C_TEXT_DIM)
            else:
                log("⚠️  Could not read expiry from current token.", C_WARNING)
        else:
            log("⚠️  No credentials found for this profile.", C_WARNING)

        log(f"\n🔄 Requesting new STS credentials ({STS_AUTO_RENEWAL_DAYS} days)...", C_PRIMARY)
        log(f"   Profile  : {perfil_rclone}", C_TEXT_DIM)
        log(f"   Endpoint : {endpoint}", C_TEXT_DIM)
        log(f"   User     : {credenciales_ldap['usuario']}", C_TEXT_DIM)

        creds = backend.get_credentials(
            endpoint,
            credenciales_ldap["usuario"],
            credenciales_ldap["password"],
            duracion_segundos,
        )

        if creds is None:
            log("\n❌ Failed to obtain credentials. Check your password or contact ITS.", C_ERROR)
            def _show_err():
                progress.visible  = False
                status_text.value = "❌ Renewal failed."
                status_text.color = C_ERROR
            ui_call(page, _show_err)
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

        new_token = backend.get_rclone_session_token(perfil_rclone)
        if new_token:
            nuevo_tiempo = backend.get_expiration_from_session_token(new_token)
            if nuevo_tiempo:
                dias_renovados = duracion_dias or STS_AUTO_RENEWAL_DAYS
                log(f"   New credentials expire in: {dias_renovados} days", C_ACCENT)

        log(f"\n✅ Done. Loading mount interface...", C_ACCENT)

        def _finish():
            progress.visible  = False
            status_text.value = "✓ Credentials renewed. Loading..."
            status_text.color = C_ACCENT

        ui_call(page, _finish)
        time.sleep(1.2)
        ui_call(page, on_continue)

    content = ft.Column(
        [
            build_header("S3 Credentials — Auto Renewal"),
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

    safe_thread(page, _do_renew).start()
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
    on_double_tap_mount: Callable[[str], None] | None = None,
    mounted_state: dict | None = None,
) -> tuple[ft.Column, Callable]:
    """
    Lista los buckets disponibles en el perfil rclone.
    Al seleccionar uno, llama on_select(bucket_name).
    Doble click monta directamente si on_double_tap_mount está definido.
    mounted_state: dict compartido {bucket_name: mount_point} para trackear mounts.
    """
    if mounted_state is None:
        mounted_state = {}
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
        on_select(bucket_name)
        _render_buckets(selected_state.get("_all_buckets", []))

    def _select_and_mount(bucket_name: str):
        _select_bucket(bucket_name)
        if on_double_tap_mount:
            on_double_tap_mount(bucket_name)

    unmount_all_btn = btn_secondary("⊠  Unmount all")
    unmount_all_btn.visible = False

    def _unmount_bucket(bucket_name: str):
        mp = mounted_state.get(bucket_name)
        if not mp:
            return
        def _do():
            try:
                backend.desmontar_punto_montaje(mp)
            except Exception as ex:
                print(f"[unmount] Error: {ex}")
            finally:
                mounted_state.pop(bucket_name, None)
            def _refresh():
                if selected_state["bucket"] == bucket_name:
                    selected_state["bucket"] = None
                    on_select("")          # notificar al caller
                _render_buckets(selected_state.get("_all_buckets", []))
            ui_call(page, _refresh)
        threading.Thread(target=_do, daemon=True).start()

    def _unmount_all():
        def _do():
            for bname, mp in list(mounted_state.items()):
                try:
                    backend.desmontar_punto_montaje(mp)
                except Exception as ex:
                    print(f"[unmount_all] Error {bname}: {ex}")
                finally:
                    mounted_state.pop(bname, None)
            def _refresh():
                selected_state["bucket"] = None
                on_select("")
                _render_buckets(selected_state.get("_all_buckets", []))
            ui_call(page, _refresh)
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

                unmount_btn = ft.IconButton(
                    icon=ft.Icons.EJECT_OUTLINED,
                    icon_color=C_ERROR,
                    icon_size=16,
                    tooltip="Unmount",
                    visible=is_mounted,
                    on_click=lambda e, b=bname: _unmount_bucket(b),
                )

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
                                #unmount_btn,
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
        ui_call(page, _set_loading)

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
            ui_call(page, _show)

        except Exception as ex:
            def _err():
                loading_row.visible = False
                error_text.value    = f"Error loading buckets: {ex}"
                error_text.visible  = True
                page.update()
            ui_call(page, _err)

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
            #unmount_all_btn,
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
    mounts_activos: list,
    on_close: Callable,
    endpoint: str,
    credenciales_ldap: dict,
    extra_config: dict | None,
    on_renew_complete: Callable,
    show_screen: Callable,
    mounted_state: dict | None = None,
    on_back: Callable | None = None,
) -> ft.Control:
    usuario_actual = credenciales_ldap["usuario"]

    # ── Badge de expiración de credenciales ───────────────────────────────
    token_actual  = backend.get_rclone_session_token(perfil_rclone)
    tiempo_expira = backend.get_expiration_from_session_token(token_actual) if token_actual else None

    if tiempo_expira:
        dias        = tiempo_expira.days
        color_badge = C_ERROR if dias < 1 else C_WARNING if dias <= STS_RENEWAL_THRESHOLD_DAYS else C_ACCENT
        expiry_text = f"🔑 Credentials expire in {dias}d {tiempo_expira.seconds // 3600}h"
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

    # ── Sección CIFS (solo Linux) ─────────────────────────────────────────
    if IS_LINUX_CLUSTER:
        cifs_shares_col   = ft.Column(spacing=6, tight=True)
        cifs_loading      = ft.Row(
            [
                ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
                ft.Text("Loading shares...", size=11, color=C_TEXT_DIM),
            ],
            spacing=8, visible=False,
        )
        cifs_error        = ft.Text("", color=C_ERROR, size=11, visible=False)
        cifs_status       = ft.Text("", color=C_TEXT_DIM, size=11, visible=False)
        cifs_checkboxes: dict[str, ft.Checkbox] = {}
        mount_cifs_btn    = btn_secondary("⊞  Mount selected shares")
        admin_creds_state = {"usando": False, "credenciales": None}

        admin_badge = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.VERIFIED_USER, color=C_ACCENT, size=14),
                    ft.Text("Using admin credentials", size=11, color=C_ACCENT),
                ],
                spacing=6,
            ),
            bgcolor=f"{C_ACCENT}18",
            border=ft.Border.all(1, f"{C_ACCENT}44"),
            border_radius=6,
            padding=ft.Padding.symmetric(horizontal=10, vertical=4),
            visible=False,
        )

        def _load_cifs_shares(creds_smb: dict | None = None):
            creds_to_use = creds_smb or credenciales_ldap

            def _set_loading():
                cifs_loading.visible = True
                cifs_error.visible   = False
                cifs_shares_col.controls.clear()
                page.update()
            ui_call(page, _set_loading)

            try:
                grupos = backend.get_ldap_groups(usuario_actual)
                shares = backend.obtener_shares_accesibles(
                    grupos,
                    usuario_actual,
                    creds_to_use["password"],
                    creds_to_use["usuario"],
                    backend.EXCEPCION_FILERS,
                    usar_privilegios=admin_creds_state["usando"],
                )
                perfiles = backend.obtener_perfiles_rclone_config()
                backend.configurar_perfiles_smb_si_faltan(shares, creds_to_use, perfiles)

                def _render():
                    cifs_loading.visible = False
                    cifs_shares_col.controls.clear()
                    cifs_checkboxes.clear()

                    if not shares:
                        cifs_shares_col.controls.append(
                            ft.Text("(no shares found)", size=11, color=C_TEXT_DIM, italic=True)
                        )
                    else:
                        for share in shares:
                            cb = ft.Checkbox(
                                label=f"{share['name']}  ({share['host']})",
                                value=False,
                                active_color=C_PRIMARY,
                                label_style=ft.TextStyle(color=C_TEXT, size=13),
                            )
                            cifs_checkboxes[share["name"]] = cb
                            cifs_shares_col.controls.append(cb)
                    page.update()

                ui_call(page, _render)

            except Exception as ex:
                def _err():
                    cifs_loading.visible = False
                    cifs_error.value     = f"Error loading shares: {ex}"
                    cifs_error.visible   = True
                    page.update()
                ui_call(page, _err)

        def _show_admin_dialog(e):
            admin_user  = f"admin_{usuario_actual}"
            pass_tf, pass_col = styled_field("Admin password", password=True)
            err = ft.Text("", color=C_ERROR, size=12, visible=False)

            def confirm(ev):
                pwd = (pass_tf.value or "").strip()
                if not pwd:
                    err.value   = "Password required."
                    err.visible = True
                    page.update()
                    return

                admin_creds = {"usuario": admin_user, "password": pwd}
                if not backend.validar_credenciales_ldap(admin_creds):
                    err.value   = "Invalid admin credentials."
                    err.visible = True
                    page.update()
                    return

                admin_creds_state["usando"]       = True
                admin_creds_state["credenciales"] = admin_creds
                page.pop_dialog()

                admin_badge.visible   = True
                use_admin_btn.visible = False
                page.update()

                safe_thread(page, lambda: _load_cifs_shares(admin_creds)).start()

            def cancel(ev):
                page.pop_dialog()

            dlg = ft.AlertDialog(
                modal=True,
                title=ft.Row(
                    [
                        ft.Icon(ft.Icons.ADMIN_PANEL_SETTINGS, color=C_PRIMARY, size=20),
                        ft.Text("Admin Credentials", color=C_TEXT, size=15,
                                weight=ft.FontWeight.W_600),
                    ],
                    spacing=8,
                ),
                content=ft.Column(
                    [
                        ft.Text(f"Username: {admin_user}", color=C_TEXT_DIM, size=12),
                        ft.Container(height=10),
                        pass_col,
                        err,
                    ],
                    spacing=6, tight=True, width=300,
                ),
                actions=[
                    btn_secondary("Cancel", on_click=cancel),
                    btn_primary("Confirm", on_click=confirm),
                ],
                bgcolor=C_OVERLAY,
                shape=ft.RoundedRectangleBorder(radius=10),
            )
            page.show_dialog(dlg)
            page.update()

        def do_mount_cifs(e):
            seleccionados = [n for n, cb in cifs_checkboxes.items() if cb.value]
            if not seleccionados:
                show_dialog(page, "Error", "Select at least one share.", C_ERROR)
                return

            mount_cifs_btn.disabled = True
            cifs_status.value   = "Mounting..."
            cifs_status.color   = C_TEXT_DIM
            cifs_status.visible = True
            page.update()

            def _mount():
                creds_to_use = admin_creds_state["credenciales"] or credenciales_ldap
                grupos  = backend.get_ldap_groups(usuario_actual)
                shares  = backend.obtener_shares_accesibles(
                    grupos, usuario_actual, creds_to_use["password"],
                    creds_to_use["usuario"], backend.EXCEPCION_FILERS,
                    usar_privilegios=admin_creds_state["usando"],
                )
                recursos = backend.construir_recursos_cifs_dict(shares, usuario_actual)
                fallidos = backend.montar_shares_seleccionados(
                    seleccionados, recursos, mounts_activos
                )

                def _after():
                    mount_cifs_btn.disabled = False
                    if fallidos:
                        cifs_status.value = f"❌ Could not mount: {', '.join(fallidos)}"
                        cifs_status.color = C_ERROR
                    else:
                        cifs_status.value = "✅ Shares mounted successfully."
                        cifs_status.color = C_ACCENT
                    page.update()

                ui_call(page, _after)

            safe_thread(page, _mount).start()

        use_admin_btn           = btn_secondary("🔑 Use admin credentials", on_click=_show_admin_dialog)
        mount_cifs_btn.on_click = do_mount_cifs
        threading.Thread(target=_load_cifs_shares, daemon=True).start()

        cifs_section = ft.Column(
            [
                section_title("CIFS SHARES"),
                ft.Container(height=10),
                card(
                    ft.Column(
                        [
                            cifs_loading,
                            cifs_error,
                            cifs_shares_col,
                            ft.Container(height=8),
                            ft.Row(
                                [mount_cifs_btn, cifs_status],
                                spacing=12,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Container(height=8),
                            ft.Row(
                                [use_admin_btn, admin_badge],
                                spacing=12,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                        ],
                        spacing=0,
                    ),
                ),
                ft.Container(height=16),
            ],
            spacing=0,
        )

    # ── Destino: selector de buckets ──────────────────────────────────────
    _dest_path = {"value": ""}
    if mounted_state is None:
        mounted_state = {}

    ruta_label = ft.Text(
        f"→ {perfil_rclone}: (select a bucket above)",
        size=12,
        color=C_WARNING,
        font_family=FONT_MONO,
    )

    def on_browser_select(path: str):
        _dest_path["value"] = path

    # ── Montar bucket ─────────────────────────────────────────────────────
    mount_btn    = btn_secondary("⊞  Mount bucket")
    mount_status = ft.Text("", size=12, color=C_TEXT_DIM, visible=False)

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
            try:
                backend.mount_rclone_S3_prefix_to_folder(perfil_rclone, ruta)
                mp = backend.resolver_mount_point_destino(perfil_rclone, ruta)

                # Esperar a que el mount esté listo (máx 10s)
                import time, platform as _platform
                sistema = _platform.system()
                for _ in range(50):
                    time.sleep(0.2)
                    try:
                        os.listdir(mp)
                        break
                    except OSError:
                        pass

                mounted_state[ruta] = mp

                # Abrir explorador
                try:
                    import time, platform as _platform
                    sistema = _platform.system()
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
                        import time; time.sleep(3)
                        def _hide():
                            mount_status.value   = ""
                            mount_status.visible = False
                            page.update()
                        ui_call(page, _hide)
                    threading.Thread(target=_clear_status, daemon=True).start()
                    threading.Timer(0.2, dest_browser_refresh).start()
                    page.update()
                ui_call(page, _ok)
            except EnvironmentError as ex:
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "FUSE / WinFSP not detected", str(ex), C_ERROR)
                ui_call(page, _err)
            except Exception as ex:
                def _err():
                    mount_btn.disabled   = False
                    mount_status.value   = ""
                    mount_status.visible = False
                    page.update()
                    show_dialog(page, "Mount error", str(ex), C_ERROR)
                ui_call(page, _err)

        safe_thread(page, _do).start()

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
            build_header(f"Mount — {perfil_rclone}"),
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
                        *([cifs_section] if IS_LINUX_CLUSTER else []),
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
# VERIFICACIÓN DE RCLONE EN DESKTOP
# ============================================================================

def check_rclone_installation_flet(page: ft.Page) -> None:
    if not backend.detect_rclone_installed():
        sistema = sys.platform
        if sistema == "darwin":
            show_dialog(
                page,
                "Rclone not found",
                "Download it with macos-third-party-assets-downloader.sh.\n",
                C_ERROR,
            )
            sys.exit(1)
        elif sistema == "win32":
            show_dialog(
                page,
                "Rclone.exe not found",
                "Download rclone.exe and place it in the same folder as this executable.\n"
                "https://rclone.org/downloads/\n\n"
                "Also install WinFsp from https://winfsp.dev/rel/",
                C_ERROR,
            )
            sys.exit(1)


# ============================================================================
# UPDATER WINDOWS
# ============================================================================

def _escribir_y_lanzar_updater_windows(ruta_actual: str, nueva_ruta: str) -> None:
    updater_code = f"""@echo off
setlocal
set "OLD_EXE={ruta_actual}"
set "NEW_EXE={nueva_ruta}"
echo Waiting for the application to close...
set /a i=0
:waitloop
if %i% geq 30 goto timeout_err
del /f "%OLD_EXE%" >nul 2>&1
if not exist "%OLD_EXE%" goto do_move
timeout /t 1 /nobreak >nul
set /a i+=1
goto waitloop
:do_move
move /y "%NEW_EXE%" "%OLD_EXE%"
if errorlevel 1 (echo ERROR: Could not replace executable. & pause & exit /b 1)
echo Update completed! Please reopen the application.
pause
exit /b 0
:timeout_err
echo ERROR: Timeout waiting for old executable.
pause
exit /b 1
"""
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".bat", mode="w", encoding="utf-8"
    ) as f:
        f.write(updater_code)
        updater_path = f.name
    subprocess.Popen(["cmd.exe", "/c", "start", "", updater_path], shell=False)
    os._exit(0)


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
    page.title             = "BIFROST MOUNT — IRB MinIO"
    page.bgcolor           = C_BG
    page.window.width      = 1100
    page.window.height     = 820
    page.window.min_width  = 800
    page.window.min_height = 600
    page.theme             = ft.Theme(color_scheme_seed=C_PRIMARY)
    page.theme_mode        = ft.ThemeMode.DARK
    page.padding           = 0

    state = {
        "credenciales_ldap": None,
        "mounts_activos":    [],
        "servidor_minio":    None,
        "perfil_rclone":     None,
        "endpoint":          None,
        "mounted_per_perfil": {},
    }

    import atexit

    def _cleanup_on_exit():
        print("[atexit] Cleaning up...")
        backend.desmontar_todos_los_mounts_s3()
        if IS_LINUX_CLUSTER and state["mounts_activos"]:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario") or getpass.getuser()
            try:
                backend.desmontar_todos_los_shares(usuario)
            except Exception as e:
                print(f"[atexit] Error unmounting shares: {e}")

    atexit.register(_cleanup_on_exit)

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

    def show_loading(message: str = "Loading..."):
        show_screen(
            ft.Column(
                [
                    ft.Container(expand=True),
                    ft.Column(
                        [
                            ft.ProgressRing(color=C_PRIMARY, width=48, height=48, stroke_width=4),
                            ft.Container(height=16),
                            ft.Text(message, size=14, color=C_TEXT_DIM),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=0,
                    ),
                    ft.Container(expand=True),
                ],
                expand=True,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            )
        )

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
        check_rclone_installation_flet(page)
        _go_credentials_or_mount()

    def _go_credentials_or_mount():
        from datetime import timedelta

        perfil         = state["perfil_rclone"]
        token          = backend.get_rclone_session_token(perfil)
        usuario_actual = state["credenciales_ldap"]["usuario"]

        needs_renewal = True
        if token:
            usuario_token = backend.get_usuario_from_session_token(token)
            tiempo        = backend.get_expiration_from_session_token(token)
            if (
                usuario_token == usuario_actual
                and tiempo
                and tiempo > timedelta(days=STS_RENEWAL_THRESHOLD_DAYS)
            ):
                needs_renewal = False
                print(f"[credentials] Token valid for {tiempo} → skipping renewal")
            else:
                print(f"[credentials] Renewal needed — token user: {usuario_token!r}, "
                      f"login user: {usuario_actual!r}, expiry: {tiempo}")

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
            ))
        else:
            go_mount()

    def go_mount():
        servidor     = state["servidor_minio"]
        perfil       = state["perfil_rclone"]
        extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")

        # Recuperar o crear el mounted_state para este perfil
        if perfil not in state["mounted_per_perfil"]:
            state["mounted_per_perfil"][perfil] = {}

        show_screen(_build_mount_bucket(
            page,
            perfil_rclone=state["perfil_rclone"],
            mounts_activos=state["mounts_activos"],
            on_close=do_close,
            endpoint=state["endpoint"],
            credenciales_ldap=state["credenciales_ldap"],
            extra_config=extra_config,
            on_renew_complete=go_mount,
            show_screen=show_screen,
            mounted_state=state["mounted_per_perfil"][perfil], 
            on_back=go_minio,
        ))

    def do_close():
        if IS_LINUX_CLUSTER and state["mounts_activos"]:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario") or getpass.getuser()
            safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()
        page.window.close()

    show_screen(_build_update_content(page, on_continue=go_login))

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    ft.run(main)