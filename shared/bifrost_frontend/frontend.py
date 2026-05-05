import sys
import os
from typing import Callable
import flet as ft
import subprocess
import shutil
from bifrost_backend import backend
from config import APP_INFO
from pathlib import Path
import tempfile

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

# ============================================================================
# BUTTONS
# ============================================================================


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
            padding=ft.padding.symmetric(horizontal=20, vertical=12),
        ),
    )
    
def card(content: ft.Control, padding=20) -> ft.Container:
    return ft.Container(
        content=content,
        bgcolor=C_SURFACE,
        border=ft.border.all(1, C_BORDER),
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
    
# ============================================================================
# HEADER COMÚN
# ============================================================================

def build_header(subtitle: str = "", IS_WEB: bool = False) -> ft.Container:
    version_str = f"v{backend.__version__}" if hasattr(backend, "__version__") else ""
    return ft.Container(
        content=ft.Row(
            [
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(
                                    APP_INFO["name"],
                                    size=22,
                                    weight=ft.FontWeight.W_700,
                                    color=C_PRIMARY,
                                    font_family=FONT_MONO,
                                ),
                                ft.Container(width=8),
                                status_badge("WEB" if IS_WEB else "DESKTOP", C_WARNING),
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Text(subtitle or APP_INFO["description"], size=12, color=C_TEXT_DIM),
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
# SELF-UPDATE
# ============================================================================


def build_update_content(page: ft.Page, on_continue: Callable) -> ft.Control:
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
                    update_btn.on_click = do_update
                    skip_btn.visible   = True
                backend.ui_call(page, _show_update)
            else:
                def _show_ok():
                    status_text.value = "✓ You are using the latest version."
                    status_text.color = C_ACCENT
                    progress.visible  = False
                backend.ui_call(page, _show_ok)
                import time; time.sleep(1)
                backend.ui_call(page, on_continue)
        except Exception as e:
            def _show_err():
                status_text.value = f"Could not check updates: {e}"
                status_text.color = C_TEXT_DIM
                progress.visible  = False
            backend.ui_call(page, _show_err)
            import time; time.sleep(0.5)
            backend.ui_call(page, on_continue)

    def do_update(e):
        update_btn.disabled = True
        progress.visible    = True
        status_text.value   = "Downloading update..."
        status_text.color   = C_TEXT_DIM
        page.update()

        def _download():
            try:
                flavour = APP_INFO["flavour"]
                new_version = backend.download_new_binary("bifrost-{0:s}".format(flavour))
                if sys.platform == "win32":
                    exe_path = str(Path(tempfile.gettempdir()) / "bifrost-{0:s}.exe".format(APP_INFO["flavour"]))  
                    shutil.move(new_version, exe_path)
                    bat_path = new_version + ".bat"
                    with open(bat_path, "w") as bat:
                        bat.write(
                            f'@echo off\n'
                            f'timeout /t 2 /nobreak >nul\n'
                            f'"{exe_path}" /SILENT /SUPPRESSMSGBOXES /NOCANCEL\n'
                            f'start "" "%ProgramFiles(x86)%\\Bifrost-{flavour}\\bifrost-{flavour}.exe"\n'
                        )
                    subprocess.Popen(
                        ["cmd", "/c", bat_path],
                        start_new_session=True,
                        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
                        close_fds=True,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    backend.ui_call(page, lambda: os._exit(0))
                elif sys.platform == "darwin":
                    result = subprocess.run(
                        ["hdiutil", "attach", new_version, "-nobrowse", "-noautoopen"],
                        capture_output=True, check=True,
                    )
                    mount_point = None
                    for line in result.stdout.decode().splitlines():
                        parts = line.split("\t")
                        if len(parts) >= 3 and parts[2].strip().startswith("/Volumes/"):
                            mount_point = parts[2].strip()
                    if not mount_point:
                        raise RuntimeError("Could not determine DMG mount point")
                    app_name = "bifrost-{0:s}.app".format(flavour)
                    app_src  = os.path.join(mount_point, app_name)
                    app_dst  = os.path.join("/Applications", app_name)
                    import shlex
                    shell_cmd = (
                        f'sleep 2 && '
                        f'rm -rf {shlex.quote(app_dst)} && '
                        f'cp -R {shlex.quote(app_src)} {shlex.quote(app_dst)} && '
                        f'hdiutil detach {shlex.quote(mount_point)} && '
                        f'open {shlex.quote(app_dst)}'
                    )
                    subprocess.Popen(
                        ["bash", "-c", shell_cmd],
                        start_new_session=True,
                    )
                    backend.ui_call(page, lambda: os._exit(0))
                else:
                    ruta_actual = os.path.abspath(sys.argv[0])
                    os.replace(new_version, ruta_actual)
                    os.chmod(ruta_actual, os.stat(ruta_actual).st_mode | stat.S_IEXEC)
                    backend.ui_call(page, lambda: show_dialog(
                        page, "Updated",
                        "Restart the application to use the new version.",
                        C_ACCENT,
                    ))
            except Exception as ex:
                backend.ui_call(page, lambda: show_dialog(page, "Update failed", str(ex), C_ERROR))

        backend.safe_thread(page, _download).start()

    skip_btn.on_click   = lambda e: backend.ui_call(page, on_continue)

    content = ft.Column(
        [
            build_header("Checking for updates"),
            ft.Container(expand=True),
            ft.Column(
                [
                    ft.Icon(ft.Icons.SYNC, color=C_PRIMARY, size=48),
                    ft.Text(APP_INFO["name"], size=32, weight=ft.FontWeight.W_700,
                            color=C_TEXT, font_family=FONT_MONO),
                    ft.Text(APP_INFO["description"], size=14, color=C_TEXT_DIM),
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
        backend.safe_thread(page, check).start()
    else:
        def _skip():
            import time
            time.sleep(0.1)
            backend.ui_call(page, on_continue)
        backend.safe_thread(page, _skip).start()
    return content