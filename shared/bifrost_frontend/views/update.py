"""Vista de comprobación e instalación de actualizaciones (compartida por mount y transfer)."""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

import flet as ft
from bifrost_backend import backend
from config import APP_INFO

from ..components import btn_primary, btn_secondary, build_header, show_dialog
from ..theme import (
    C_ACCENT, C_ERROR, C_PRIMARY, C_SURFACE2, C_TEXT, C_TEXT_DIM, C_WARNING,
    FONT_MONO, MONO_FALLBACK,
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
                    page.update()
                backend.ui_call(page, _show_update)
            else:
                def _show_ok():
                    status_text.value = "✓ You are using the latest version."
                    status_text.color = C_ACCENT
                    progress.visible  = False
                    page.update()
                backend.ui_call(page, _show_ok)
                import time; time.sleep(1)
                backend.ui_call(page, on_continue)
        except Exception as e:
            def _show_err():
                status_text.value = f"Could not check updates: {e}"
                status_text.color = C_TEXT_DIM
                progress.visible  = False
                page.update()
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
                    proc_name = f'bifrost-{flavour}'
                    shell_cmd = (
                        f'pkill -x {shlex.quote(proc_name)} ; '
                        f'while pgrep -xq {shlex.quote(proc_name)}; do sleep 2; done && '
                        f'chmod -R u+w {shlex.quote(app_dst)} ; '
                        f'rm -rf {shlex.quote(app_dst)} && '
                        f'ditto {shlex.quote(app_src)} {shlex.quote(app_dst)} && '
                        f'hdiutil detach {shlex.quote(mount_point)} && '
                        f'find {shlex.quote(app_dst)} -not -type l -exec xattr -d com.apple.quarantine {{}} + 2>/dev/null; true; '
                        f'open {shlex.quote(app_dst)}'
                    )
                    with tempfile.NamedTemporaryFile(
                        mode='w', suffix='.sh', delete=False
                    ) as sf:
                        sf.write('#!/bin/bash\n' + shell_cmd + '\n')
                        script_path = sf.name
                    os.chmod(script_path, 0o755)
                    escaped_path = script_path.replace('\\', '\\\\').replace('"', '\\"')
                    osascript_cmd = (
                        f'do shell script "{escaped_path}" '
                        f'with administrator privileges'
                    )
                    subprocess.Popen(
                        ["osascript", "-e", osascript_cmd],
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
                err_str = str(ex)
                backend.ui_call(page, lambda: show_dialog(page, "Update failed", err_str, C_ERROR))

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
                            color=C_TEXT, font_family=FONT_MONO,
                            font_family_fallback=MONO_FALLBACK),
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
