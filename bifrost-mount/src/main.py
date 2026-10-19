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
import atexit
import logging
import signal

import flet as ft

from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *
from version import __version__

from views.mount import _build_mount_bucket

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

# Log técnico: consola + fichero por sesión en la carpeta estándar del SO (common/logs.py)
backend.setup_logging("mount", is_web=False, version=__version__)
log = logging.getLogger("bifrost.mount")


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
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
        log.info("APP shutdown — cleaning up")
        backend.desmontar_todos_los_mounts_s3()

    atexit.register(_cleanup_on_exit)

    def _handle_termination_signal(signum, frame):
        # DCV/Open OnDemand puede matar la sesión con SIGTERM/SIGINT al cerrarse
        # abruptamente. Sin este handler, atexit no llega a ejecutarse y el
        # mount FUSE queda colgado para la siguiente sesión.
        nombre_senal = signal.Signals(signum).name
        log.info("APP shutdown requested (reason=%s)", nombre_senal)
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
        show_screen(build_login_content(page, on_success=on_login_success,
                                        no_ldap=NO_LDAP))

    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds
        go_minio()

    def go_minio():
        show_screen(build_minio_content(page, on_continue=on_minio_selected, no_ldap=NO_LDAP))

    def on_minio_selected(eleccion: dict):
        state["servidor_minio"] = eleccion["servidor"]
        state["perfil_rclone"]  = eleccion["perfil"]
        state["endpoint"]       = eleccion["endpoint"]
        log.info(f"PROFILE selected — {eleccion['perfil']} ({eleccion['endpoint']})")
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
            show_screen(build_credentials_content(
                page,
                perfil_rclone=perfil,
                endpoint=state["endpoint"],
                credenciales_ldap=state["credenciales_ldap"],
                on_continue=go_mount,
                extra_config=extra_config,
                on_back=go_login if NO_LDAP else None,
                no_ldap=NO_LDAP,
                done_message="Loading mount interface...",
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