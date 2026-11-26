"""
BIFROST MOUNT — IRB MinIO Mount Tool — FRONTEND (Flet)
======================================================

Migración de tkinter a Flet.
Soporta modo desktop (Mac, Windows, Linux).

Uso:
    python main.py             # desktop

Flujo de vistas:
    view_update → view_login ⇄ view_servers ⇄ view_credentials

    view_servers vuelve al login con "← Back to login"; view_credentials vuelve a view_servers con
    "← Back to servers" (en cualquier momento) y, si falla, deja reintentar con "Try again".

    view_servers tiene una tarjeta por servidor MinIO; cada servidor se monta entero (sus buckets son carpetas).

Notas sobre credenciales STS (se comprueban al pedir montar un servidor):
  - Si quedan MÁS de 3 días → monta directamente
  - Si quedan MENOS de 3 días (o no hay credenciales) → renueva automáticamente
    por 7 días, mostrando el progreso en un log en pantalla, y vuelve a view_servers para montar
  - "Renew credentials" en una tarjeta renueva a mano (1-30 días) y vuelve a view_servers

"""

from __future__ import annotations

import sys
import io
import logging

import flet as ft

from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP
from bifrost_frontend.frontend import *
from version import __version__

from views.servers import build_servers_content

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

# Cierre: desmontar los servidores al salir, también si DCV/Open OnDemand mata la sesión con una señal
# (si no, el montaje FUSE queda colgado para la siguiente sesión). Una sola vez por proceso.
backend.register_shutdown(backend.desmontar_todos_los_mounts_s3)


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
    backend.install_signal_handlers()   # ft.run() ha puesto los suyos al arrancar (ver common/shutdown.py)
    apply_theme(page)

    # Lo que está montado no se guarda aquí: la pantalla de servidores se lo pregunta al backend.
    state = {"credenciales_ldap": None}

    install_window_close(page)

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
        go_servers()

    def go_servers(mount: str | None = None):
        """La pantalla de servidores; con `mount`, monta ese servidor al cargar (al volver de renovar)."""
        show_screen(build_servers_content(
            page,
            usuario=state["credenciales_ldap"]["usuario"],
            on_credentials=go_credentials,
            on_back=go_login,
            mount_on_load=mount,
        ))

    def go_credentials(servidor: str, dias: int | None):
        """Renueva las credenciales de `servidor`: automáticas antes de montar (`dias` None: al terminar vuelve y
        monta) o a mano desde "Renew credentials" (al terminar vuelve sin montar)."""
        irb = backend.MINIO_SERVERS[servidor]["IRB"]
        automatic = dias is None
        show_screen(build_credentials_content(
            page,
            perfil_rclone=irb["profile"],
            endpoint=irb["endpoint"],
            credenciales_ldap=state["credenciales_ldap"],
            on_continue=lambda: go_servers(mount=servidor if automatic else None),
            extra_config=irb.get("extra_rclone_config"),
            duracion_dias=dias,
            on_back=go_login if (NO_LDAP and automatic) else None,
            no_ldap=NO_LDAP,
            done_message="Loading servers...",
            on_cancel=go_servers,
            cancel_label="Back to servers",
        ))


    show_screen(build_update_content(page, on_continue=go_login))

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    ft.run(main)