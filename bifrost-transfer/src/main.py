from __future__ import annotations

"""
IRB MinIO Rclone Data Transfer Tool — FRONTEND (Flet)
=====================================================

Migración de tkinter a Flet.
Soporta modo desktop y modo web (--web).

Uso:
    python bifrost.py          # desktop
    python bifrost.py --web    # Open OnDemand / cluster (Rocky Linux)

Flujo de vistas (Mac / Windows / Web):
    view_update → view_login → view_minio → view_credentials (auto) → view_copy

Flujo de vistas (Linux cluster):
    view_update → view_login → view_shares → view_minio
    → view_credentials → view_copy

Notas sobre credenciales STS:
  - Si quedan MÁS de 3 días → se salta la renovación y va directo a view_copy
  - Si quedan MENOS de 3 días (o no hay credenciales) → renueva automáticamente
    por 7 días, mostrando el progreso en un log en pantalla
  - No hay botones manuales de renovación en el flujo Mac/Windows/Web

Fixes aplicados respecto al piloto inicial:
  - Thread-safety: toda modificación de UI desde hilos usa backend.ui_call(page, fn)
  - Import circular eliminado (check_rclone_installation_flet se llama directamente)
  - Cierre por X registra on_window_event para desmontar shares
  - Spinner de carga entre login y vista de shares
  - FilePicker instanciado una sola vez (no se acumula en overlay)
  - Log usa ft.ListView con auto_scroll=True en lugar de TextField
  - ft.Ref[str] reemplazado por dict simple
  - Vista de shares vacíos muestra mensaje explicativo
  - atexit eliminado; el cierre limpio se gestiona via on_window_event y do_close()
  - Sin hint de asteriscos en campos password
  - Espaciado (margin bottom) entre header y contenido de cada vista
  - backend.safe_thread: todos los hilos capturan excepciones y las muestran en diálogo
  - Navegador de carpetas rclone para el destino (build_rclone_browser)
  - FIX: carga inicial del browser diferida con Timer para evitar
    "Text Control must be added to the page first"
"""


import os
import sys
import io
import getpass
import pathlib
from datetime import datetime

import flet as ft

# # Dev: añadir shared/ al path si no está ya en él
# _shared = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
# if os.path.isdir(_shared):
#     sys.path.insert(0, os.path.abspath(_shared))

# import backend

from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *

import web_session
from web_session import _LAST_WEB_USER, _ws_clear, _ws_load, _ws_save
from views import copy as _views_copy, shares as _views_shares, tag_manager as _views_tag_manager
from views.copy import _build_copy_content
from views.shares import _build_shares_content
from views.tag_manager import _build_tag_manager_content

# ============================================================================
# MODO DE EJECUCIÓN
# ============================================================================



# Modo web: producción (BIFROST_CLUSTER=1), Flet web runtime, o dev local (--web)
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or (os.environ.get("BIFROST_CLUSTER") == "1")


def _propagar_is_web() -> None:
    """Copia IS_WEB a los módulos movidos de main.py, que lo leen como variable global propia.

    IS_WEB solo puede calcularse aquí (depende de __name__) y main() puede cambiarlo
    (page.web), así que hay que llamar a esta función cada vez que cambie.
    """
    for _m in (web_session, _views_shares, _views_copy, _views_tag_manager):
        _m.IS_WEB = IS_WEB


_propagar_is_web()

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
# TEE DE CONSOLA A FICHERO — persiste todo lo que se hace print() (navegación,
# filtros, copy, tags, selección de cluster, etc.) en ~/bifrost-logs/, igual
# que ya se hace con los logs de copy/tags. Así el histórico de debug no
# depende de que haya una consola visible (apps empaquetadas con flet build
# no muestran una).
# ============================================================================
class _TeeStream:
    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for s in self._streams:
            try:
                s.write(data)
            except Exception:
                pass

    def flush(self):
        for s in self._streams:
            try:
                s.flush()
            except Exception:
                pass


try:
    _console_log_dir = pathlib.Path.home() / "bifrost-logs"
    _console_log_dir.mkdir(parents=True, exist_ok=True)
    _console_log_path = _console_log_dir / f"bifrost-console-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
    _console_log_file = open(_console_log_path, "a", encoding="utf-8", errors="replace", buffering=1)
    sys.stdout = _TeeStream(sys.stdout, _console_log_file)
    sys.stderr = _TeeStream(sys.stderr, _console_log_file)
    print(f"[startup] console log → {_console_log_path}")

    # Rotación: conservar solo los 50 ficheros de consola más recientes.
    _console_logs = sorted(
        _console_log_dir.glob("bifrost-console-*.log"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for _old_console_log in _console_logs[50:]:
        try:
            _old_console_log.unlink()
        except Exception:
            pass
except Exception as _console_log_ex:
    print(f"[startup] Could not set up console log file: {_console_log_ex}")


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(page: ft.Page):
    global IS_WEB
    IS_WEB = IS_WEB or page.web
    _propagar_is_web()
    apply_theme(page)

    state = {
        "credenciales_ldap":     None,
        "grupos_ldap":           [],
        "usar_privilegios":      False,
        "credenciales_admin":    None,
        "credenciales_smb":      None,
        "shares_accesibles":     [],
        "perfiles_configurados": [],
        "mounts_activos":        [],
        "servidor_minio":        None,
        "perfil_rclone":         None,
        "endpoint":              None,
        "_cifs_loading":         False,
    }

    import atexit
    
    def _cleanup_on_exit():
        print("[atexit] Cleaning up...")
        mounts = state.get("mounts_activos", [])
        if mounts and IS_WEB:
            usuario = (state.get("credenciales_smb") or {}).get("usuario") or getpass.getuser()
            try:
                backend.desmontar_todos_los_shares(usuario)
            except Exception as e:
                print(f"[atexit] Error unmounting shares: {e}")

    atexit.register(_cleanup_on_exit)


    # def on_window_close(e):
    #     print(f"[debug] on_window_close called, e={e}, e.data={e.data if hasattr(e, 'data') else 'no data'}")
    #     _cleanup_on_exit()
    #    page.window.close()

    async def on_window_event(e: ft.WindowEvent):
        if e.type == ft.WindowEventType.CLOSE:
            print("[close] Starting cleanup...")
            _cleanup_on_exit()
            print("[close] Cleanup done, destroying window...")
            await page.window.destroy()
            print("[close] Window destroyed")
            os._exit(0)


    #page.window.on_close = on_window_close
    page.window.on_event = on_window_event
    page.window.prevent_close = True
    

    body = ft.Container(expand=True, bgcolor=C_BG)
    page.scroll = ft.ScrollMode.AUTO
    page.add(body)
    page.update()

    # --- WebSocket keep-alive -----------------------------------------------
    # OOD's nginx proxy closes idle WebSocket connections (default ~60 s).
    # Sending a Flet protocol update every 20 s resets the idle timer and
    # prevents the Flutter client from having to reconnect (which causes the
    # "working…" flash the user sees).
    # A stop-event is used so the previous task exits immediately when
    # main() is called again on reconnection, preventing task accumulation.
    if IS_WEB:
        _hb_stop = [False]   # mutable flag accessible from the coroutine closure

        async def _ws_heartbeat():
            import asyncio as _aio
            while not _hb_stop[0]:
                await _aio.sleep(20)
                if _hb_stop[0]:
                    return
                try:
                    page.update()
                except Exception:
                    return

        # Signal any previous heartbeat for this page object to stop,
        # then launch a fresh one.
        if hasattr(page, "_bifrost_hb_stop"):
            page._bifrost_hb_stop[0] = True
        page._bifrost_hb_stop = _hb_stop
        page.run_task(_ws_heartbeat)
    # ------------------------------------------------------------------------

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
        # If a previous session exists for the last known user, pre-fill the
        # username and use a special on_success that skips update/shares/minio.
        if IS_WEB:
            last_user = _LAST_WEB_USER[0]
            session   = _ws_load(last_user) if last_user else None
            if session:
                print(f"[session] Previous session found for {last_user!r} — showing restore-login")
                show_screen(build_login_content(
                    page,
                    on_success=lambda creds: on_login_success_with_restore(creds, session),
                    prefill_user=last_user,
                    no_ldap=NO_LDAP,
                    is_web=IS_WEB,
                ))
                return
        show_screen(build_login_content(page, on_success=on_login_success,
                                        no_ldap=NO_LDAP, is_web=IS_WEB))

    def on_login_success_with_restore(creds: dict, session: dict) -> None:
        """
        Called after password re-auth when restoring a previous web session.
        Restores navigation state and jumps straight to copy view,
        skipping update / shares / minio selection entirely.
        In OOD web mode there are no CIFS mounts to restore.
        """
        usuario = creds["usuario"]
        # If the user typed a different username, discard the old session
        # and run the normal fresh flow instead.
        if usuario != _LAST_WEB_USER[0]:
            print(f"[session] Username changed ({_LAST_WEB_USER[0]!r} → {usuario!r}), discarding old session")
            _ws_clear(_LAST_WEB_USER[0] or "")
            on_login_success(creds)
            return

        print(f"[session] Restoring session for {usuario!r} → cluster={session['servidor_minio']!r} ({session['endpoint']})")
        state["credenciales_ldap"] = creds
        state["servidor_minio"]    = session["servidor_minio"]
        state["perfil_rclone"]     = session["perfil_rclone"]
        state["endpoint"]          = session["endpoint"]

        def _sweep_sftp_huerfanos():
            try:
                backend.limpiar_perfiles_rclone_con_prefijo("sftp-src-")
            except Exception as ex:
                print(f"[sftp] cleanup sweep failed (non-fatal): {ex}")

        backend.safe_thread(page, _sweep_sftp_huerfanos).start()

        # Jump straight to credentials-check → copy view
        _go_credentials_or_copy()

    def on_login_success(creds: dict):
        state["credenciales_ldap"] = creds

        def _sweep_sftp_huerfanos():
            try:
                backend.limpiar_perfiles_rclone_con_prefijo("sftp-src-")
            except Exception as ex:
                print(f"[sftp] cleanup sweep failed (non-fatal): {ex}")

        backend.safe_thread(page, _sweep_sftp_huerfanos).start()
        go_minio()

    def go_minio():
        show_screen(build_minio_content(page, on_continue=on_minio_selected,
                                        no_ldap=NO_LDAP, is_web=IS_WEB))

    def on_minio_selected(eleccion: dict):
        print(f"[minio] cluster selected → {eleccion['servidor']} ({eleccion['endpoint']})")
        state["servidor_minio"] = eleccion["servidor"]
        state["perfil_rclone"]  = eleccion["perfil"]
        state["endpoint"]       = eleccion["endpoint"]

        if IS_WEB and state.get("credenciales_ldap"):
            _ws_save(state["credenciales_ldap"]["usuario"], state)

        _go_credentials_or_copy()

    def _go_credentials_or_copy():
        perfil  = state["perfil_rclone"]
        usuario_actual = state["credenciales_ldap"]["usuario"]

        info = backend.get_session_info(perfil)
        needs_renewal = info is None or info.needs_renewal(usuario_actual, STS_RENEWAL_THRESHOLD_DAYS)
        if info is not None:
            print(
                f"[credentials] {'Renewal needed' if needs_renewal else 'Token valid → skipping renewal'} — "
                f"token user: {info.usuario!r}, login user: {usuario_actual!r}, "
                f"expiry: {info.remaining_text()}"
            )

        if needs_renewal:
            servidor     = state["servidor_minio"]
            extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")
            show_screen(build_credentials_content(
                page,
                perfil_rclone=perfil,
                endpoint=state["endpoint"],
                credenciales_ldap=state["credenciales_ldap"],
                on_continue=go_copy,
                extra_config=extra_config,
                on_back=go_login if NO_LDAP else None,
                no_ldap=NO_LDAP,
                is_web=IS_WEB,
                done_message="Continuing to copy interface...",
            ))
        else:
            go_copy()

    def go_tags():
        print("[tags] Entrando en Tag Manager", flush=True)
        show_screen(_build_tag_manager_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            endpoint=state["endpoint"],
            on_back=go_copy,
        ))

    def _load_and_show_shares(skip_groups: bool = False) -> None:
        """Carga grupos LDAP + credentials SMB + shares en background y muestra la vista."""
        if state.get("_cifs_loading"):
            return
        state["_cifs_loading"] = True
        creds_ldap = state["credenciales_ldap"]

        show_loading("Loading accessible shares...")

        def _bg():
            try:
                if not skip_groups:
                    grupos = backend.get_ldap_groups(creds_ldap["usuario"])
                    state["grupos_ldap"] = grupos

                try:
                    state["credenciales_smb"] = backend.construir_credenciales_smb(
                        creds_ldap,
                        state["usar_privilegios"],
                        state["credenciales_admin"],
                    )
                except ValueError as ex:
                    backend.ui_call(page, lambda: show_dialog(page, "Error", str(ex), C_ERROR))
                    return

                shares = backend.obtener_shares_accesibles(
                    state["grupos_ldap"],
                    creds_ldap["usuario"],
                    creds_ldap["password"],
                    state["credenciales_smb"]["usuario"],
                    backend.EXCEPCION_FILERS,
                    state["usar_privilegios"],
                )

                # Si estamos en modo admin y no hay shares, las credenciales
                # admin son probablemente incorrectas — revertir y mostrar error.
                if skip_groups and not shares:
                    state["usar_privilegios"]   = False
                    state["credenciales_admin"] = None
                    state["credenciales_smb"]   = None
                    backend.ui_call(page, lambda: show_dialog(
                        page,
                        "Admin credentials error",
                        "No shares were found. Check your admin password and try again.",
                        C_ERROR,
                    ))
                    return

                backend.actualizar_password_perfiles_rclone(
                    state["credenciales_smb"]["usuario"],
                    state["credenciales_smb"]["password"],
                )
                perfiles = backend.configurar_perfiles_smb_si_faltan(
                    shares,
                    state["credenciales_smb"],
                    backend.obtener_perfiles_rclone_config(),
                )
                state["shares_accesibles"]     = shares
                state["perfiles_configurados"] = perfiles

                def _show():
                    show_screen(_build_shares_content(
                        page,
                        shares=shares,
                        usuario_actual=state["credenciales_smb"]["usuario"],
                        mounts_activos=state["mounts_activos"],
                        grupos_ldap=state["grupos_ldap"],
                        credenciales_ldap=creds_ldap,
                        on_back=go_copy,
                        on_admin_activated=on_admin_activated,
                    ))
                backend.ui_call(page, _show)
            finally:
                state["_cifs_loading"] = False

        backend.safe_thread(page, _bg).start()


    def go_cifs() -> None:
        """Navega a la vista de CIFS shares. Carga lazy en el primer acceso."""
        if state["credenciales_smb"] is not None and not state.get("_cifs_loading"):
            creds_ldap = state["credenciales_ldap"]
            show_screen(_build_shares_content(
                page,
                shares=state["shares_accesibles"],
                usuario_actual=state["credenciales_smb"]["usuario"],
                mounts_activos=state["mounts_activos"],
                grupos_ldap=state["grupos_ldap"],
                credenciales_ldap=creds_ldap,
                on_back=go_copy,
                on_admin_activated=on_admin_activated,
            ))
            return
        _load_and_show_shares(skip_groups=False)


    def on_admin_activated(credenciales_admin: dict) -> None:
        """Callback llamado desde la vista CIFS al confirmar credenciales de admin ITS."""
        state["usar_privilegios"]   = True
        state["credenciales_admin"] = credenciales_admin
        state["credenciales_smb"]   = None   # forzar recarga, evitar fast-path con datos viejos
        _load_and_show_shares(skip_groups=True)


    def go_copy():
        servidor     = state["servidor_minio"]
        extra_config = backend.MINIO_SERVERS.get(servidor, {}).get("IRB", {}).get("extra_rclone_config")
        usuario      = (state.get("credenciales_ldap") or {}).get("usuario")
        if IS_WEB and usuario:
            _ws_save(usuario, state)
        session = _ws_load(usuario) if (IS_WEB and usuario) else None
        show_screen(_build_copy_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            mounts_activos=state["mounts_activos"],
            on_close=do_close,
            endpoint=state["endpoint"],
            credenciales_ldap=state["credenciales_ldap"],
            extra_config=extra_config,
            on_renew_complete=go_copy,
            show_screen=show_screen,
            web_session=session,
            on_back=go_minio,
            on_tags=go_tags,
            on_cifs=go_cifs,          # ← nuevo
            on_login=go_login,
        ))

    def do_close():
        if IS_WEB:
            usuario = (state.get("credenciales_ldap") or {}).get("usuario")
            if usuario:
                _ws_clear(usuario)
        if IS_WEB and state["mounts_activos"]:
            usuario = (state["credenciales_smb"] or {}).get("usuario") or getpass.getuser()
            backend.safe_thread(page, lambda: backend.desmontar_todos_los_shares(usuario)).start()
        if IS_WEB:
            show_screen(
                ft.Column(
                    [
                        ft.Container(expand=True),
                        ft.Column(
                            [
                                ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C_ACCENT, size=56),
                                ft.Text("Session closed", size=24, color=C_TEXT,
                                        weight=ft.FontWeight.W_600),
                                ft.Text("You can close this browser tab.",
                                        size=14, color=C_TEXT_DIM),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=12,
                        ),
                        ft.Container(expand=True),
                    ],
                    expand=True,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                )
            )
        else:
            page.window.close()

    if IS_WEB:
        go_login()
    else:
        show_screen(build_update_content(page, on_continue=go_login))

# ============================================================================
# WEB VERSION IN OOD
# ============================================================================
if os.environ.get("BIFROST_CLUSTER") == "1":
    from flet.fastapi import FletApp, app_manager
    from fastapi import FastAPI, WebSocket
    import asyncio

    WEBSOCKET_ENDPOINT = os.environ.get("FLET_WEBSOCKET_HANDLER_ENDPOINT")
    WEBPATH = os.environ.get("WEBPATH")
    SECRET_TOKEN = os.environ.get("password") or ""
    if not SECRET_TOKEN:
        print("[WARNING] 'password' environment variable is not set — WebSocket auth disabled", flush=True)

    app = FastAPI()
    flet_asgi_app  = ft.app(main,export_asgi_app=True)
    app.mount(WEBPATH, flet_asgi_app)

    @app.websocket(WEBSOCKET_ENDPOINT)
    async def flet_app(websocket: WebSocket):
        if "--web" not in sys.argv:
            token = websocket.cookies.get("bifrost_auth_token")

            if not SECRET_TOKEN or token != SECRET_TOKEN:
                await websocket.close(code=1008)
                return

        await FletApp(
            loop=asyncio.get_running_loop(),
            executor=app_manager.executor,
            main=main,
            before_main=None,
        ).handle(websocket)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    ft.run(main)
