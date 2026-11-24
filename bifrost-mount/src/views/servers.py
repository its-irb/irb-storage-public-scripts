"""Pantalla principal de bifrost-mount: una tarjeta por servidor MinIO para montarlo entero, abrirlo o desmontarlo."""

from __future__ import annotations

import logging
import threading
from typing import Callable

import flet as ft

from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP
from bifrost_frontend.frontend import *

from views.renew_dialog import show_renew_dialog
from views.server_card import ServerCard
from views.winfsp_dialog import prompt_install_winfsp

log = logging.getLogger("bifrost.mount")


def build_servers_content(
    page: ft.Page,
    *,
    usuario: str,
    on_credentials: Callable[[str, int | None], None],
    mount_on_load: str | None = None,
) -> ft.Control:
    """Una tarjeta por servidor de `MINIO_SERVERS`, con su estado leído del backend (no se guarda aparte).

    `on_credentials(servidor, días)` lleva a la pantalla de credenciales: con `días=None`, la renovación automática
    antes de montar (al volver, `main` pasa `mount_on_load=servidor` y se monta); con días, la renovación a mano.
    """
    servers = {srv: cfg["IRB"] for srv, cfg in backend.MINIO_SERVERS.items()}
    mount_points: dict[str, str | None] = dict.fromkeys(servers)   # dónde está montado cada uno (None: no lo está)
    busy: set[str] = set(servers)                                    # montando, desmontando o comprobando
    cards: dict[str, ServerCard] = {}

    def _profile(srv: str) -> str:
        return servers[srv]["profile"]

    # ── Pintar (solo desde el hilo de la UI) ──────────────────────────────
    def _show(srv: str, status: str = "", color: str = C_TEXT_DIM) -> None:
        cards[srv].show(mount_point=mount_points[srv], session=backend.get_session_info(_profile(srv)),
                        status=status, status_color=color, busy=srv in busy)
        page.update()

    def _start(srv: str, status: str) -> None:
        busy.add(srv)
        _show(srv, status)

    def _finish(srv: str, status: str = "", color: str = C_TEXT_DIM) -> None:
        busy.discard(srv)
        _show(srv, status, color)

    # ── Acciones ──────────────────────────────────────────────────────────
    def mount(srv: str) -> None:
        """Monta el servidor, o abre su carpeta si ya está montado. Antes, renueva las credenciales si hace falta."""
        if srv in busy:
            return
        mount_point = mount_points[srv]
        if mount_point and backend.is_mounted(mount_point):
            log.info("mount: %s is already mounted, opening %s", srv, mount_point)
            backend.open_in_file_browser(_openable(mount_point))
            return
        if backend.hay_que_renovar_credenciales(_profile(srv), usuario):
            on_credentials(srv, None)
            return
        _start(srv, "Mounting...")

        def _do():
            log.info("mount: server=%s profile=%s", srv, _profile(srv))
            mounted_at, error = None, None
            try:
                mounted_at = backend.mount_profile(_profile(srv))
            except backend.WinFspMissingError:
                log.info("mount: WinFsp missing")

                def _ask():
                    _finish(srv)
                    prompt_install_winfsp(page, on_success=lambda: mount(srv))
                backend.ui_call(page, _ask)
                return
            except backend.MountError as ex:
                error = ex
            except Exception as ex:
                log.exception("mount %s failed", srv)
                error = backend.MountError(backend.issue_for_exception(ex))
            else:
                backend.open_in_file_browser(_openable(mounted_at))   # solo ahora: el montaje ya se ha comprobado
            backend.ui_call(page, lambda: _after_mount(srv, mounted_at, error))

        backend.safe_thread(page, _do).start()

    def _after_mount(srv: str, mounted_at: str | None, error) -> None:
        mount_points[srv] = mounted_at
        if error is not None:
            _finish(srv)
            show_issue(page, error.issue, is_web=False, title="Could not mount the server",
                       context=_error_context(srv, error), screen="mount")
            return
        _finish(srv, "✅ Mounted!", C_ACCENT)

        def _clear_status():
            if srv not in busy:
                _show(srv)
        threading.Timer(3, lambda: backend.ui_call(page, _clear_status)).start()

    def unmount(srv: str) -> None:
        if srv in busy:
            return
        _start(srv, "Unmounting...")

        def _do():
            log.info("unmount: server=%s", srv)
            try:
                unmounted = backend.unmount_profile(_profile(srv))
            except Exception:
                log.exception("unmount %s failed", srv)
                unmounted = False

            def _after():
                if unmounted:
                    mount_points[srv] = None
                _finish(srv)
                if not unmounted:
                    show_issue(page, backend.UNMOUNT_FAILED, is_web=False, context=srv, screen="mount")
            backend.ui_call(page, _after)

        backend.safe_thread(page, _do).start()

    def renew(srv: str) -> None:
        show_renew_dialog(page, perfil=_profile(srv), usuario=usuario, on_renew=lambda dias: on_credentials(srv, dias))

    # ── Estado inicial: dónde está montado cada servidor (también por una sesión anterior u otra ventana) ──
    def _active(srv: str) -> str | None:
        try:
            return backend.active_mount_point(_profile(srv), scan=True)
        except Exception:                  # que un fallo no deje las tarjetas en "Checking..." para siempre
            log.exception("mount: could not check whether %s is mounted", srv)
            return None

    def _load():
        found = {srv: _active(srv) for srv in servers}

        def _show_all():
            for srv, mount_point in found.items():
                mount_points[srv] = mount_point
                if mount_point:
                    log.info("mount: %s is mounted at %s", srv, mount_point)
                _finish(srv)
            if mount_on_load in servers:
                mount(mount_on_load)
        backend.ui_call(page, _show_all)

    for srv, irb in servers.items():
        cards[srv] = ServerCard(srv, irb["endpoint"], on_mount=lambda s=srv: mount(s),
                                on_unmount=lambda s=srv: unmount(s), on_renew=lambda s=srv: renew(s))
        cards[srv].show(mount_point=None, session=backend.get_session_info(_profile(srv)), status="Checking...",
                        busy=True)
    backend.safe_thread(page, _load).start()

    return ft.Column(
        [
            build_header(no_ldap=NO_LDAP, subtitle="Mount — MinIO servers", page=page),
            ft.Container(
                content=ft.Column(
                    [
                        section_title("MINIO SERVERS"),
                        ft.Container(height=6),
                        ft.Text("Each server is mounted whole, with its buckets as folders. "
                                "Double-click a server to mount it, or to open it if it is already mounted.",
                                size=12, color=C_TEXT_DIM),
                        ft.Container(height=12),
                        ft.Column([card.control for card in cards.values()], spacing=10),
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


def _openable(mount_point: str) -> str:
    """Lo que se abre en el explorador: en Windows, la raíz de la unidad ("X:" sería la carpeta actual de X:)."""
    return mount_point + "\\" if len(mount_point) == 2 and mount_point[1] == ":" else mount_point


def _error_context(srv: str, error) -> str:
    """El servidor y, si quedan montajes por bucket de la versión anterior en uso, cuáles."""
    if isinstance(error, backend.BucketMountsBusyError):
        return f"{srv}: {', '.join(error.buckets)} (folders mounted by the previous version of Bifrost mount)"
    return srv
