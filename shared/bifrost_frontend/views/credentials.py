"""Vista de renovación de credenciales STS (compartida por mount y transfer)."""

from __future__ import annotations

import logging
import time
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import STS_AUTO_RENEWAL_DAYS

from ..components import (
    btn_primary, btn_secondary, build_header, card, error_code_row, issue_reference, nav_bar, section_title, tip_box,
)
from ..theme import (
    C_ACCENT, C_BG, C_BORDER, C_ERROR, C_PRIMARY, C_SURFACE2, C_TEXT, C_TEXT_DIM,
    C_WARNING, FONT_MONO, MONO_FALLBACK, tint,
)

log = logging.getLogger("bifrost.auth")

# Estado de la tarjeta de arriba → icono y color
_STATES = {
    "running": (ft.Icons.AUTORENEW, C_PRIMARY),
    "error":   (ft.Icons.ERROR_OUTLINE, C_ERROR),
    "done":    (ft.Icons.CHECK_CIRCLE_OUTLINE, C_ACCENT),
}


def build_credentials_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    credenciales_ldap: dict,
    on_continue: Callable,
    extra_config: dict | None = None,
    duracion_dias: int | None = None,
    on_back: Callable | None = None,
    *,
    no_ldap: bool,
    is_web: bool = False,
    done_message: str,
    on_cancel: Callable | None = None,
    cancel_label: str = "Back",
) -> ft.Control:
    """Renueva las credenciales STS en un hilo, con el progreso en pantalla.

    Arriba, una tarjeta con el estado (renovando, error con qué hacer, renovadas); debajo, el log de la renovación.
    Si falla, deja reintentar ("Try again"), salvo cuando es la contraseña sin LDAP (`on_back`: volver al login).
    Con `on_cancel`, un botón (`cancel_label`) arriba a la izquierda sale de la pantalla en cualquier momento sin
    esperar al resultado.
    """
    dias = duracion_dias or STS_AUTO_RENEWAL_DAYS
    automatic = duracion_dias is None
    cancelled = False   # tras salir con on_cancel, el hilo que siga en marcha ya no toca la pantalla ni navega

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
        border_radius=8,
        height=240,
    )

    # ── Tarjeta de estado ─────────────────────────────────────────────────
    state_icon  = ft.Icon(ft.Icons.AUTORENEW, size=24)
    state_tile  = ft.Container(content=state_icon, width=48, height=48, border_radius=12,
                               alignment=ft.Alignment.CENTER)
    title_text  = ft.Text("", size=16, weight=ft.FontWeight.W_600, color=C_TEXT)
    status_text = ft.Text("", size=13, color=C_TEXT_DIM)
    progress    = ft.ProgressBar(color=C_PRIMARY, bgcolor=C_SURFACE2, bar_height=4, border_radius=2)
    # Si falla: qué hacer y el código del error, con las mismas piezas que los diálogos de error
    hint_box    = ft.Column(spacing=10, tight=True, visible=False)

    back_btn    = btn_secondary("Back to login", icon=ft.Icons.LOGIN)
    back_btn.visible   = False
    back_btn.on_click  = lambda e: on_back() if on_back else None
    retry_btn   = btn_primary("Try again", icon=ft.Icons.REFRESH)
    retry_btn.visible  = False
    actions     = ft.Row([retry_btn, back_btn], spacing=10, wrap=True)

    def _set_state(kind: str, title: str, status: str = "", *, hint: str = "", ref: str = "") -> None:
        """Pinta la tarjeta (desde el hilo de la UI); no llama a page.update()."""
        icon, color = _STATES[kind]
        state_icon.icon, state_icon.color = icon, color
        state_tile.bgcolor = tint(color, 0.13)
        actions.visible    = kind == "error"
        title_text.value   = title
        status_text.value  = status
        status_text.visible = bool(status)
        progress.visible   = kind == "running"
        hint_box.controls  = ([tip_box(hint)] if hint else []) + ([error_code_row(page, ref)] if ref else [])
        hint_box.visible   = bool(hint or ref)

    _set_state("running", "Renewing MinIO credentials", "Requesting new credentials from MinIO…")

    def panel(msg: str, color: str = C_TEXT):
        """Una línea del panel RENEWAL LOG (no va al log técnico: allí van líneas de resumen)."""
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK, selectable=True)
            )
        backend.ui_call(page, _add)

    def _fail(title: str, *, retry: bool, hint: str = "", ref: str = "") -> None:
        """Estado de error (desde el hilo): para la barra, dice qué hacer y ofrece reintentar y/o volver."""
        def _show():
            if cancelled:
                return
            _set_state("error", title, hint=hint, ref=ref)
            retry_btn.visible = retry
            back_btn.visible  = on_back is not None
            page.update()
        backend.ui_call(page, _show)

    def _retry(e=None) -> None:
        log.info("credentials: retrying profile=%s", perfil_rclone)
        retry_btn.visible = False
        back_btn.visible  = False
        _set_state("running", "Renewing MinIO credentials", "Trying again…")
        log_list.controls.append(
            ft.Text("\n── Trying again ──", size=11, color=C_TEXT_DIM,
                    font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK)
        )
        page.update()
        backend.safe_thread(page, _run).start()

    def _cancel(e=None) -> None:
        nonlocal cancelled
        cancelled = True
        log.info("credentials: renewal of profile=%s left by the user", perfil_rclone)
        on_cancel()

    retry_btn.on_click = _retry

    def _run():
        """Un intento. Un fallo inesperado también deja la pantalla en error, con "Try again", en vez de colgada."""
        try:
            _do_renew()
        except Exception:
            ref = issue_reference(backend.UNEXPECTED, "credentials")
            log.exception("credentials: unexpected error renewing profile=%s ref=%s", perfil_rclone, ref)
            panel(f"\n❌ Unexpected error while renewing the credentials. (Error {ref})", C_ERROR)
            _fail("Renewal failed", retry=True, ref=ref,
                  hint="Something unexpected went wrong. Try again; if it keeps failing, contact ITS with this code.")

    def _do_renew():
        info = backend.get_session_info(perfil_rclone)
        if info is None:
            panel("⚠️  No credentials found for this profile.", C_WARNING)
        elif info.remaining is None:
            panel("⚠️  Could not read expiry from current token.", C_WARNING)
        else:
            panel(f"⚠️  Current credentials expire in: {info.remaining_text()}", C_WARNING)
        log.info("credentials: renewing profile=%s endpoint=%s days=%d current=%s", perfil_rclone, endpoint, dias,
                 info.remaining_text() if info else "none")

        panel(f"\n🔄 Requesting new STS credentials ({dias} days)...", C_PRIMARY)
        panel(f"   Profile  : {perfil_rclone}", C_TEXT_DIM)
        panel(f"   Endpoint : {endpoint}", C_TEXT_DIM)
        panel(f"   User     : {credenciales_ldap['usuario']}", C_TEXT_DIM)

        try:
            creds = backend.get_credentials(
                endpoint,
                credenciales_ldap["usuario"],
                credenciales_ldap["password"],
                dias * 86400,
            )
        except Exception as exc:
            log.warning("credentials: request to MinIO failed: %s", exc)
            issue = backend.issue_for_exception(exc)
            ref = issue_reference(issue, "credentials")
            panel(f"\n❌ Cannot connect to MinIO — {issue.title} (Error {ref})", C_ERROR)
            hint = issue.hint_for(is_web)
            if hint:
                panel(f"   What you can do: {hint}", C_TEXT_DIM)
            _fail(f"Cannot connect to MinIO — {issue.title}", retry=True, hint=hint, ref=ref)
            return

        if creds is None:
            # Sin LDAP (on_back), el login no comprobó la contraseña: es lo más probable. Con LDAP sí la comprobó,
            # así que es otra cosa; la causa está en la línea "sts: …" del log técnico.
            if on_back:
                ref = issue_reference(backend.INVALID_CREDENTIALS, "credentials")
                panel(f"\n❌ Wrong username or password. Please try again. (Error {ref})", C_ERROR)
                # Reintentar con la misma contraseña no sirve: se vuelve al login a escribirla otra vez.
                _fail("Wrong username or password", retry=False, ref=ref,
                      hint="Go back to the login and type your username and password again.")
            else:
                ref = issue_reference(backend.UNEXPECTED, "credentials")
                panel(f"\n❌ Failed to obtain credentials. Check your password or contact ITS. (Error {ref})", C_ERROR)
                _fail("Renewal failed", retry=True, ref=ref,
                      hint="MinIO did not give new credentials. Try again; if it keeps failing, contact ITS "
                           "with this code.")
            return

        panel("\n✅ Credentials obtained successfully.", C_ACCENT)
        panel("   Writing to rclone config...", C_TEXT_DIM)

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
            panel(f"   New credentials expire in: {new_info.remaining_text()}", C_ACCENT)
            log.info("credentials: renewed profile=%s expiry=%s", perfil_rclone, new_info.remaining_text())
        else:
            panel("⚠️  Could not verify the new token in rclone config.", C_WARNING)
            log.warning("credentials: renewed profile=%s, but the new token could not be read back", perfil_rclone)

        panel(f"\n✅ Done. {done_message}", C_ACCENT)

        def _finish():
            if cancelled:
                return
            _set_state("done", "Credentials renewed", done_message)
            page.update()

        backend.ui_call(page, _finish)
        time.sleep(1.2)
        backend.ui_call(page, lambda: None if cancelled else on_continue())

    nav_row = nav_bar(cancel_label, _cancel if on_cancel is not None else None, usuario=credenciales_ldap["usuario"])

    content = ft.Column(
        [
            build_header(subtitle="MinIO credentials — " + ("Auto renewal" if automatic else "Renewal"),
                         IS_WEB=is_web, no_ldap=no_ldap, page=page),
            ft.Container(
                content=ft.Column(
                    [
                        nav_row,
                        ft.Container(height=12),
                        section_title(f"STS {'AUTO-RENEWAL' if automatic else 'RENEWAL'} — {perfil_rclone.upper()}"),
                        ft.Container(height=12),
                        card(
                            ft.Column(
                                [
                                    ft.Row(
                                        [
                                            state_tile,
                                            ft.Column(
                                                [
                                                    title_text,
                                                    ft.Text(
                                                        ("Automatic renewal" if automatic else "Renewal")
                                                        + f" for {dias} days",
                                                        size=12, color=C_TEXT_DIM,
                                                    ),
                                                ],
                                                spacing=3, tight=True, expand=True,
                                            ),
                                        ],
                                        spacing=14,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                    progress,
                                    status_text,
                                    hint_box,
                                    actions,
                                ],
                                spacing=16,
                            ),
                        ),
                        ft.Container(height=20),
                        section_title("RENEWAL LOG"),
                        ft.Container(height=8),
                        log_container,
                    ],
                    spacing=0,
                ),
                expand=True,
                padding=ft.Padding.only(left=24, right=24, top=0, bottom=16),
            ),
        ],
        expand=True,
        spacing=0,
    )

    backend.safe_thread(page, _run).start()
    return content
