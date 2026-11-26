"""Componentes Flet reutilizables: botones, campos, diálogos, cabecera y cierre de la ventana."""

import logging
import os
from typing import Callable

import flet as ft
from bifrost_backend import backend
from bifrost_backend.common.constants import STS_RENEWAL_THRESHOLD_DAYS
from config import APP_INFO

from .theme import (
    C_ACCENT, C_BORDER, C_ERROR, C_OVERLAY, C_PRIMARY, C_SURFACE, C_SURFACE2,
    C_TEXT, C_TEXT_DIM, C_WARNING, FONT_MONO, FONT_REGULAR, MONO_FALLBACK,
    REGULAR_FALLBACK, tint,
)

log = logging.getLogger("bifrost.ui")

# ============================================================================
# BUTTONS
# ============================================================================


def btn_primary(text: str, on_click=None, width=None, disabled=False, icon=None) -> ft.Button:
    return ft.Button(
        content=ft.Text(text, font_family=FONT_REGULAR, font_family_fallback=REGULAR_FALLBACK),
        icon=icon,
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
    
def btn_secondary(text: str, on_click=None, width=None, icon=None) -> ft.OutlinedButton:
    return ft.OutlinedButton(
        content=ft.Text(text, font_family=FONT_REGULAR, font_family_fallback=REGULAR_FALLBACK),
        icon=icon,
        on_click=on_click,
        width=width,
        style=ft.ButtonStyle(
            color=C_TEXT,
            side=ft.BorderSide(1, C_BORDER),
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.padding.symmetric(horizontal=20, vertical=12),
        ),
    )


def btn_nav(text: str, on_click=None, icon=ft.Icons.ARROW_BACK) -> ft.TextButton:
    """Botón discreto de navegación ("Back to login"), arriba a la izquierda de la pantalla."""
    return ft.TextButton(
        content=ft.Text(text, size=13, font_family=FONT_REGULAR, font_family_fallback=REGULAR_FALLBACK),
        icon=icon,
        on_click=on_click,
        style=ft.ButtonStyle(
            color={ft.ControlState.DEFAULT: C_TEXT_DIM, ft.ControlState.HOVERED: C_TEXT},
            shape=ft.RoundedRectangleBorder(radius=6),
            # Sin margen a la izquierda: el icono queda alineado con el borde del contenido de debajo.
            padding=ft.Padding.only(left=0, right=10, top=8, bottom=8),
        ),
    )


def icon_tile(icon, color: str, size: int = 44) -> ft.Container:
    """Un icono sobre un cuadrado redondeado del mismo color, translúcido (cabeza de tarjetas y estados)."""
    return ft.Container(
        content=ft.Icon(icon, color=color, size=round(size / 2)),
        width=size,
        height=size,
        bgcolor=tint(color, 0.13),
        border_radius=round(size / 4),
        alignment=ft.Alignment.CENTER,
    )


def nav_bar(back_text: str | None = None, on_back: Callable | None = None, *,
            usuario: str | None = None) -> ft.Row:
    """Fila de arriba de una pantalla: a la izquierda, volver (`back_text`, si hay `on_back`); a la derecha, con qué
    usuario se ha entrado."""
    left: list[ft.Control] = [btn_nav(back_text or "Back", on_click=lambda e: on_back())] if on_back else []
    right: list[ft.Control] = [
        ft.Icon(ft.Icons.PERSON_OUTLINE, size=16, color=C_TEXT_DIM),
        ft.Text(f"Signed in as {usuario}", size=12, color=C_TEXT_DIM),
    ] if usuario else []
    return ft.Row([*left, ft.Container(expand=True, height=36), *right], spacing=6,
                  vertical_alignment=ft.CrossAxisAlignment.CENTER)


def expiry_label(session) -> tuple[str, str]:
    """El texto y el color de la caducidad de las credenciales de un perfil (rojo con menos de 1 día, ámbar hasta
    3). `session`: el `SessionInfo` (`backend.get_session_info`), o None si no tiene credenciales."""
    if session is None:
        return "No credentials yet", C_TEXT_DIM
    if session.remaining is None:
        return "Credentials: unknown expiry", C_TEXT_DIM
    if session.expired:
        return "Credentials expired", C_ERROR
    dias = session.remaining.days
    color = C_ERROR if dias < 1 else C_WARNING if dias <= STS_RENEWAL_THRESHOLD_DAYS else C_ACCENT
    return f"Credentials expire in {session.remaining_text()}", color


def expiry_chip(session) -> ft.Container:
    """Etiqueta con la llave y la caducidad de las credenciales (ver `expiry_label`)."""
    text, color = expiry_label(session)
    return ft.Container(
        content=ft.Row([ft.Icon(ft.Icons.KEY, size=13, color=color),
                        ft.Text(text, size=11, color=color, weight=ft.FontWeight.W_600)], spacing=6, tight=True),
        bgcolor=tint(color, 0.13),
        border=ft.Border.all(1, tint(color, 0.33)),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=10, vertical=5),
        tooltip="MinIO credentials for this server",
    )


@ft.control
class ErrorBanner(ft.Container):
    """Un error dentro de una pantalla o un diálogo: icono y texto sobre un recuadro rojo suave.

    Se usa como el ft.Text rojo al que sustituye: se cambian `value` y `visible`. Un emoji del principio del texto
    ("⚠️ …", el de issue_line) se quita, porque ya lleva el icono.
    """
    value: str = ""

    def init(self):
        self._text = ft.Text("", size=12, color=C_TEXT, selectable=True, expand=True)
        self.content = ft.Row([ft.Icon(ft.Icons.ERROR_OUTLINE, size=16, color=C_ERROR), self._text],
                              spacing=8, vertical_alignment=ft.CrossAxisAlignment.START)
        self.bgcolor = tint(C_ERROR, 0.10)
        self.border = ft.Border.all(1, tint(C_ERROR, 0.35))
        self.border_radius = 8
        self.padding = ft.Padding.symmetric(horizontal=12, vertical=8)

    def before_update(self):
        super().before_update()
        text = (self.value or "").strip()
        for emoji in ("⚠️", "❌"):
            text = text.removeprefix(emoji).strip()
        self._text.value = text


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
        font_family_fallback=MONO_FALLBACK,
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
        bgcolor=tint(color, 0.13),
        border=ft.Border.all(1, tint(color, 0.33)),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
    )
    
def log_text(line: str) -> ft.Text:
    """Una línea de un panel de log. El color sale de su emoji inicial, con el mismo criterio en todas las
    pantallas."""
    color = (
        C_ACCENT   if line.startswith("✅") else
        C_ERROR    if line.startswith("❌") else
        C_WARNING  if line.startswith(("⚠️", "⏹")) else
        C_PRIMARY  if line.startswith(("🔍", "📤", "📁", "🧪")) else
        C_TEXT_DIM if line.startswith(("⏳", "🔁", "📄")) else
        C_TEXT
    )
    return ft.Text(line.rstrip("\n"), size=11, color=color,
                   font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK, selectable=True)


# ============================================================================
# DIÁLOGOS GENÉRICOS
# ============================================================================

    
_DIALOG_ICONS = {
    C_ACCENT:  ft.Icons.CHECK_CIRCLE_OUTLINE,
    C_ERROR:   ft.Icons.ERROR_OUTLINE,
    C_WARNING: ft.Icons.WARNING_AMBER_ROUNDED,
}


def open_dialog(page: ft.Page, *, title: str, color: str, icon, body: list[ft.Control], actions: list,
                 subtitle: str = "") -> None:
    """Diálogo modal con el aspecto común: icono en un cuadrado del color del tipo, título (y debajo `subtitle`, a
    qué se refiere), el cuerpo y los botones a la derecha."""
    head = ft.Row(
        [
            icon_tile(icon, color, size=40),
            ft.Column(
                [ft.Text(title, color=C_TEXT, size=16, weight=ft.FontWeight.W_600)]
                + ([ft.Text(subtitle, color=C_TEXT_DIM, size=12, selectable=True)] if subtitle else []),
                spacing=2, tight=True, expand=True,
            ),
        ],
        spacing=14,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )
    dlg = ft.AlertDialog(
        modal=True,
        title=head,
        content=ft.Column(body, spacing=12, tight=True, width=460),
        actions=actions,
        actions_alignment=ft.MainAxisAlignment.END,
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=12),
        title_padding=ft.Padding.only(left=24, top=24, right=24, bottom=0),
        content_padding=ft.Padding.only(left=24, top=18, right=24, bottom=4),
        actions_padding=ft.Padding.only(left=24, top=16, right=24, bottom=20),
    )
    page.show_dialog(dlg)
    page.update()


def show_dialog(
    page: ft.Page,
    title: str,
    message: str,
    color: str = C_TEXT,
    actions: list | None = None,
    content: ft.Control | None = None,
):
    """Diálogo modal. `content` sustituye al texto de `message` si se pasa. El color da el icono (éxito, error,
    aviso o información)."""
    def close(e=None):
        page.pop_dialog()

    if not actions:
        actions = [btn_primary("OK", on_click=close)]

    open_dialog(
        page, title=title, color=color if color in _DIALOG_ICONS else C_PRIMARY,
        icon=_DIALOG_ICONS.get(color, ft.Icons.INFO_OUTLINE),
        body=[content or ft.Text(message, color=C_TEXT_DIM, size=13, selectable=True)],
        actions=actions,
    )


def tip_box(text: str) -> ft.Container:
    """Recuadro "What you can do": qué puede hacer el usuario ante un error."""
    return ft.Container(
        content=ft.Row(
            [
                ft.Icon(ft.Icons.LIGHTBULB_OUTLINE, size=16, color=C_WARNING),
                ft.Column(
                    [
                        ft.Text("What you can do", size=11, color=C_WARNING, weight=ft.FontWeight.W_600),
                        ft.Text(text, size=13, color=C_TEXT, selectable=True),
                    ],
                    spacing=2, tight=True, expand=True,
                ),
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.START,
        ),
        bgcolor=tint(C_WARNING, 0.08),
        border=ft.Border.all(1, tint(C_WARNING, 0.25)),
        border_radius=8,
        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
    )


def error_code_row(page: ft.Page, ref: str) -> ft.Container:
    """El código del error, que el usuario pasa a ITS, con un botón para copiarlo."""
    copy_btn = ft.IconButton(icon=ft.Icons.CONTENT_COPY, icon_size=16, icon_color=C_TEXT_DIM, tooltip="Copy code")

    async def _copy(e):
        try:
            await page.clipboard.set(ref)
        except Exception as ex:                     # sin portapapeles (p. ej. el navegador no lo deja): no pasa nada
            log.debug("copying the error code failed: %s", ex)
            return
        copy_btn.icon, copy_btn.icon_color, copy_btn.tooltip = ft.Icons.CHECK, C_ACCENT, "Copied"
        copy_btn.update()

    copy_btn.on_click = _copy
    return ft.Container(
        content=ft.Row(
            [
                ft.Text("Error code", size=11, color=C_TEXT_DIM),
                ft.Text(ref, size=12, color=C_TEXT, selectable=True, expand=True,
                        font_family=FONT_MONO, font_family_fallback=MONO_FALLBACK),
                copy_btn,
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE2,
        border_radius=8,
        padding=ft.Padding.only(left=12, right=4, top=2, bottom=2),
    )


def show_issue(
    page: ft.Page,
    issue,
    *,
    is_web: bool,
    title: str | None = None,
    context: str = "",
    screen: str = "copy",
    buttons: list[tuple[str, Callable | None]] | None = None,
    color: str = C_ERROR,
    ref: str | None = None,
) -> str:
    """Diálogo de error a partir de un UserIssue (common/rclone_output.py). Devuelve el código del error.

    Debajo del título, `context` (el bucket, el fichero o el recuento al que se refiere; nunca listas de ficheros
    ni rutas de logs); después qué ha pasado, qué puede hacer el usuario (recuadro "What you can do") y el código
    ("MNT101-1103-141526", con un botón para copiarlo). `screen` ("mount", "netapp", "copy", "check", "tags" o "app") da el principio del código y la pista.
    `ref`: el código que ya tiene este error (el de una operación, o el de la primera vez que se mostró).
    `buttons` son pares (texto, acción): cada botón cierra el diálogo y después ejecuta su acción; el último es
    el principal.
    """
    def _button(label: str, action: Callable | None, primary: bool):
        def _click(e):
            page.pop_dialog()
            if action:
                action()
        return (btn_primary if primary else btn_secondary)(label, on_click=_click)

    ref = issue_reference(issue, screen, ref)
    buttons = buttons or [("OK", None)]
    # Con un título propio, el del issue va delante del mensaje para no perder la causa.
    body: list[ft.Control] = [ft.Text(f"{issue.title}: {issue.message}" if title else issue.message,
                                      color=C_TEXT, size=13, selectable=True)]
    if hint := issue.hint_for(is_web, screen=screen):
        body.append(tip_box(hint))
    body.append(error_code_row(page, ref))
    open_dialog(
        page, title=title or issue.title, subtitle=context, color=color,
        icon=_DIALOG_ICONS.get(color, ft.Icons.INFO_OUTLINE), body=body,
        actions=[_button(label, action, i == len(buttons) - 1) for i, (label, action) in enumerate(buttons)],
    )
    return ref


def issue_line(issue, *, is_web: bool, screen: str) -> str:
    """Un error en una línea, para mostrarlo en lugar de una lista que no se pudo cargar: qué ha pasado, su código
    y qué hacer."""
    ref = issue_reference(issue, screen)
    hint = issue.hint_for(is_web, screen=screen)
    return f"⚠️ {issue.title} (Error {ref}). {hint}" if hint else f"⚠️ {issue.title} (Error {ref})."


def issue_reference(issue, screen: str, ref: str | None = None) -> str:
    """El código del error que se va a mostrar (uno nuevo si no tiene) y su línea en el log técnico, que es lo que
    busca ITS. Sin el contexto: puede ser el nombre de un fichero. Lo usan show_issue, issue_line y los mensajes
    que no son ninguno de los dos: la pantalla de credenciales y el login (este solo anota la línea, sin enseñar
    el código)."""
    ref = ref or issue.reference(screen)
    log.warning("issue shown: ref=%s code=%s screen=%s", ref, issue.code, screen)
    return ref


# ============================================================================
# HEADER COMÚN
# ============================================================================

def build_header(subtitle: str = "", IS_WEB: bool = False, no_ldap: bool = False,
                 page: ft.Page | None = None) -> ft.Container:
    """Cabecera de cada pantalla. Con `page`, en escritorio, lleva el botón "Export logs…" (en Open OnDemand los
    logs están en la carpeta de la sesión)."""
    version_str = f"v{backend.__version__}" if hasattr(backend, "__version__") else ""
    right: list[ft.Control] = [ft.Text(version_str, size=11, color=C_TEXT_DIM, font_family=FONT_MONO,
                                       font_family_fallback=MONO_FALLBACK)]
    if page is not None and not page.web:
        right.insert(0, ft.TextButton(
            content=ft.Text("Export logs…", size=12),
            icon=ft.Icons.DOWNLOAD,
            style=ft.ButtonStyle(color=C_TEXT_DIM),
            on_click=lambda e: _confirm_export_logs(page),
        ))
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
                                    font_family_fallback=MONO_FALLBACK,
                                ),
                                ft.Container(width=8),
                                status_badge("WEB" if IS_WEB else ("DESKTOP (NO LDAP)" if no_ldap else "DESKTOP"), C_WARNING),
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Text(subtitle or APP_INFO["description"], size=12, color=C_TEXT_DIM),
                    ],
                    spacing=2,
                    expand=True,
                ),
                ft.Row(right, spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE,
        border=ft.Border.only(bottom=ft.BorderSide(1, C_BORDER)),
        padding=ft.Padding.symmetric(horizontal=24, vertical=16),
        margin=ft.Margin.only(bottom=24),
    )


def _confirm_export_logs(page: ft.Page) -> None:
    """Dice qué se va a exportar y, si el usuario acepta, guarda el zip en Descargas y lo muestra seleccionado."""
    text = (f"BIFROST will save the logs of your last {backend.EXPORTED_SESSIONS} sessions to your Downloads folder "
            "so you can send them to ITS.")
    if APP_INFO["flavour"] == "transfer":
        text += (" It also includes the copy, check and Tag Manager reports of those sessions, which contain file "
                 "names and tag values.")

    def _export(e):
        page.pop_dialog()
        try:
            zip_path = backend.export_logs_zip()
        except OSError as ex:
            log.warning("exporting the logs failed: %s", ex)
            show_issue(page, backend.issue_for_exception(ex), is_web=False, title="Could not export the logs",
                       screen="app")
            return
        backend.open_in_file_browser(zip_path, select=True)
        show_dialog(page, "Logs exported", "Saved to Downloads. Send this file to ITS with the error code.", C_ACCENT)

    show_dialog(page, "Export logs", text, C_PRIMARY,
                actions=[btn_secondary("Cancel", on_click=lambda e: page.pop_dialog()),
                         btn_primary("Export", on_click=_export)])


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

    open_dialog(
        page, title=title, color=C_PRIMARY, icon=ft.Icons.HELP_OUTLINE,
        body=[ft.Text(message, color=C_TEXT_DIM, size=13)],
        actions=[btn_secondary("No", on_click=no), btn_primary("Yes", on_click=yes)],
    )


# ============================================================================
# CIERRE DE LA VENTANA (ESCRITORIO)
# ============================================================================

def install_window_close(page: ft.Page) -> None:
    """Al cerrar la ventana: la limpieza de la app (una sola vez, common/shutdown.py), destruir la ventana y salir."""
    async def _on_window_event(e: ft.WindowEvent):
        if e.type == ft.WindowEventType.CLOSE:
            backend.request_shutdown("window")
            await page.window.destroy()
            os._exit(0)                # destruir la ventana no termina el proceso de Python

    page.window.on_event = _on_window_event
    page.window.prevent_close = True
