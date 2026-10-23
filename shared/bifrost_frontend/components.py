"""Componentes Flet reutilizables: botones, campos, diálogos y cabecera."""

from typing import Callable

import flet as ft
from bifrost_backend import backend
from config import APP_INFO

from .theme import (
    C_ACCENT, C_BORDER, C_ERROR, C_OVERLAY, C_PRIMARY, C_SURFACE, C_SURFACE2,
    C_TEXT, C_TEXT_DIM, C_WARNING, FONT_MONO, FONT_REGULAR, MONO_FALLBACK,
    REGULAR_FALLBACK,
)

# ============================================================================
# BUTTONS
# ============================================================================


def btn_primary(text: str, on_click=None, width=None, disabled=False) -> ft.Button:
    return ft.Button(
        content=ft.Text(text, font_family=FONT_REGULAR, font_family_fallback=REGULAR_FALLBACK),
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
        content=ft.Text(text, font_family=FONT_REGULAR, font_family_fallback=REGULAR_FALLBACK),
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
        bgcolor=f"{color}22",
        border=ft.Border.all(1, f"{color}55"),
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

    
def show_dialog(
    page: ft.Page,
    title: str,
    message: str,
    color: str = C_TEXT,
    actions: list | None = None,
    content: ft.Control | None = None,
):
    """Diálogo modal. `content` sustituye al texto de `message` si se pasa."""
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
        content=content or ft.Text(message, color=C_TEXT_DIM, size=13),
        actions=actions,
        bgcolor=C_OVERLAY,
        shape=ft.RoundedRectangleBorder(radius=10),
    )
    page.show_dialog(dlg)
    page.update()


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
) -> None:
    """Diálogo de error a partir de un UserIssue (common/rclone_output.py).

    Muestra `context` (el fichero o el recuento al que se refiere; nunca listas de ficheros), qué ha pasado y
    qué puede hacer el usuario según la pantalla (`screen`: "copy" o "tags"). `buttons` son pares
    (texto, acción): cada botón cierra el diálogo y después ejecuta su acción; el último es el principal.
    El PR 4 añadirá aquí la referencia del error y "Copy details".
    """
    def _button(label: str, action: Callable | None, primary: bool):
        def _click(e):
            page.pop_dialog()
            if action:
                action()
        return (btn_primary if primary else btn_secondary)(label, on_click=_click)

    buttons = buttons or [("OK", None)]
    texts = [ft.Text(context, color=C_TEXT, size=13, selectable=True)] if context else []
    # Con un título propio, el del issue va delante del mensaje para no perder la causa.
    texts.append(ft.Text(f"{issue.title}: {issue.message}" if title else issue.message, color=C_TEXT_DIM, size=13))
    if hint := issue.hint_for(is_web, screen=screen):
        texts.append(ft.Text(f"What you can do: {hint}", color=C_TEXT_DIM, size=13))
    show_dialog(
        page, title or issue.title, "", color,
        actions=[_button(label, action, i == len(buttons) - 1) for i, (label, action) in enumerate(buttons)],
        content=ft.Column(texts, spacing=10, tight=True, width=460),
    )


# ============================================================================
# HEADER COMÚN
# ============================================================================

def build_header(subtitle: str = "", IS_WEB: bool = False, no_ldap: bool = False) -> ft.Container:
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
                ft.Text(version_str, size=11, color=C_TEXT_DIM, font_family=FONT_MONO,
                        font_family_fallback=MONO_FALLBACK),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C_SURFACE,
        border=ft.Border.only(bottom=ft.BorderSide(1, C_BORDER)),
        padding=ft.Padding.symmetric(horizontal=24, vertical=16),
        margin=ft.Margin.only(bottom=24),
    )


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
    #page.overlay.append(dlg)
    #dlg.open = True
    page.show_dialog(dlg)
    page.update()
