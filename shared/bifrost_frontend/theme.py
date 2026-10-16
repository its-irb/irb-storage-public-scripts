"""Paleta de colores, fuentes y tema global de las apps BIFROST."""

import flet as ft
from bifrost_backend import backend
from config import APP_INFO

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
# Fuente principal para el texto general (botones, TextTheme). No está
# instalada en Linux/macOS, así que ahí cae directamente al fallback
# ("sans-serif", resuelto por fontconfig/Core Text); en Windows sí existe
# y se usa tal cual.
FONT_REGULAR = "Segoe UI"
EMOJI_FONT_FAMILY = "NotoColorEmoji"
_SYSTEM_FALLBACK_FONTS = ["sans-serif"]
MONO_FALLBACK = ["monospace", EMOJI_FONT_FAMILY]
REGULAR_FALLBACK = ["sans-serif", EMOJI_FONT_FAMILY]

def apply_theme(page: ft.Page) -> None:
    page.title             = APP_INFO["name"]
    page.bgcolor           = C_BG
    page.window.width      = 1100
    page.window.height     = 820
    page.window.min_width  = 800
    page.window.min_height = 600
    page.theme             = ft.Theme(color_scheme_seed=C_PRIMARY)
    page.theme_mode        = ft.ThemeMode.DARK
    page.padding           = 0

    # Registrar NotoColorEmoji como fallback emoji global.
    font_rel = backend.get_emoji_font_asset_path()
    if not font_rel:
        return
    family = EMOJI_FONT_FAMILY
    page.fonts = {family: font_rel}

    # Fallback ordenado: fuentes del sistema primero, emoji al final.
    fallback = _SYSTEM_FALLBACK_FONTS + [family]
    # Los 15 estilos de TextTheme (Material 3).
    styles = {
        attr: ft.TextStyle(font_family=FONT_REGULAR, font_family_fallback=fallback)
        for attr in (
            "body_large", "body_medium", "body_small",
            "display_large", "display_medium", "display_small",
            "headline_large", "headline_medium", "headline_small",
            "label_large", "label_medium", "label_small",
            "title_large", "title_medium", "title_small",
        )
    }
    page.theme.text_theme = ft.TextTheme(**styles)
