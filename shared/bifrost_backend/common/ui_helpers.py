"""Helpers thread-safe para la UI de Flet."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from .rclone_output import UNEXPECTED

if TYPE_CHECKING:
    import flet as ft

log = logging.getLogger("bifrost.ui")


def ui_call(page: ft.Page, fn: Callable) -> bool:
    """Ejecuta *fn* en el bucle de la UI. Devuelve False si no se pudo (página desconectada)."""
    # Use run_task (asyncio coroutine) instead of run_thread (ThreadPoolExecutor).
    # Flet's ObjectPatch.from_diff walks control.controls as a live list with no
    # lock; run_thread runs fn() in a thread pool *in parallel* to the asyncio
    # event loop, so concurrent .controls.clear()/.extend() from the thread pool
    # races with the diff walker → IndexError: list index out of range.
    # run_task schedules the coroutine on the same asyncio event loop; since
    # _compare_lists contains no `await`, no run_task coroutine can preempt it
    # mid-iteration, eliminating the race entirely.

    # Guard: skip UI updates if WebSocket connection is closed (OOD reconnection scenario).
    # page.session raises RuntimeError once Flet has destroyed the session (tab closed for longer
    # than FLET_SESSION_TIMEOUT). Debug level: a closed tab skips several updates per second.
    try:
        connected = page.session.connection
    except RuntimeError:
        connected = None
    if not connected:
        log.debug("Skipping UI update — session disconnected")
        return False

    async def _wrapper():
        fn()
    page.run_task(_wrapper)
    return True


def safe_thread(page: ft.Page, target: Callable, daemon: bool = True) -> threading.Thread:
    """Crea un Thread que, si `target` falla sin controlarlo, deja la traza en el log técnico con un código y se
    lo muestra al usuario (UNEXPECTED), en lugar de perder el error en silencio."""
    def _wrapper():
        try:
            target()
        except Exception:
            from bifrost_frontend.frontend import show_issue  # lazy: evita import circular
            ref = UNEXPECTED.reference("app")
            log.exception("unexpected error ref=%s", ref)
            ui_call(page, lambda: show_issue(page, UNEXPECTED, is_web=page.web, screen="app", ref=ref))

    return threading.Thread(target=_wrapper, daemon=daemon)
