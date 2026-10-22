"""Helpers thread-safe para la UI de Flet."""

from __future__ import annotations

import logging
import threading
import traceback

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
    """
    Crea un Thread que captura cualquier excepción no controlada y la muestra
    en un diálogo de error en lugar de matar el proceso silenciosamente.
    """
    def _wrapper():
        try:
            target()
        except Exception as exc:
            from bifrost_frontend.frontend import show_dialog, C_ERROR  # lazy: evita import circular
            tb = traceback.format_exc()
            print(f"[safe_thread] Unhandled exception:\n{tb}")
            _exc = exc  # capture before Python deletes the except-clause variable
            def _show(e=_exc):
                show_dialog(
                    page,
                    "Unexpected error",
                    f"{type(e).__name__}: {e}\n\nCheck console or contact ITS.",
                    C_ERROR,
                )
            ui_call(page, _show)

    t = threading.Thread(target=_wrapper, daemon=daemon)
    return t
