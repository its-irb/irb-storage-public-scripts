"""Cierre ordenado de bifrost-mount y bifrost-transfer.

Una sola limpieza por proceso, llegue el cierre por donde llegue: salida normal (atexit), señal del sistema
(SIGTERM de Slurm/Open OnDemand o DCV, Ctrl+C) o cierre de la ventana (la app llama a la función que
devuelve register_shutdown).
"""

from __future__ import annotations

import atexit
import logging
import signal
import sys
from typing import Callable

log = logging.getLogger("bifrost.shutdown")

_state: dict = {"cleanup": None, "server_managed": False, "done": False}


def register_shutdown(cleanup: Callable[[], None], *, server_managed: bool = False) -> Callable[[], None]:
    """Registra `cleanup` para el cierre del proceso y devuelve la versión que se ejecuta una sola vez.

    Se llama una vez, al importar la app (desde el hilo principal, el único donde se pueden instalar
    manejadores de señal).

    `server_managed=True` es para producción en Open OnDemand, donde Hypercorn ejecuta la app en un proceso
    hijo y es su proceso padre quien decide el cierre:
      - el hijo ignora SIGINT a propósito (Ctrl+C lo gestiona el padre), así que no se toca;
      - el hijo no tiene manejador de SIGTERM y un scancel (Delete en Open OnDemand) lo mataría sin limpiar,
        así que se instala uno que solo limpia: el padre recibe la misma señal y cierra el hijo de forma
        ordenada (un sys.exit aquí cortaría ese cierre a medias).
    """
    if _state["cleanup"] is not None:
        raise RuntimeError("register_shutdown() ya se ha llamado en este proceso")
    _state.update(cleanup=cleanup, server_managed=server_managed)
    atexit.register(_run_once)
    install_signal_handlers()
    return _run_once


def install_signal_handlers() -> None:
    """(Re)instala los manejadores de señal del cierre registrado con register_shutdown.

    En escritorio fuera de la app empaquetada (`flet run`, `python main.py`), ft.run() instala al arrancar
    sus propios manejadores, que no cierran la app (solo marcan un evento que en la vista de escritorio nadie
    espera) y hacen que la segunda señal la mate sin limpiar. Por eso la app los vuelve a instalar desde
    main(), que se ejecuta después.
    """
    sigs = (signal.SIGTERM,) if _state["server_managed"] else (signal.SIGTERM, signal.SIGINT)
    for sig in sigs:
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            log.warning("Cannot install handler for %s (not in the main thread)", sig.name)


def _run_once() -> None:
    if _state["done"]:
        return
    _state["done"] = True
    log.info("APP shutdown — cleaning up")
    _state["cleanup"]()


def _on_signal(signum, frame) -> None:
    log.info("APP shutdown requested (reason=%s)", signal.Signals(signum).name)
    # Se limpia aquí y no se confía en atexit: en la app empaquetada, Flet sustituye sys.exit por una función
    # que avisa al lanzador y no termina el intérprete, así que atexit no llegaría a ejecutarse.
    _run_once()
    if not _state["server_managed"]:
        sys.exit(0)
