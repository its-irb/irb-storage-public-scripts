"""Persistencia de sesiones en modo web (memoria del proceso; nunca guarda contraseñas)."""

from __future__ import annotations


from bifrost_backend import backend

from meta_fields import TAG_PROFILES

# main.py fija el valor real al arrancar: IS_WEB solo puede calcularse en main.py
# (depende de __name__), y las funciones de este módulo lo leen al ejecutarse.
IS_WEB = False


# ============================================================================
# SESSION PERSISTENCE (web mode — in-memory, TTL = Hypercorn process lifetime)
# ============================================================================
#
# _WEB_SESSIONS[username] holds every piece of navigation state that can be
# restored without the user's password:
#   - servidor_minio, perfil_rclone, endpoint, extra_config
#   - copy_log_buffer  — accumulated log lines from a running/finished copy
#   - copy_proceso     — dict shared by reference with the copy view: "proc" (the
#                        live subprocess.Popen or None), "cancelled" and "status"
#                        ("running" or the RunSummary outcome of the last copy/check)
#   - copy_origen, copy_destino  — last copy paths
#   - copy_log_callbacks         — callables registered by the current UI page;
#                                  multiple sessions may subscribe simultaneously
#
# The password is NEVER stored here.
# ============================================================================

_WEB_SESSIONS: dict[str, dict] = {}
_LAST_WEB_USER: list[str] = [None]   # one-element list so closures can mutate it


def _ws_save(usuario: str, state: dict) -> None:
    """Persist navigation + copy state for *usuario* into the in-memory store."""
    if not IS_WEB:
        return
    existing = _WEB_SESSIONS.get(usuario, {})
    _WEB_SESSIONS[usuario] = {
        # navigation state (enough to skip update/shares/minio on reconnect)
        "servidor_minio": state.get("servidor_minio"),
        "perfil_rclone":  state.get("perfil_rclone"),
        "endpoint":       state.get("endpoint"),
        "extra_config": (
            backend.MINIO_SERVERS
            .get(state.get("servidor_minio") or "", {})
            .get("IRB", {})
            .get("extra_rclone_config")
        ),
        # copy state — always inherited so a running copy survives reconnection
        "copy_log_buffer":    existing.get("copy_log_buffer", []),
        "copy_origen":        existing.get("copy_origen", ""),
        "copy_destino":       existing.get("copy_destino", ""),
        "copy_log_callbacks": existing.get("copy_log_callbacks", []),
        # The Popen wrapper dict — shared with the background thread so that
        # a new UI session can cancel a process that survived a tab close.
        "copy_proceso":        existing.get("copy_proceso", {"proc": None}),
        "copy_tag_profile":   existing.get("copy_tag_profile", list(TAG_PROFILES.keys())[0]),
    }
    _LAST_WEB_USER[0] = usuario
    print(f"[session] Saved session for {usuario!r}")


def _ws_load(usuario: str) -> dict | None:
    """Return the persisted session for *usuario*, or None if absent/incomplete."""
    s = _WEB_SESSIONS.get(usuario)
    if s and s.get("perfil_rclone") and s.get("endpoint"):
        return s
    return None


def _ws_clear(usuario: str) -> None:
    """Remove the session for *usuario*."""
    session = _WEB_SESSIONS.get(usuario, {})
    # Clear callbacks first so they don't fire on a dead page object after logout.
    session.get("copy_log_callbacks", []).clear()
    # Cancel any pending throttle timer so it doesn't fire on a dead session.
    t = session.get("_dispatch_timer")
    if t:
        t.cancel()
    _WEB_SESSIONS.pop(usuario, None)
    if _LAST_WEB_USER[0] == usuario:
        _LAST_WEB_USER[0] = None
    print(f"[session] Cleared session for {usuario!r}")
