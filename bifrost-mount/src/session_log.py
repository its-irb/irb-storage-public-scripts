"""Log persistente de la sesión de bifrost-mount (~/bifrost-mount-logs/)."""

import pathlib
from datetime import datetime

# ── Log persistente ───────────────────────────────────────────────────────
_LOG_DIR  = pathlib.Path.home() / "bifrost-mount-logs"
_LOG_FILE = _LOG_DIR / f"bifrost-mount-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

def _write_to_log_file(msg: str) -> None:
    """Escribe msg en el fichero de log de sesión con timestamp. Falla silenciosamente."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            line = msg if msg.endswith("\n") else msg + "\n"
            f.write(f"[{timestamp}] {line}")
    except Exception:
        pass


def _log_event(msg: str) -> None:
    """Registra un evento de usuario en el log de sesión."""
    _write_to_log_file(msg)
