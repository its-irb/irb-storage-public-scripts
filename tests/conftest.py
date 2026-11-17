"""Configuración global de pytest.

El código compartido vive en ``shared/`` y espera dos módulos que aporta cada app
(``config`` y ``version``, en ``bifrost-<flavour>/src``). Aquí se hace importable
``shared/`` y se registra un ``config`` de pruebas para no depender de ninguna app.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "shared"))

if "config" not in sys.modules:
    _config = types.ModuleType("config")
    _config.APP_INFO = {"flavour": "test", "name": "BIFROST TEST", "description": "tests"}
    sys.modules["config"] = _config
