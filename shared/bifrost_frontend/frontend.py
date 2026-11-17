"""Fachada de compatibilidad: reexporta el frontend dividido en módulos.

Las apps (`from bifrost_frontend.frontend import *`), meta_fields.py y
backend.common.ui_helpers siguen importando desde aquí; el código vive en
theme.py, components.py y views/.
"""

# Imports que el frontend.py original exponía a través de `import *`. Se
# mantienen para no cambiar los nombres que reciben las apps.
import sys
import os
from typing import Callable
import flet as ft
import subprocess
import shutil
from bifrost_backend import backend
from config import APP_INFO
from pathlib import Path
import tempfile

from .theme import *
from .components import *
from .views.update import build_update_content
from .views.login import build_login_content
from .views.minio import build_minio_content
from .views.credentials import build_credentials_content
