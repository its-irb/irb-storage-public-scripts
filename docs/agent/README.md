# Documentación para agentes — BIFROST

Capa compacta y modular para localizar y modificar el código con seguridad. Cada documento cubre un ámbito independiente; cargar solo el necesario para la tarea.

| Documento | Ámbito |
|---|---|
| `architecture.md` | Responsabilidades, layout del repo, acoplamiento app↔shared, entry points |
| `backend.md` | Secciones de `shared/bifrost_backend/backend.py`, invariantes (`ui_call`, `safe_thread`), resolución rclone, STS, tagging S3 |
| `frontend.md` | Flujos de vistas de `main.py`, modo web (OOD), thread-safety, convenciones de UI |
| `meta-fields.md` | `meta_fields.py` (solo transfer): `TAG_PROFILES`, `LAB_ACRONYMS`, `detect_profile`, lab filter |
| `build-release.md` | Build/packaging por plataforma, CI, versioning, wheel `bifrost-shared` |
| `conventions.md` | Idioma, paleta, diálogos, variables de entorno, logs, reglas críticas |

Para contexto técnico amplio consultar `docs/development/`. Para superficie de uso, `docs/user/`. Esta capa debe ser suficiente para el trabajo habitual sin salir de ella.

Reglas de oro (ver `frontend.md` y `backend.md` para detalle):

1. Toda mutación de `control.controls` o `page.update()` desde un hilo → `backend.ui_call(page, fn)`. Usar `backend.safe_thread(page, target)` para hilos.
2. `TAG_PROFILES`, `LAB_ACRONYMS`, `build_meta_fields`, `detect_profile`, `build_lab_filter_widget` se editan **solo** en `bifrost-transfer/src/meta_fields.py`.
3. No asumir path de rclone: siempre `backend.get_rclone_executable()`.
4. No commitear `.venv/`, `dist/`, `build/`, `*.whl`, `uv.lock`, `src/assets/*` (salvo `.keep`/`icon.png`/`splash.png`), `frameworks/*` (salvo `.keep`) (ver `.gitignore`). `src/version.py` sí se commitea con el placeholder `2.0.0.dev`; CI lo sobrescribe en build.
5. `config.py` debe ser importable como módulo top-level en cada app (el backend hace `from config import APP_INFO`).
