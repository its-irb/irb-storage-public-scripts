# Log de la wiki

Registro cronológico append-only. Prefijo `## [YYYY-MM-DD] <tipo> | <título>` para parseo. Tipos: `task`, `ingest`, `query`, `lint`.

---

## [2026-05-18] task | bootstrap de la wiki LLM

Creado el scaffolding completo de `docs/wiki/` siguiendo el spec `docs/superpowers/specs/2026-05-18-llm-wiki-design.md`: estructura de carpetas, `CLAUDE_WIKI.md` con el protocolo (ingest/query/lint/cierre de tarea/seguridad), `index.md` y `log.md` vacíos, página de ejemplo [[wheel-local-bifrost-shared]] en `decisiones/`, `.gitignore` actualizado para excluir `raw/`, y puntero añadido al `CLAUDE.md` raíz. Memorias de Claude actualizadas (`project-llm-wiki`, `feedback-end-of-task-logging`).

## [2026-05-19] task | auto-instalación de WinFsp en bifrost-mount

Añadido flujo de auto-instalación de WinFsp en Windows para `bifrost-mount`: cuando falta, la app pregunta y descarga la última release oficial desde la GitHub Releases API (`winfsp/winfsp`), lanza `msiexec /qb` (UAC) y reintenta el mount automáticamente. Backend: nueva excepción `WinFspMissingError` + funciones `_winfsp_latest_msi_url`, `_download_winfsp_msi`, `install_winfsp_windows` en `shared/bifrost_backend/backend.py`. UI: helper `_prompt_install_winfsp` en `bifrost-mount/src/main.py`. Mensajes del flujo en inglés. `bifrost-transfer` queda fuera porque su botón de mount está pendiente de eliminarse en otra tarea. Detalle y decisiones en [[winfsp-auto-install-windows]]. Spec: `docs/superpowers/specs/2026-05-19-winfsp-auto-install-design.md`; plan: `docs/superpowers/plans/2026-05-19-winfsp-auto-install.md`.
