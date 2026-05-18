# Log de la wiki

Registro cronológico append-only. Prefijo `## [YYYY-MM-DD] <tipo> | <título>` para parseo. Tipos: `task`, `ingest`, `query`, `lint`.

---

## [2026-05-18] task | bootstrap de la wiki LLM

Creado el scaffolding completo de `docs/wiki/` siguiendo el spec `docs/superpowers/specs/2026-05-18-llm-wiki-design.md`: estructura de carpetas, `CLAUDE_WIKI.md` con el protocolo (ingest/query/lint/cierre de tarea/seguridad), `index.md` y `log.md` vacíos, página de ejemplo [[wheel-local-bifrost-shared]] en `decisiones/`, `.gitignore` actualizado para excluir `raw/`, y puntero añadido al `CLAUDE.md` raíz. Memorias de Claude actualizadas (`project-llm-wiki`, `feedback-end-of-task-logging`).
