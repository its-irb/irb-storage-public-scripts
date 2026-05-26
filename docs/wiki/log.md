# Log de la wiki

Registro cronológico append-only. Prefijo `## [YYYY-MM-DD] <tipo> | <título>` para parseo. Tipos: `task`, `ingest`, `query`, `lint`.

---

## [2026-05-21] task | Tag Manager — browser de solo carpetas con "View files"

Cambiado el comportamiento del browser de MinIO en el Tag Manager (`bifrost-transfer/src/main.py`): por defecto ahora muestra solo carpetas (sin renderizar ficheros), lo que mejora el rendimiento de la UI cuando hay muchas entradas. Si la carpeta actual contiene ficheros, aparece un botón "View files (N)" que al pulsarlo expande los ficheros en el mismo panel (sin nueva llamada a S3 — los datos ya estaban cargados). El estado `nav["show_files"]` se resetea a `False` cada vez que se navega a una carpeta nueva. No se modificó el backend ni la llamada a la API.

## [2026-05-18] task | bootstrap de la wiki LLM

Creado el scaffolding completo de `docs/wiki/` siguiendo el spec `docs/superpowers/specs/2026-05-18-llm-wiki-design.md`: estructura de carpetas, `CLAUDE_WIKI.md` con el protocolo (ingest/query/lint/cierre de tarea/seguridad), `index.md` y `log.md` vacíos, página de ejemplo [[wheel-local-bifrost-shared]] en `decisiones/`, `.gitignore` actualizado para excluir `raw/`, y puntero añadido al `CLAUDE.md` raíz. Memorias de Claude actualizadas (`project-llm-wiki`, `feedback-end-of-task-logging`).

## [2026-05-20] task | Tag Manager en bifrost-transfer

Implementada la pantalla "Tag Manager" en `bifrost-transfer`: navegación de buckets/carpetas/ficheros S3 vía boto3, visualización y edición de tags (replace completo), operación masiva sobre todos los objetos de un prefijo con `ThreadPoolExecutor`, log en pantalla y auto-guardado en `~/bifrost-logs/`. Acceso desde botón "🏷️ Tags" en la toolbar de la vista de copia. Sistema `TAG_PROFILES` centraliza los campos de metadatos para copia y tagging. Disponible en desktop y web (Open OnDemand).

## [2026-05-20] task | doble click y botón back en bifrost-transfer

Replicadas dos mejoras de UX de `bifrost-mount` en `bifrost-transfer` (`bifrost-transfer/src/main.py`): (1) doble click en las tarjetas de selección de servidor MinIO actúa como "Continue" — las tarjetas están ahora envueltas en `GestureDetector` con `on_tap` (selecciona) y `on_double_tap` (continúa directamente); (2) botón "← Back" en la vista principal de copia que vuelve a la selección de servidor — parámetro `on_back: Callable | None` añadido a `_build_copy_content`, botón creado condicional al parámetro, y `go_copy` pasa `on_back=go_minio`.

## [2026-05-19] task | auto-instalación de WinFsp en bifrost-mount

Añadido flujo de auto-instalación de WinFsp en Windows para `bifrost-mount`: cuando falta, la app pregunta y descarga la última release oficial desde la GitHub Releases API (`winfsp/winfsp`), lanza `msiexec /qb` (UAC) y reintenta el mount automáticamente. Backend: nueva excepción `WinFspMissingError` + funciones `_winfsp_latest_msi_url`, `_download_winfsp_msi`, `install_winfsp_windows` en `shared/bifrost_backend/backend.py`. UI: helper `_prompt_install_winfsp` en `bifrost-mount/src/main.py`. Mensajes del flujo en inglés. `bifrost-transfer` queda fuera porque su botón de mount está pendiente de eliminarse en otra tarea. Detalle y decisiones en [[winfsp-auto-install-windows]]. Spec: `docs/superpowers/specs/2026-05-19-winfsp-auto-install-design.md`; plan: `docs/superpowers/plans/2026-05-19-winfsp-auto-install.md`.
