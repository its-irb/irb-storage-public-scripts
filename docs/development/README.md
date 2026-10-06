# Documentación para desarrollo — BIFROST

Esta capa permite comprender, mantener y ampliar el proyecto sin leer toda la
documentación antigua de la raíz. Está organizada por áreas:

| Documento | Contenido |
|---|---|
| [architecture.md](architecture.md) | Qué problema resuelve BIFROST, por qué está estructurado así, límites entre componentes y consecuencias de modificarlos. |
| [backend.md](backend.md) | `shared/bifrost_backend/backend.py`: secciones, decisión de diseño de `ui_call`, acoplamiento backend→frontend, convenciones, autoupdate. |
| [frontend.md](frontend.md) | Apps Flet: inicialización, flujos de vistas, modo web (sesiones, reconexión, throttle de logs), `meta_fields.py`, el bug `IndexError` y su solución. |
| [build-and-ci.md](build-and-ci.md) | Entorno de desarrollo, empaquetado por plataforma e integración continua. |
| [operations.md](operations.md) | Variables de entorno, autoupdate, logs y política de validación (tests). |

## Audiencia y alcance

- Para modificar código con seguridad, esta capa es autosuficiente: no
  requiere consultar `docs/agent/`. Los ficheros `CLAUDE*.md` de la raíz ya
  solo redirigen a `AGENTS.md` y `docs/agent/`.
- La documentación de usuario está en [../user/README.md](../user/README.md).
- Toda afirmación técnica está verificada contra el estado actual del
  repositorio; las que no pudieron verificarse están marcadas como pendientes.
