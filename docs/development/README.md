# Documentación para desarrolladores — BIFROST

Capa técnica completa para comprender, mantener y ampliar el proyecto. Autosuficiente sin necesidad de consultar `docs/agent/` ni `docs/user/`.

| Documento | Ámbito |
|---|---|
| `architecture.md` | Arquitectura, dependencias, entry points, acoplamiento, flujos |
| `setup.md` | Preparación del entorno de desarrollo (comandos verificados) |
| `build-release.md` | Build/packaging por plataforma, CI, versioning, firma |
| `web-mode.md` | Modo web OOD: sesión, dispatcher, reconexión, autosave |
| `thread-safety.md` | Bug `IndexError`, regla `ui_call`, `safe_thread`, `Timer` |
| `meta-fields.md` | Diseño de perfiles, `LAB_ACRONYMS`, lab filter, `detect_profile` |
| `operations.md` | Logs, autoupdate, STS, env vars, WinFsp/fuse-t, depuración |

Para contexto compacto orientado a edición puntual, `docs/agent/` ofrece módulos cargables bajo demanda. Para superficie de uso, `docs/user/`.
