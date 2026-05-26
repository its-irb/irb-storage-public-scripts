---
type: gotcha
tags: [windows, winfsp, mount, instalacion]
fuentes: [docs/superpowers/specs/2026-05-19-winfsp-auto-install-design.md, docs/superpowers/plans/2026-05-19-winfsp-auto-install.md]
actualizado: 2026-05-19
---

# Auto-instalación de WinFsp en Windows (bifrost-mount)

## Resumen

En Windows, `bifrost-mount` necesita WinFsp instalado a nivel de sistema (incluye un driver de kernel, no se puede empaquetar como binario portable). Si falta al intentar montar, la app detecta la ausencia y ofrece descargar e instalar la última release oficial desde GitHub Releases (`winfsp/winfsp`) automáticamente — con UAC.

## Detalle

### Por qué no es un binario portable

WinFsp distribuye un driver de kernel (`winfsp-x64.sys`) que tiene que estar firmado, registrado con el SCM de Windows y cargado por el sistema. Eso obliga a instalación vía MSI con elevación. No es como `rclone`, que sí se empaqueta dentro de la app.

### Flujo implementado

1. Al hacer click en **Mount**, `mount_rclone_S3_prefix_to_folder` levanta `WinFspMissingError` (subclase de `EnvironmentError`, definida en `shared/bifrost_backend/backend.py`).
2. La UI (`bifrost-mount/src/main.py`, helper `_prompt_install_winfsp`) muestra el diálogo "WinFsp is not installed" con botones **Install / Cancel**.
3. Si **Install**: `backend.install_winfsp_windows()` consulta `api.github.com/repos/winfsp/winfsp/releases/latest`, descarga el primer asset `.msi` a `%TEMP%\winfsp-<tag>.msi`, y lanza `msiexec /i <msi> /qb /norestart`. El UAC del sistema aparece automáticamente.
4. Tras instalación correcta (exit code 0 ó 3010), el mount se reintenta automáticamente.
5. Si el usuario cancela el UAC (exit code 1602), no se considera error: aparece un aviso informativo y el botón Mount queda re-habilitado.

### Decisiones clave

- **Fuente:** GitHub Releases API (no scraping de `winfsp.dev`). Es la fuente oficial real y JSON estable.
- **Descarga bajo demanda**, no bundle del MSI dentro del instalador de la app. El usuario lo pidió explícitamente; el instalador queda más liviano y siempre se baja la última versión.
- **Solo `bifrost-mount`**. `bifrost-transfer` también llama a `mount_rclone_S3_prefix_to_folder` hoy, pero ese botón está pendiente de eliminarse en otra tarea, así que no se tocó.
- **Mensajes en inglés** en este flujo (título de diálogo, botones, progreso), por consistencia con el resto de la UI de `bifrost-mount` que también está en inglés. Esto es una excepción consciente al `CLAUDE.md §Convenciones #3`.
- **Sin caché entre ejecuciones**: si el usuario cancela el UAC, se redescarga la próxima vez (~2 MB, no merece la pena).

### Exit codes de msiexec manejados

| Código | Significado | Tratamiento |
|---|---|---|
| 0 | OK | éxito → reintenta mount |
| 3010 | OK pero requiere reinicio | éxito (raro con WinFsp) |
| 1602 | Usuario canceló | devuelve False, aviso informativo |
| otros | error real | `RuntimeError`, diálogo con link manual |

## Fuentes

- Spec: `docs/superpowers/specs/2026-05-19-winfsp-auto-install-design.md`
- Plan: `docs/superpowers/plans/2026-05-19-winfsp-auto-install.md`
- Código: `shared/bifrost_backend/backend.py` (clase `WinFspMissingError` y funciones `_winfsp_latest_msi_url`, `_download_winfsp_msi`, `install_winfsp_windows`) y `bifrost-mount/src/main.py` (`_prompt_install_winfsp` dentro del scope del mount).
