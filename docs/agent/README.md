# Documentación para agentes — BIFROST

BIFROST es un conjunto de dos aplicaciones de escritorio (Flet/Python) para el
servidor MinIO S3 del IRB Barcelona: **bifrost-transfer** (copiar datos a
buckets con verificación y etiquetado; incluye Tag Manager y modo web) y
**bifrost-mount** (montar buckets como unidad local). Ambas comparten el
paquete `bifrost-shared` (`shared/`).

Lee solo el módulo necesario para la tarea. Índice:

| Módulo | Cuándo consultarlo |
|---|---|
| [architecture.md](architecture.md) | Cualquier tarea: qué es cada componente, estructura del repo, acoplamiento e invariantes. |
| [backend.md](backend.md) | Cambios en `shared/bifrost_backend/` (rclone, STS, LDAP, SMB, S3, tagging, autoupdate). |
| [frontend.md](frontend.md) | Cambios en `bifrost-*/src/` (vistas Flet, modo web, `meta_fields.py`, convenciones UI). |
| [operations.md](operations.md) | Ejecutar, empaquetar, CI, releases, variables de entorno. |
| [conventions-gotchas.md](conventions-gotchas.md) | Antes de modificar código: reglas críticas y errores conocidos. |

## Notas de contexto

- Comentarios, docstrings y mensajes de UI están en **español**.
- **No hay suite de tests automatizada**: la validación es manual con `flet run`.
- `docs/agent/` debe bastar para el trabajo habitual; consulta
  `docs/development/` solo para profundizar en un área al actualizar esa capa.
- Existe documentación heredada en la raíz (`CLAUDE.md`, `CLAUDE_BACKEND.md`,
  `CLAUDE_FRONTEND.md`, `README.md`) pendiente de retirar. Si contradice esta
  capa, prevalece el estado real del repositorio; avisa si detectas la
  contradicción. No la uses como fuente para nuevos cambios documentales.

## Convenciones de estilo documental

- Los comandos que se presentan como **instrucción** van siempre en bloques
  de código (bloque `bash` para bash, bloque `powershell` para comandos de
  Windows); solo se usa formato inline para referencias nominales en el texto
  (nombres de herramientas, scripts, ficheros o flags mencionados en prosa).
