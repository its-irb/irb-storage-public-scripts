# Diseño: LLM Wiki para BIFROST

**Fecha:** 2026-05-18
**Autora:** ona-perez
**Estado:** aprobado, pendiente de plan de implementación

---

## Objetivo

Implementar una base de conocimiento incremental en `docs/wiki/` siguiendo el patrón "LLM Wiki": Claude mantiene páginas markdown estructuradas e interconectadas a partir de fuentes brutas y de conversaciones, para que el conocimiento sobre BIFROST se acumule entre sesiones en lugar de perderse.

## Alcance

Cubre tres tipos de conocimiento:

1. **Decisiones técnicas y arquitectura** — el "por qué" detrás de patrones del repo que no se deducen del código (wheel local `bifrost-shared`, sustitución `__BUILDPATH__`, dos apps con backend compartido, acoplamiento backend→frontend, etc.).
2. **Infraestructura MinIO / Nexica / IRB** — topología del cluster, endpoints, STS, LDAP, shares CIFS, VPN Forticlient, contactos IT.
3. **Incidencias y gotchas de usuarios** — bugs reportados, casos raros (Mac Intel vs ARM, FUSE-T, codificación de consola Windows, thread-safety Flet), workarounds aplicados.

**Fuera de alcance:** onboarding/runbooks (ya cubiertos por `README.md` y `CLAUDE.md`), tests, features nuevas en las apps.

## Estructura

```
docs/wiki/
  CLAUDE_WIKI.md        # schema: protocolo para Claude
  index.md              # catálogo de páginas
  log.md                # registro cronológico append-only
  raw/                  # FUENTES BRUTAS — .gitignored
    .gitkeep
    conversaciones/     # resúmenes de sesiones Claude relevantes
    docs-externos/      # snippets descargados (rclone, FUSE-T, Flet, MinIO…)
  decisiones/           # ADRs ligeros
  infra/                # cluster, S3, LDAP, STS, red
  gotchas/              # incidencias resueltas
  conceptos/            # entidades transversales (rclone, FUSE-T, flet build…)
```

Decisiones de visibilidad:
- `docs/wiki/raw/` → `.gitignore` (fuentes brutas pueden contener datos sensibles o ser voluminosas).
- Resto de `docs/wiki/` → commiteado (conocimiento compartido con el equipo).

## Componentes

### `CLAUDE_WIKI.md` (el schema)

Documento maestro que define cómo Claude opera la wiki. Contiene:

- **Workflow ingest**: usuaria pega fuente en `raw/<categoría>/<slug>.md` → Claude la lee, propone resumen, lo guarda en la categoría adecuada (`decisiones/`, `infra/`, `gotchas/`, `conceptos/`), actualiza páginas relacionadas vía `[[wikilinks]]`, añade fila a `index.md`, añade entrada a `log.md`.
- **Workflow query**: Claude lee `index.md` primero, luego entra en páginas relevantes, cita con wikilinks. Si la síntesis es valiosa, ofrece archivarla como nueva página.
- **Workflow lint** (a petición, no automático): detectar contradicciones, páginas huérfanas, conceptos mencionados sin página propia, enlaces rotos.
- **Formato de página**: frontmatter YAML (`type`, `tags`, `fuentes`, `actualizado`) + cuerpo en español + sección final "Fuentes" enlazando a `raw/`.
- **Reglas de seguridad**: nunca commitear credenciales, IPs internas no públicas, ni nombres concretos de usuarios. Las fuentes con datos sensibles se quedan en `raw/` (gitignored); las páginas sintetizadas anonimizan.
- **Convención de cierre de tarea**: al terminar cualquier tarea no trivial del proyecto, añadir entrada a `log.md` (`## [YYYY-MM-DD] task | <título>`) y, si lo aprendido es duradero, crear/actualizar página correspondiente.

### `index.md`

Catálogo en formato:
```markdown
## Decisiones
- [Wheel local bifrost-shared](decisiones/wheel-local-bifrost-shared.md) — por qué __BUILDPATH__ en lugar de PyPI

## Infra
- ...
```

### `log.md`

Append-only. Prefijo consistente `## [YYYY-MM-DD] <tipo> | <título>` (tipos: `task`, `ingest`, `query`, `lint`) para parsing con `grep`.

### `CLAUDE.md` raíz — sección añadida

Bloque corto al final apuntando a `docs/wiki/CLAUDE_WIKI.md`. No duplica protocolo; solo indica que existe y cuándo consultarlo.

## Bootstrap inicial

Una sola tarea de scaffolding:

1. Crear carpetas con `.gitkeep` donde haga falta.
2. Escribir `CLAUDE_WIKI.md` con el protocolo completo.
3. Crear `index.md` y `log.md` con cabeceras vacías.
4. Crear página de ejemplo: `decisiones/wheel-local-bifrost-shared.md` (por qué `bifrost-shared` se referencia como wheel local con `__BUILDPATH__` sustituido en build).
5. Añadir entradas a `index.md` y `log.md` para esa página.
6. Actualizar `.gitignore` con `docs/wiki/raw/` (con excepción para `.gitkeep`).
7. Añadir sección "Wiki del proyecto" a `CLAUDE.md` raíz.
8. Commit.

## No-objetivos / YAGNI

- **No** hooks de `settings.json` que automaticen escritura. La disciplina vive en `CLAUDE_WIKI.md` y en memoria de Claude (`feedback-end-of-task-logging`).
- **No** búsqueda con embeddings (`qmd` u otro) en esta primera versión — `index.md` basta hasta ~cientos de páginas.
- **No** integración con Obsidian-específica más allá de que el formato (wikilinks `[[ ]]`, frontmatter YAML) es compatible con Obsidian si la usuaria quiere abrirlo así.
- **No** tooling de Dataview, Marp ni similar — añadir solo si surge necesidad real.
- **No** ingest masivo inicial — la wiki crece orgánicamente.

## Riesgos

- **Filtraciones**: una fuente bruta con credenciales podría acabar en una página sintetizada si Claude no anonimiza bien. Mitigación: regla explícita en `CLAUDE_WIKI.md` + `raw/` gitignored como contención.
- **Wiki abandonada**: si nadie ejecuta lint ni mantiene índice, decae. Mitigación: convención de cierre de tarea documentada como memoria de feedback (`feedback-end-of-task-logging`).
- **Duplicación con CLAUDE.md/README**: si el mismo conocimiento aparece en CLAUDE.md y en la wiki, divergerán. Mitigación: CLAUDE.md sigue siendo el "qué es el proyecto y cómo se ejecuta"; la wiki es el "por qué de decisiones + estado de infra + gotchas". Sin solape funcional.

## Criterios de aceptación

- Estructura de carpetas creada.
- `CLAUDE_WIKI.md` legible y completo (protocolo de ingest/query/lint, formato, seguridad, cierre de tarea).
- `index.md` y `log.md` con al menos la entrada de ejemplo.
- Página `decisiones/wheel-local-bifrost-shared.md` redactada y enlazada.
- `.gitignore` actualizado.
- `CLAUDE.md` raíz con sección de puntero a la wiki.
- Commit limpio en `feature/backend-rclone` (o rama nueva si se prefiere).
