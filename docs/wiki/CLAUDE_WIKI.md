# CLAUDE_WIKI.md — Protocolo de la wiki BIFROST

Este documento le dice a Claude **cómo operar** la base de conocimiento incremental en `docs/wiki/`. Léelo entero antes de crear, modificar o consultar páginas de la wiki.

> El "qué es la wiki" y "por qué existe" está en `docs/superpowers/specs/2026-05-18-llm-wiki-design.md`. Aquí solo está el cómo.

---

## Estructura

```
docs/wiki/
  CLAUDE_WIKI.md        # este fichero
  index.md              # catálogo de páginas
  log.md                # registro cronológico append-only
  raw/                  # fuentes brutas — gitignored
    conversaciones/
    docs-externos/
  decisiones/           # ADRs ligeros: por qué se hizo X
  infra/                # MinIO, Nexica, LDAP, STS, red, contactos IT
  gotchas/              # incidencias resueltas y workarounds
  conceptos/            # entidades transversales (rclone, FUSE-T, flet build…)
```

`raw/` está en `.gitignore` (puede contener datos sensibles o ficheros grandes). El resto se commitea.

---

## Workflows

### Ingest (la usuaria añade una fuente)

Disparador: la usuaria pega un fichero en `raw/<conversaciones|docs-externos>/<slug>.md` o me dice "ingesta esto".

Pasos:

1. Leer la fuente entera.
2. Resumir en chat los takeaways principales y proponer en qué categoría/categorías encaja (`decisiones/`, `infra/`, `gotchas/`, `conceptos/`).
3. Esperar OK de la usuaria si la categoría es ambigua.
4. Crear o actualizar la(s) página(s) en la categoría correspondiente. Si actualizo una existente, fusionar en lugar de duplicar y marcar el `actualizado:` en frontmatter.
5. Atravesar páginas relacionadas vía `[[wikilinks]]` y actualizar referencias cruzadas donde haga falta.
6. Añadir/actualizar entrada en `index.md`.
7. Añadir entrada en `log.md`: `## [YYYY-MM-DD] ingest | <título corto>`.
8. Anonimizar credenciales, IPs internas no públicas y nombres concretos de personas en las páginas commiteadas (ver "Reglas de seguridad" abajo).

### Query (la usuaria pregunta)

1. Leer `index.md` primero para localizar páginas relevantes.
2. Leer las páginas señaladas (no toda la wiki).
3. Si la pregunta abarca varias páginas, sintetizar con citas tipo `[[nombre-de-página]]`.
4. Si la síntesis es nueva y útil (no se deduce de páginas existentes), **ofrecer archivarla** como página propia ("¿quieres que guarde esto en `conceptos/` como página nueva?"). No archivar sin permiso explícito.
5. Si encuentro una contradicción entre lo que veo en código y lo que dice la wiki, **el código manda** — flag la página obsoleta y proponer actualizarla.

### Lint (a petición)

Disparador: la usuaria dice "lint la wiki" o equivalente. **No automático.**

Chequear:
- Páginas huérfanas (sin enlaces entrantes desde otras páginas o desde `index.md`).
- Enlaces `[[wikilink]]` rotos.
- Conceptos mencionados ≥3 veces sin página propia.
- Contradicciones entre páginas.
- Páginas con `actualizado:` > 6 meses que mencionan partes del código que ya no existen.
- Entradas en `index.md` que apuntan a ficheros borrados.

Reportar como lista, no aplicar cambios sin OK.

### Cierre de tarea (al terminar cualquier tarea no trivial del proyecto)

Antes del mensaje final al usuario en cualquier sesión que cierre una tarea (commit hecho, PR creada, fix verificado):

1. Añadir entrada a `log.md` con prefijo `## [YYYY-MM-DD] task | <título corto>` y un párrafo breve sobre qué se hizo y qué se aprendió.
2. Si lo aprendido es duradero (decisión arquitectónica, gotcha de infra, workaround, concepto nuevo), crear/actualizar la página correspondiente y enlazarla desde `index.md`.
3. No saturar el log con cambios triviales (typos, renombres locales, comentarios).

Esto está respaldado por la memoria `feedback-end-of-task-logging` — no lo olvides aunque la conversación esté siendo larga.

---

## Formato de página

Cada página markdown en `decisiones/`, `infra/`, `gotchas/`, `conceptos/` sigue este formato:

```markdown
---
type: decision | infra | gotcha | concepto
tags: [tag1, tag2]
fuentes: [raw/conversaciones/2026-05-18-session.md, raw/docs-externos/rclone-s3.md]
actualizado: 2026-05-18
---

# Título de la página

## Resumen
Una o dos frases con el qué y el por qué.

## Detalle
Cuerpo libre. Usa `[[wikilinks]]` a otras páginas (sin extensión .md).

## Fuentes
- `raw/conversaciones/2026-05-18-session.md` — qué aportó
- enlaces externos si aplica
```

Reglas:
- **Idioma: español.** Coherente con el resto del proyecto.
- Wikilinks `[[nombre-de-pagina-sin-extension]]` — compatibles con Obsidian si la usuaria lo abre así.
- Frontmatter YAML mínimo, no inventar campos.
- Sin emojis salvo que la usuaria los pida.

---

## Reglas de seguridad

**Nunca commitear en `docs/wiki/` (fuera de `raw/`):**
- Credenciales de cualquier tipo (access keys, secrets, contraseñas, tokens STS, contraseñas LDAP).
- IPs internas que no aparezcan ya en el repo público.
- Nombres y emails concretos de personas (usar roles: "el equipo IT de Nexica", "el PI del lab X").
- Nombres de buckets de usuarios.
- Rutas SMB que revelen estructura interna sensible.

Si una fuente en `raw/` contiene esto:
- La fuente puede quedarse en `raw/` (está gitignored).
- La página sintetizada debe anonimizar y, si hace falta, decir "ver fuente en `raw/...`" en lugar de incluir el dato.

Si tengo dudas, **preguntar antes de commitear**.

---

## Convenciones del log

`log.md` es append-only con prefijo consistente para parsear con grep:

```
## [2026-05-18] task | bootstrap de la wiki LLM
Detalle breve...

## [2026-05-18] ingest | conversación sobre el wheel local
Detalle breve...
```

Tipos válidos: `task`, `ingest`, `query` (solo si la query produjo página archivada), `lint`.

Para ver lo último: `grep "^## \[" docs/wiki/log.md | tail -5` (en PowerShell: `Select-String "^## \[" docs/wiki/log.md | Select-Object -Last 5`).

---

## Convenciones del índice

`index.md` agrupa por categoría con una línea por página:

```markdown
## Decisiones
- [Wheel local bifrost-shared](decisiones/wheel-local-bifrost-shared.md) — por qué __BUILDPATH__ en lugar de PyPI

## Infra
- (vacío de momento)
```

Mantener ordenado alfabéticamente dentro de cada categoría. Borrar entradas si se borra la página.

---

## Qué NO va en la wiki

- Cómo lanzar/ejecutar las apps → eso está en `README.md` y `CLAUDE.md`.
- Estructura del repo y convenciones de código → `CLAUDE.md`, `CLAUDE_BACKEND.md`, `CLAUDE_FRONTEND.md`.
- TODOs efímeros y planning de tareas → `docs/superpowers/specs/` o issues.
- Secretos de cualquier tipo → en ningún sitio del repo.

La wiki es el **"por qué" duradero**: decisiones que cuesta deducir del código, estado de infra externa al repo, incidencias resueltas que pueden volver.
