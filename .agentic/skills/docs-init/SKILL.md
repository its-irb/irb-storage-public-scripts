---
name: docs-init
description: Inicializa la estructura documental básica del repositorio y crea README mínimos para agentes, desarrolladores y usuarios. Ejecuta docs-init-full únicamente cuando el usuario solicita explícitamente una documentación inicial exhaustiva.
---

# docs-init

Inicializa la estructura documental mínima necesaria para construir la
documentación del repositorio progresivamente.

Primero lee:

```text
docs/documentation-methodology.md
```

No realices una revisión exhaustiva del código ni intentes documentar todo el
repositorio.

## Inicialización básica

Comprueba y crea, cuando falten, estas ubicaciones:

```text
docs/agent/
docs/development/
docs/user/
```

Cada capa debe contener un `README.md` mínimo que explique únicamente su
propósito:

- `docs/agent/README.md`: contexto operativo para agentes que trabajan sobre el
  repositorio;
- `docs/development/README.md`: documentación para comprender, mantener y
  ampliar el proyecto;
- `docs/user/README.md`: guías orientadas a los objetivos de las personas que
  utilizan el producto.

Los README deben indicar que la documentación se incorporará progresivamente.

No incluyas inventarios de componentes, funciones, scripts o funcionalidades.
No hagas afirmaciones sobre el producto que no hayan sido verificadas.

## README raíz

Si no existe `README.md`, crea uno mínimo con:

- el nombre del repositorio como título;
- enlaces a las tres capas documentales;
- ninguna afirmación funcional no verificada.

Si `README.md` ya existe:

- consérvalo;
- no lo sobrescribas;
- indica si sería conveniente añadir enlaces a las capas documentales;
- solicita confirmación antes de modificarlo.

## Documentación existente

Conserva toda la documentación existente.

No muevas, renombres, dividas, reescribas ni elimines documentación existente
durante esta inicialización básica.

La invocación de `docs-init` autoriza crear los directorios y README mínimos que
falten, pero no modificar contenido documental existente.

## Generación exhaustiva opcional

Si el usuario solicita explícitamente durante la invocación una documentación
inicial completa, integral o exhaustiva:

1. completa primero la inicialización básica;
2. lee y ejecuta:

```text
.agentic/skills/docs-init-full/SKILL.md
```

La mera invocación de `docs-init` no autoriza ejecutar `docs-init-full`.

## Baseline documental

Si solo se realiza la inicialización básica, actualiza `.agentic.lock.json`
preservando todas las claves existentes:

- `documentation.last_reviewed_commit` = commit actual de `HEAD`;
- `documentation.last_reviewed_at` = fecha y hora actual real en formato
  ISO 8601;
- si no puedes obtener la fecha y hora real, usa `null` y avisa.

Este baseline marca el inicio del seguimiento incremental. No significa que el
código anterior esté completamente documentado.

Si se ejecuta `docs-init-full`, deja que esa skill actualice el baseline al
terminar.

## Reglas

- No modifiques código.
- No generes documentación exhaustiva salvo petición explícita.
- No inventes información sobre el producto.
- No sobrescribas documentación existente.
- Mantén los README iniciales breves.
- Preserva las claves ajenas de `.agentic.lock.json`.

## Resultado

Explica brevemente:

- qué directorios se crearon;
- qué README se crearon;
- qué contenido existente se conservó;
- si el README raíz necesita cambios;
- si se ejecutó `docs-init-full`;
- cómo quedó establecido el baseline.
