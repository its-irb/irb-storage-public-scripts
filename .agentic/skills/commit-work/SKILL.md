---
name: commit-work
description: Revisa cambios, actualiza y valida las capas documentales si procede, y prepara un commit descriptivo.
---

# commit-work

Prepara un commit de trabajo con una descripción clara y completa.

## Proceso obligatorio

1. Revisa el estado del repositorio:

   - `git status --short`
   - `git diff --stat`
   - `git diff`

2. Ejecuta siempre la lógica de `.agentic/skills/docs-update/SKILL.md` antes de preparar el commit.

3. Si `docs-update` indica que no existe un baseline documental o que el repositorio todavía no dispone de documentación inicial conforme a la metodología, ejecuta o propone el flujo de `.agentic/skills/docs-init/SKILL.md` antes de continuar.

4. Si `docs-update` o `docs-init` modifican documentación o estado documental, vuelve a revisar:

   - `git status --short`
   - `git diff --stat`
   - `git diff`

5. Comprueba que el resultado de la revisión documental incluye:

   - impacto en documentación para agentes;
   - impacto en documentación para desarrolladores;
   - impacto en documentación para usuarios;
   - validación del `README.md`;
   - validación de `AGENTS.md`, si existe;
   - comprobación de coherencia entre las capas afectadas;
   - comprobación de autosuficiencia de las capas afectadas;
   - pendientes de validación, si existen.

6. Propón el conjunto final de ficheros a incluir en el commit.

7. Propón un mensaje de commit con:

   - título corto;
   - cuerpo largo explicando qué cambió;
   - motivo del cambio;
   - impacto funcional;
   - impacto documental;
   - notas de validación realizadas.

8. Antes de ejecutar `git add` o `git commit`, pide confirmación explícita al usuario.

9. Si el usuario confirma:

   - ejecuta `git add` sobre los ficheros aprobados;
   - ejecuta `git commit` con el mensaje propuesto.

10. No hagas `git push` salvo que el usuario lo pida explícitamente.

11. Si el usuario pide push:

   - muestra primero la rama actual;
   - muestra el remote y el upstream configurados;
   - ejecuta `git push` solo tras confirmación explícita.

## Reglas

- No inventes cambios.
- No incluyas ficheros no revisados.
- No hagas commit si hay conflictos, secretos, binarios inesperados o cambios dudosos.
- No hagas commit si la documentación requerida no está actualizada, contiene contradicciones conocidas o alguna capa afectada ha quedado insuficiente.
- No modifiques documentación solo para producir cambios artificiales.
- Si el estado del repositorio no está claro, detente y pregunta.