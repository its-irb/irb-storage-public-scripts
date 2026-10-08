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

2. Determina el tipo de repositorio:

   - Si existe `.agentic-framework.json` en la raíz, considera que se está trabajando en el repositorio fuente del Agentic Framework.
   - Si no existe, considera que se está trabajando en un repositorio destino sincronizado mediante el framework.

3. Ejecuta siempre la lógica de `.agentic/skills/docs-update/SKILL.md` antes de preparar el commit, comunicándole explícitamente el tipo de repositorio detectado.

4. En el repositorio fuente del Agentic Framework:

   - La baseline documental debe representar el `HEAD` existente antes de crear el nuevo commit.
   - Es normal que, después del commit, `documentation.last_reviewed_commit` apunte al padre del nuevo `HEAD`.
   - No intentes hacer que la baseline apunte al commit que se está creando.
   - No propongas ciclos de `commit` y `amend` para actualizar la baseline.
   - No muestres opciones A/B/C para resolver esta diferencia esperada.
   - No modifiques ni valides como parte del flujo de commit los campos:
     - `framework_remote_url`;
     - `framework_branch`;
     - `framework_commit`.
   - Estos campos son responsabilidad exclusiva de `agentic-sync.py --apply`.

5. En un repositorio destino, aplica normalmente las reglas de baseline y trazabilidad definidas por `docs-update`.

6. Si `docs-update` indica que no existe un baseline documental o que el repositorio todavía no dispone de documentación inicial conforme a la metodología, ejecuta o propone el flujo de `.agentic/skills/docs-init/SKILL.md` antes de continuar.

7. Si `docs-update` o `docs-init` modifican documentación o estado documental, vuelve a revisar:

   - `git status --short`
   - `git diff --stat`
   - `git diff`

8. Comprueba que el resultado de la revisión documental incluye:

   - impacto en documentación para agentes;
   - impacto en documentación para desarrolladores;
   - impacto en documentación para usuarios;
   - validación del `README.md`;
   - validación de `AGENTS.md`, si existe;
   - comprobación de coherencia entre las capas afectadas;
   - comprobación de autosuficiencia de las capas afectadas;
    - pendientes de validación, si existen.

9. Comprueba que los cambios pendientes no contienen información sensible
   (ver Reglas). Si la contienen, detente y avisa al usuario antes de
   continuar con la propuesta de commit.

10. Valida los cambios ejecutando tests, aplicando la política de validación
    de tests (ver Reglas):

    - Si el repositorio define una política de tests (p. ej. en `AGENTS.md`,
      documentación de desarrollo o configuración del proyecto), aplícala tal
      cual.
    - Si el repositorio no define política, aplica esta regla por defecto:
      - ejecuta solo los tests directamente relacionados con los ficheros
        cambiados (suite focalizada del módulo o área afectada);
      - si el cambio es pequeño y localizado (1-2 ficheros de un único módulo,
        sin cambios de contrato público), esa suite focalizada es la única
        suite que debe ejecutarse en este flujo;
      - ejecuta la suite completa únicamente si el cambio toca código
        transversal (bibliotecas compartidas, contratos públicos,
        infraestructura común) o varios subsistemas, o si el usuario lo pide
        expresamente.
    - No ejecutes la suite completa "por si acaso".
    - No relances ninguna suite ya ejecutada en este flujo (ver Reglas).

11. Propón el conjunto final de ficheros a incluir en el commit.

12. Propón un mensaje de commit con:

    - título corto;
    - cuerpo largo explicando qué cambió;
    - motivo del cambio;
    - impacto funcional;
    - impacto documental;
    - notas de validación realizadas, incluyendo qué suites de tests se
      ejecutaron y su resultado y, en el caso de suite completa, la duración
      total y los tests más lentos.

13. Antes de ejecutar `git add` o `git commit`, pide confirmación explícita al usuario.

14. Si el usuario confirma:

    - ejecuta `git add` sobre los ficheros aprobados;
    - ejecuta `git commit` con el mensaje propuesto.

15. No hagas `git push` salvo que el usuario lo pida explícitamente.

16. Si el usuario pide push:

   - muestra primero la rama actual;
   - muestra el remote y el upstream configurados;
   - ejecuta `git push` solo tras confirmación explícita.

## Reglas

- No inventes cambios.
- No incluyas ficheros no revisados.
- No hagas commit si hay conflictos, binarios inesperados o cambios dudosos.
- No hagas commit si los cambios pendientes contienen información sensible
  (claves, tokens, contraseñas, claves privadas, material criptográfico
  sensible, URLs o connection strings con credenciales embebidas;
  definición completa en «Información sensible y secretos» de
  `docs/documentation-methodology.md`). Antes de proponer el commit,
  comprueba el diff pendiente. Si detectas información sensible, detente,
  avisa al usuario indicando fichero y ubicación sin mostrar el valor
  completo, y no propongas el commit.
- Si no puedes determinar con suficiente seguridad si un valor es
  sensible, no decidas por tu cuenta: trátalo provisionalmente como
  potencialmente sensible, avisa al usuario (fichero y ubicación, sin
  mostrar el valor completo) y pregúntale explícitamente antes de proponer
  el commit; si el usuario confirma que no es un secreto, regístralo en
  `AGENTS.md` como falso positivo conocido del caso concreto (fichero,
  campo, variable o contexto), sin el valor completo si pudiera ser
  sensible, para no volver a preguntar.
- No hagas commit si la documentación requerida no está actualizada, contiene contradicciones conocidas o alguna capa afectada ha quedado insuficiente.
- No modifiques documentación solo para producir cambios artificiales.
- Si el estado del repositorio no está claro, detente y pregunta.
- La presencia de `.agentic-framework.json` en la raíz es el criterio autoritativo para identificar el repositorio fuente.
- En el repositorio fuente, no trates como error que la baseline documental quede un commit por detrás después de crear el commit.
- Política de validación de tests: no ejecutes la suite completa por
  defecto. Si el repositorio define una política de tests, aplícala tal cual;
  si no, ejecuta solo los tests directamente relacionados con los ficheros
  cambiados. La suite completa exige justificación: cambio de código
  transversal (bibliotecas compartidas, contratos públicos, infraestructura
  común), cambio en varios subsistemas o petición expresa del usuario.
- Nunca relances la misma suite dos veces en el mismo flujo de commit. Si una
  ejecución produce fallos, analízalos y repórtalos con la información ya
  disponible, distinguiendo fallos preexistentes de los causados por el
  cambio; no re-ejecutes la suite para identificar o reconfirmar un fallo ya
  conocido o ya reportado.
- Si la suite completa está justificada, ejecútala una única vez y reporta en
  las notas de validación su duración total y los tests más lentos. No hay
  re-ejecuciones.
- El tiempo del flujo de commit no puede bloquearse por tests lentos ajenos al
  cambio. Si la suite completa justificada supera un tiempo razonable, no la
  relances: repórtalo e incluye la recomendación de «Recomendación para
  repositorios destino» cuando aplique.

## Recomendación para repositorios destino

En un repositorio destino (sin `.agentic-framework.json`), si durante la
validación observas que los tests pagan esperas reales (sleeps, bucles de
polling con retardos, I/O real no mockeada) o que la suite completa supera un
presupuesto razonable de tiempo, incluye en el resultado del flujo una
recomendación de mejora para el repositorio:

- Los tests deben mockear sleeps e I/O reales: nunca deben pagar esperas
  reales por polling.
- La suite completa debe tener un presupuesto de tiempo (objetivo: menos de
  60 s).

Si el repositorio no documenta su política de tests (p. ej. en `AGENTS.md`),
puede incluirse en la propuesta de `docs-update` la documentación de la
política de tests y de esta recomendación.