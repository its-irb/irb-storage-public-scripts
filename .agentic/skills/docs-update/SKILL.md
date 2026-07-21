---
name: docs-update
description: Revisa los cambios desde el último commit documentado, propone las actualizaciones necesarias en las capas documentales y solo las aplica después de recibir confirmación humana explícita.
---

# docs-update

Revisa si los cambios del repositorio desde el último commit documentado requieren actualizar documentación.

Primero lee:

```text
docs/documentation-methodology.md
```

Después lee:

```text
.agentic.lock.json
```

## Flujo obligatorio en dos fases

`docs-update` se ejecuta siempre en dos fases separadas.

### Fase 1: análisis y propuesta

En la primera ejecución:

- inspecciona el repositorio y la documentación;
- identifica los cambios necesarios;
- prepara una propuesta concreta;
- no modifiques ningún fichero;
- no actualices `.agentic.lock.json`;
- detente y solicita confirmación humana explícita.

No utilices herramientas de escritura o edición durante esta fase.

La petición inicial de ejecutar `docs-update` no constituye autorización para
aplicar cambios, aunque el usuario emplee expresiones como «actualiza»,
«corrige», «arregla», «revisa y modifica» o equivalentes.

La confirmación solo es válida después de haber presentado la propuesta
concreta de cambios.

### Fase 2: aplicación confirmada

Solo después de recibir una respuesta humana posterior que apruebe la propuesta:

- aplica únicamente los cambios aprobados;
- no añadas cambios distintos de los presentados;
- incorpora la información nueva que el usuario haya proporcionado explícitamente;
- valida el resultado;
- actualiza el baseline documental al finalizar correctamente.

Si el usuario aprueba solo una parte de la propuesta, aplica únicamente esa
parte y deja el resto pendiente.

## Baseline documental

Si no existe `.agentic.lock.json`, o no contiene `documentation.last_reviewed_commit`:

- no ejecutes una actualización incremental sin baseline;
- indica que el repositorio necesita una revisión documental integral;
- ejecuta o recomienda ejecutar la lógica de `.agentic/skills/docs-init/SKILL.md`.

Si existe `documentation.last_reviewed_commit`, continúa con el proceso obligatorio.

## Proceso obligatorio

1. Valida siempre el `README.md` raíz, aunque el rango de commits no parezca afectarlo.

   La validación del README no depende del diff y debe ejecutarse en cada invocación.

2. Obtén el commit base desde `documentation.last_reviewed_commit`.

3. Revisa los cambios desde ese commit hasta `HEAD`:

   - `git log --oneline <base>..HEAD`
   - `git diff --name-status <base>..HEAD`
   - `git diff <base>..HEAD`

4. Deriva automáticamente qué conocimiento y áreas del sistema han cambiado a partir del diff y del árbol actual del repositorio.

   No uses una lista fija de rutas a revisar.

   Ten en cuenta especialmente:

   - ficheros añadidos;
   - ficheros borrados;
   - ficheros movidos;
   - ficheros modificados;
   - nuevas convenciones de directorios;
   - cambios en scripts ejecutables;
   - cambios en manifiestos o configuración;
   - cambios en skills o wrappers;
   - cambios en documentación existente;
   - cambios de comportamiento, capacidades o limitaciones visibles.

5. Para cada conocimiento afectado, evalúa su impacto en:

   - documentación para agentes;
   - documentación para desarrolladores;
   - documentación para usuarios;
   - `README.md`;
   - `AGENTS.md`, si existe.

   No asumas que un cambio pertenece a una sola capa porque se originó en código interno o en una interfaz pública.

   Proyecta el conocimiento actualizado sobre todas las capas donde resulte relevante.
   Para las áreas afectadas, evalúa también el impacto sobre su intención y su
   utilidad:

   - en la capa de desarrollo, comprueba si el cambio altera o aclara el propósito,
   las razones de diseño, las responsabilidades, los límites, las restricciones,
   los invariantes o las consecuencias de modificar esa área;
   - en la capa de usuario, comprueba si el cambio altera los objetivos que pueden
   alcanzarse, cuándo debe utilizarse cada flujo, los requisitos previos, la
   elección entre alternativas, el resultado esperado, las limitaciones o la
   recuperación ante errores.

   No consideres suficiente actualizar únicamente listas de componentes, comandos,
   funciones, opciones o pasos.

6. Revisa la documentación existente y busca afirmaciones relacionadas con las áreas cambiadas.

7. Valida esas afirmaciones contra el estado actual del repositorio:

   - las rutas mencionadas existen o reflejan correctamente los movimientos;
   - las listas de componentes coinciden con el árbol real;
   - los comandos documentados coinciden con los scripts reales;
   - los formatos descritos coinciden con los ficheros reales;
   - los elementos movidos, renombrados o eliminados no siguen documentados como activos;
   - las nuevas piezas relevantes están documentadas si afectan al uso o mantenimiento;
   - el comportamiento visible para usuarios coincide con la implementación actual.

8. Prepara una propuesta de actualización documental.

   Para cada cambio propuesto, indica:

   - el documento afectado;
   - la afirmación o sección actual, cuando exista;
   - el cambio propuesto;
   - la evidencia que lo justifica;
   - las demás capas donde debe propagarse el mismo conocimiento.
   - qué intención, decisión o restricción de diseño debe explicarse o actualizarse
   para desarrolladores;
   - qué objetivo del usuario resulta afectado y cómo debe explicarse el flujo
   desde esa perspectiva;
   - qué razones o contexto no pueden verificarse y requieren información humana.

   No modifiques ningún fichero en esta fase.

   Después de presentar la propuesta completa, detente y solicita confirmación humana explícita.

9. Si la invocación señala un ámbito concreto —por ejemplo, un fichero,
   clase, función, script, comando, módulo, funcionalidad, flujo o afirmación—,
   trátalo como alcance explícito de la revisión.

   Limita el análisis y la propuesta a ese ámbito y al contexto estrictamente
   necesario para comprenderlo y documentarlo correctamente.

   Evalúa su impacto en las capas pertinentes. Revisa otras áreas únicamente
   cuando sea necesario para evitar contradicciones directas o mantener la
   coherencia del conocimiento documentado sobre ese ámbito.

   No revises, completes ni propongas mejoras en áreas no relacionadas.

   Mantén el flujo obligatorio de propuesta y confirmación humana antes de
   modificar cualquier fichero.

## Autosuficiencia de las capas

Comprueba que, después de la actualización:

- la documentación para agentes sigue siendo suficiente para el trabajo habitual sin depender de `docs/development/`;
- la documentación para desarrolladores permite comprender cómo funciona el
  área afectada, para qué existe, cómo encaja en el sistema y qué decisiones,
  restricciones o invariantes deben preservarse, sin depender de
  `docs/agent/`;
- la documentación para usuarios permite partir de un objetivo real, elegir el
  flujo adecuado, completar la tarea, reconocer el resultado esperado y actuar
  ante errores, sin consultar documentación técnica.

La redundancia entre capas está permitida cuando sea necesaria para preservar esa autosuficiencia.

No sustituyas información necesaria por enlaces a otra capa.

Si un cambio deja una capa incompleta aunque otra contenga la información correcta, incluye también esa capa en la propuesta de actualización.

## Auditoría basada en evidencias

Antes de dar la documentación por válida, realiza una auditoría contra el estado actual del repositorio.

Para cada documento afectado por el rango revisado:

1. Extrae las afirmaciones técnicas o funcionales relevantes.

   Por ejemplo:

   - listas de skills, comandos, hooks o componentes;
   - rutas de ficheros o directorios;
   - formatos de lockfiles, manifests o configuración;
   - comandos de uso;
   - flujos de instalación, sincronización o actualización;
   - comportamiento de scripts, herramientas o funcionalidades;
   - capacidades y limitaciones visibles para usuarios.

2. Para cada afirmación, identifica su fuente de verdad.

   Por ejemplo:

   - árbol actual de directorios;
   - contenido real de ficheros;
   - scripts ejecutables;
   - manifests;
   - lockfiles;
   - configuración;
   - interfaces públicas;
   - salida de comandos de inspección.

3. Comprueba la fuente de verdad antes de aceptar la afirmación.

4. Si una afirmación existente no puede verificarse con las evidencias disponibles en el repositorio:

   - no concluyas que es incorrecta;
   - no la modifiques, elimines, matices ni marques como pendiente dentro del
     documento;
   - indícala en el resultado como información no verificable desde el
     repositorio;
   - si consideras necesario cambiarla, solicita antes confirmación humana.

La ausencia de evidencia en el repositorio no es evidencia de que una afirmación sea falsa.

5. No concluyas que un documento está actualizado solo porque parece coherente.

   Debes poder explicar qué evidencia confirma las afirmaciones relevantes.

La documentación debe describir el estado actual del proyecto, no limitarse a cubrir el diff revisado.

## Validación de intención y utilidad

Para cada área afectada, no des la documentación por suficiente solo porque las
afirmaciones sean correctas.

Comprueba que:

### Desarrollo

- explica el propósito del área y no solo sus componentes;
- relaciona la implementación con los flujos completos;
- documenta decisiones, restricciones, invariantes y consecuencias relevantes;
- distingue las razones verificadas de las que requieren confirmación humana.

### Usuarios

- presenta las funcionalidades dentro de los objetivos a los que sirven;
- explica cuándo elegir cada flujo;
- permite completar una tarea y reconocer su resultado;
- incluye las limitaciones y la recuperación relevantes;
- no utiliza como estructura principal una enumeración de pantallas, controles,
  opciones o comandos.

Si falta este contexto en un área afectada, incluye su incorporación en la
propuesta de actualización.

No inventes intención, motivaciones ni objetivos que no estén respaldados por
el repositorio o por información humana.

## Coherencia entre capas

Para los conceptos afectados por el cambio, busca referencias relacionadas en:

- `README.md`;
- `AGENTS.md`, si existe;
- `docs/agent/`;
- `docs/development/`;
- `docs/user/`;
- cualquier otra documentación existente que cumpla esas funciones.

Comprueba que:

- se usan nombres compatibles;
- se describe el mismo comportamiento;
- coinciden las capacidades y limitaciones;
- no hay rutas, comandos o instrucciones incompatibles;
- no se mantiene como actual algo eliminado o sustituido;
- el nivel de detalle, el enfoque y el lenguaje cambian según la audiencia, pero no los hechos;
- cada capa conserva toda la información necesaria para su propia audiencia.

## Confirmación obligatoria antes de cualquier modificación

Todo cambio en la documentación requiere confirmación humana previa.

Esto incluye:

- añadir información;
- eliminar información;
- corregir afirmaciones;
- modificar o matizar afirmaciones existentes;
- completar documentación insuficiente;
- propagar conocimiento entre capas;
- cambiar rutas, enlaces o comandos;
- corregir errores ortográficos o de formato;
- modificar `README.md`;
- modificar `AGENTS.md`;
- actualizar `.agentic.lock.json`.

No existen cambios documentales exentos de confirmación.

En la fase de análisis:

1. no modifiques ningún fichero;
2. presenta conjuntamente todos los cambios propuestos;
3. explica las evidencias principales;
4. señala las dudas o información no verificable;
5. solicita confirmación explícita;
6. detente y espera la respuesta del usuario.

La instrucción inicial del usuario no sustituye esta confirmación. La confirmación debe producirse después de que el usuario haya podido revisar la propuesta concreta.

Tras recibir confirmación:

1. aplica únicamente los cambios aprobados;
2. muestra el resultado o el diff;
3. valida la coherencia entre capas;
4. actualiza el baseline solo si no quedan decisiones pendientes.

## Validación obligatoria del README

El `README.md` raíz debe actuar como puerta de entrada útil y seguir las convenciones habituales para el tipo real de proyecto.

Deriva primero la superficie pública del repositorio.

Inspecciona, si existen:

- scripts ejecutables;
- comandos o herramientas CLI;
- skills, hooks, plugins, workflows o integraciones de agentes;
- manifests, lockfiles o ficheros de configuración relevantes;
- servicios, entrypoints, APIs o interfaces públicas;
- documentación existente;
- funcionalidades visibles para usuarios.

Comprueba que el README explica, cuando proceda:

1. qué es el proyecto;
2. qué problema resuelve;
3. para quién está pensado;
4. sus funcionalidades principales;
5. el flujo básico de uso;
6. el flujo básico de instalación, ejecución o sincronización;
7. los comandos, scripts, herramientas o puntos de entrada principales;
8. el estado o madurez del proyecto, si es relevante;
9. dónde encontrar la documentación detallada;
10. cómo contribuir, obtener soporte o consultar la licencia, cuando corresponda.

No marques un punto como no aplicable solo porque el README actual no lo mencione. Debes haber inspeccionado antes la superficie pública y comprobado que realmente no corresponde al proyecto.

Si existe una funcionalidad pública, comando, script, skill, servicio, API, workflow o mecanismo de instalación, el README debe mencionarlo de forma resumida cuando sea relevante para entender o empezar a usar el proyecto.

Si el README menciona algo que ya no existe, incluye su corrección en la propuesta.

Si es genérico, pobre, incompleto o no permite entender cómo empezar, incluye las mejoras necesarias en la propuesta aunque no contenga afirmaciones falsas.

No conviertas el README en la documentación completa: debe presentar el proyecto, ofrecer un inicio útil y enlazar los documentos detallados.

## Actualización del baseline

No modifiques `.agentic.lock.json` durante la fase de análisis y propuesta.

Después de que el usuario confirme los cambios, y únicamente cuando se hayan aplicado y validado correctamente, actualiza `.agentic.lock.json`:

- `documentation.last_reviewed_commit` = commit actual de `HEAD`;
- `documentation.last_reviewed_at` = fecha y hora actual real en formato ISO 8601;
- si no puedes obtener la fecha y hora real, usa `null` y avisa.

## Reglas

- No inventes información.
- No actualices documentación si no hace falta.
- No modifiques código.
- Mantén compacta y autosuficiente la documentación para agentes.
- En documentación para desarrolladores y usuarios, prioriza claridad, suficiencia y autosuficiencia sobre brevedad.
- No hardcodees una lista fija de documentos o rutas; deriva lo afectado desde el diff, el árbol actual y las referencias existentes.
- Si el diff muestra cambios relevantes no documentados, incluye la actualización correspondiente en la propuesta.
- No sustituyas conocimiento necesario por enlaces a otra capa.
- No des la revisión por terminada si existen contradicciones conocidas o capas insuficientes.

## Resultado de la fase de análisis

Antes de solicitar confirmación, explica:

- qué rango de commits revisaste;
- qué conocimiento cambió;
- qué impacto evaluaste en cada capa;
- qué cambios propones;
- qué documentos se verían afectados;
- qué evidencias justifican cada cambio;
- qué contradicciones o dudas detectaste;
- qué información no pudo verificarse.

Termina solicitando confirmación explícita y no modifiques ningún fichero.

## Resultado de la fase de aplicación

Después de recibir confirmación y aplicar los cambios, explica:

- qué cambios aprobados aplicaste;
- qué documentos modificaste;
- qué propuestas no fueron aprobadas o quedaron pendientes;
- cómo validaste la coherencia y autosuficiencia de las capas;
- qué evidencias principales utilizaste;
- cómo actualizaste el baseline documental.