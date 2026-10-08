# Metodología de documentación del repositorio

## Objetivo

Mantener una documentación actualizada, coherente y adaptada a tres audiencias permanentes:

- agentes de coding;
- desarrolladores y mantenedores;
- usuarios del proyecto.

Cada audiencia debe disponer de una capa documental propia, suficiente y autosuficiente. Ninguna persona o agente debería tener que consultar otra capa para cubrir las necesidades normales de su función.

La documentación destinada a agentes debe seguir siendo pequeña, modular y cargable bajo demanda. La documentación destinada a desarrolladores y usuarios puede ser más extensa cuando sea necesario para comprender, mantener o utilizar correctamente el proyecto.

## Capas documentales

La documentación se organiza conceptualmente en tres capas o vistas del mismo sistema.

Las capas pueden resumir, ampliar, reorganizar o adaptar el lenguaje, pero deben describir los mismos hechos y mantenerse coherentes entre sí.

### Documentación para agentes

Debe permitir que un agente comprenda y modifique el repositorio de forma selectiva sin cargar documentación innecesaria ni depender de la documentación para desarrolladores o usuarios.

Debe ser:

- pequeña;
- organizada en módulos de conocimiento independientes;
- orientada a responsabilidades, arquitectura, interfaces, invariantes, convenciones y operación;
- cargable bajo demanda;
- centrada en el conocimiento necesario para localizar y modificar el código con seguridad;
- suficiente para el trabajo habitual de un agente sobre el repositorio.

No debe reproducir el código ni convertirse en un manual exhaustivo, pero tampoco debe omitir conocimiento necesario obligando al agente a acudir a otra capa.

La ubicación recomendada es:

```text
docs/agent/
```

La estructura interna depende de las necesidades reales del proyecto.

### Modularidad y carga selectiva

La documentación para agentes debe organizarse en módulos de conocimiento independientes.

Cada módulo debe cubrir un único ámbito coherente del repositorio para que un agente pueda cargar únicamente la información necesaria para la tarea que está realizando.

La modularidad no depende del tamaño del repositorio ni del número de documentos, sino de la organización conceptual del conocimiento.

Agrupa en un mismo documento únicamente conocimiento que:

- normalmente se consulte conjuntamente;
- pertenezca al mismo subsistema, responsabilidad o flujo;
- evolucione habitualmente por las mismas razones.

Divide la documentación cuando un documento mezcle:

- responsabilidades independientes;
- subsistemas distintos;
- workflows diferentes;
- áreas de conocimiento que un agente podría consultar de forma aislada.

No impongas un número fijo de documentos.

Un repositorio pequeño puede necesitar pocos documentos, pero no debe concentrar en un único documento áreas conceptualmente independientes solo porque su volumen sea reducido.

Puede existir un documento índice para facilitar la navegación, pero su función es orientar la carga selectiva de la documentación, no concentrar toda la información de la capa de agentes.

### Documentación para desarrolladores

Debe permitir que un desarrollador comprenda el proyecto, su intención, su estructura y sus principales flujos, y pueda mantenerlo o ampliarlo sin tener que leer previamente todo el código ni consultar la documentación para agentes.

Puede incluir, según proceda:

- arquitectura y responsabilidades;
- estructura del repositorio;
- flujos entre componentes;
- decisiones y restricciones relevantes;
- preparación del entorno;
- ejecución, pruebas y depuración;
- despliegue y operación;
- extensibilidad y mantenimiento.

No debe duplicar mecánicamente el código, pero sí explicar el contexto necesario para comprenderlo y modificarlo con seguridad.

La ubicación recomendada es:

```text
docs/development/
```

La estructura y extensión dependen de la complejidad del proyecto.

### Documentación para usuarios

Debe permitir que un usuario instale, acceda, configure y utilice el proyecto, y resuelva los problemas habituales, sin depender de la documentación para desarrolladores o agentes.

Debe adaptarse a la superficie real del producto y a los conocimientos razonables de sus usuarios. Una herramienta técnica puede dirigirse a usuarios técnicos; una aplicación de uso general debe emplear lenguaje comprensible para usuarios no especializados.

Puede incluir, según proceda:

- instalación o acceso;
- primeros pasos;
- tareas y flujos habituales;
- comandos, opciones o controles visibles;
- configuración;
- capacidades y limitaciones;
- resolución de problemas y recuperación;
- preguntas frecuentes.

La ubicación recomendada es:

```text
docs/user/
```

La estructura y el número de documentos dependen de la superficie funcional del proyecto.

## Orientación por intención y objetivos

La documentación no debe limitarse a inventariar componentes, funciones,
comandos, opciones o pantallas. Debe explicar el propósito del sistema desde
la perspectiva de cada audiencia.

### Documentación para desarrolladores

La documentación para desarrolladores debe explicar no solo cómo está
implementado el sistema, sino también, cuando pueda verificarse:

- qué problema resuelve cada área relevante;
- qué responsabilidad tiene dentro del conjunto;
- por qué el código está dividido o estructurado de esa manera;
- qué decisiones, restricciones o necesidades condicionaron el diseño;
- qué invariantes y límites deben preservarse;
- qué riesgos o consecuencias tendría modificar esas decisiones;
- cómo encaja cada componente en los flujos completos del sistema.

No es necesario justificar cada función ni describir línea por línea el código.
Debe documentarse especialmente la intención que no resulte evidente al leer
una implementación aislada.

No inventes motivaciones ni decisiones arquitectónicas. Distingue entre:

- comportamiento y estructura verificables en el repositorio;
- intención o razones respaldadas por documentación, comentarios, historial o
  información humana;
- razones que no pueden determinarse con las evidencias disponibles.

Cuando una razón relevante no pueda verificarse, indícala como pendiente y
solicita información humana en lugar de deducirla.

### Documentación para usuarios

La documentación para usuarios debe organizarse principalmente alrededor de
los objetivos que el usuario quiere alcanzar, no alrededor de la estructura
interna del producto ni de una enumeración de sus controles.

Identifica los objetivos reales soportados por el producto. Para cada objetivo
relevante, explica:

- qué puede conseguir el usuario;
- cuándo debe utilizar ese flujo;
- qué requisitos o condiciones previas existen;
- qué funcionalidad debe elegir cuando hay varias alternativas;
- cómo completar la tarea;
- qué resultado debe esperar;
- qué limitaciones debe conocer;
- qué hacer si la operación falla o no obtiene el resultado esperado.

Los comandos, botones, campos, opciones y secuencias de pasos deben explicarse
dentro del objetivo al que sirven. Pueden existir documentos de referencia de
la interfaz, pero no deben sustituir las guías orientadas a tareas.

La estructura documental no tiene que seguir literalmente títulos del tipo
«Quiero...», pero debe permitir que un usuario encuentre la guía partiendo de
lo que necesita conseguir.

## Autosuficiencia y redundancia

Cada capa documental debe ser autosuficiente para su audiencia:

- un agente debe poder trabajar con la documentación para agentes;
- un desarrollador debe poder comprender y mantener el proyecto con la documentación para desarrolladores;
- un usuario debe poder utilizar el producto con la documentación para usuarios.

La redundancia entre capas está permitida y es esperable cuando resulta necesaria para mantener esa autosuficiencia.
La autosuficiencia se exige al conjunto de cada capa documental, no a cada documento individual.
Cada documento debe ser autosuficiente únicamente dentro de su ámbito de conocimiento y poder consultarse de forma independiente.
La documentación de una misma capa debe organizarse para favorecer la carga selectiva, evitando documentos que concentren áreas de conocimiento no relacionadas.

No copies texto mecánicamente entre capas. Expresa el mismo conocimiento con el lenguaje, el enfoque y el nivel de detalle adecuados para cada audiencia.
Evita la duplicación innecesaria dentro de una misma capa documental.

## Principios generales

1. La unidad de mantenimiento es el conocimiento, no el documento.

   Cuando cambia una funcionalidad, interfaz, componente, flujo o limitación, identifica qué conocimiento ha cambiado y actualiza todas las capas donde resulte relevante.

2. Las capas derivan directamente del conocimiento verificado del repositorio.

   La documentación para agentes, desarrolladores y usuarios debe construirse a partir del código, la configuración, los scripts, los manifiestos, las interfaces, el comportamiento real y la documentación válida existente.

   No uses una capa documental como fuente canónica para generar mecánicamente las demás.

   Ninguna capa es la documentación principal de la que derivan las otras.
   
   Las tres son representaciones independientes del mismo conocimiento, adaptadas a distintas audiencias.

3. Documentar según la audiencia y el propósito.

   La brevedad es prioritaria en la documentación para agentes. En la documentación para desarrolladores y usuarios, deben priorizarse la claridad, la suficiencia y la utilidad.

4. No imponer una estructura rígida.

   Cada proyecto debe tener únicamente los documentos que necesite. No existe una lista fija de nombres, subdirectorios ni número de ficheros.

5. No duplicar mecánicamente el código.

   No documentar línea por línea aquello que el código expresa de forma evidente. Sí documentar intención, contexto, relaciones, flujos, decisiones, restricciones y procedimientos que sería costoso reconstruir leyendo el repositorio.

6. No cargar toda la documentación por defecto.

   Los agentes deben consultar solo los documentos necesarios para la tarea actual. Deben empezar por la documentación compacta de `docs/agent/`.

   Pueden consultar otras capas para comprobar impacto o coherencia documental, pero la documentación para agentes debe seguir siendo suficiente para su trabajo habitual.

7. Optimizar la carga selectiva del conocimiento.

   La organización documental debe minimizar la cantidad de contexto necesaria para realizar una tarea.

   La documentación para agentes no se considera suficientemente modular si obliga habitualmente a cargar información perteneciente a áreas independientes del repositorio.

   La modularidad debe favorecer que cada tarea consulte únicamente el conocimiento relacionado con la parte del sistema que va a analizar o modificar.

8. Referenciar documentación mediante rutas normales del repositorio.

   Por ejemplo:

   ```text
   docs/agent/architecture.md
   docs/development/testing.md
   docs/user/getting-started.md
   ```

   No usar sintaxis específica de un arnés, como `@docs/...`, dentro de documentación o skills comunes.

9. Actualizar la documentación junto con el código.

   Si cambia la arquitectura, una interfaz, la operación, el flujo de desarrollo o el comportamiento visible para usuarios, debe actualizarse el conocimiento correspondiente en todas las capas afectadas durante la misma sesión.

10. Reutilizar antes de crear, sin confundir reutilización con simple reparto.

   Al adaptar un repositorio existente, conservar el conocimiento útil y reutilizarlo para generar las representaciones adecuadas para cada audiencia.

   Mover o reclasificar documentos no es suficiente si alguna capa sigue siendo incompleta o dependiente de otra.

11. No inventar ni asumir información.

   Toda afirmación debe poder justificarse con el estado actual del
   repositorio. No rellenes huecos con deducciones ni con justificaciones
   plausibles: si algo no puede verificarse, no se documenta como hecho. En
   ese caso se pregunta al humano indicando qué falta y por qué importa; solo
   si la cuestión no puede resolverse se la marca como pendiente de validar.

   No absorbas ni elimines artefactos operativos del framework por considerar que su contenido aparece también en la documentación.

   Antes de mover, sustituir o eliminar un fichero, determina si su función es:

   - documentación;
   - configuración;
   - manifiesto;
   - índice operativo;
   - interfaz pública;
   - entrada consumida por herramientas o agentes.

    La documentación puede explicar esos artefactos, pero no sustituirlos cuando cumplen una función operativa propia.

12. No documentar información sensible.

   Claves, tokens, contraseñas, claves privadas, material criptográfico
   sensible, connection strings con credenciales ni ningún otro valor
   sensible no se incluyen en ningún documento que los skills del framework
   generen o modifiquen, independientemente de su ruta. Al detectar
   información sensible en el repositorio o en la documentación existente, se
   avisa al usuario y se propone su redacción. Ante la duda sobre si un valor
   es sensible, no se decide de forma unilateral: se trata provisionalmente
   como potencialmente sensible y se pregunta al usuario. Ver la sección
   «Información sensible y secretos».

13. Al actualizar, la coherencia del conjunto prima sobre la minimalidad
   del cambio.

   Cuando una modificación necesaria puede integrarse en el texto de forma
   más ordenada y coherente que como un añadido o un parche puntual, se
   redacta la sección afectada de forma integrada, aunque implique más
   cambios: no se minimiza el número de modificaciones a costa de la
   cohesión, la comprensión ni la coherencia de la documentación. Esta regla
   no autoriza actualizaciones que no sean necesarias: solo regula cómo
   se realizan los cambios que lo sean.

   En toda reescritura, la información preexistente sobre aquello que no ha
   cambiado se conserva íntegramente: puede reformularse, reordenarse o
   ampliarse, pero no eliminarse ni reducirse. Una reescritura nunca mengúa
   el conocimiento documentado: antes de aplicarla, se verifica que ninguna
   afirmación, procedimiento, ruta, comando, decisión, limitación o
   advertencia preexistente haya desaparecido del resultado.

## Coherencia documental

La documentación debe mantenerse como un conjunto coherente, no como documentos independientes.

Al crear o actualizar documentación:

1. Verificar las afirmaciones relevantes contra el código, la configuración, los scripts, los manifiestos, las interfaces y el comportamiento actual del repositorio.
2. Buscar referencias al mismo concepto, componente, comando, flujo o funcionalidad en:
   - `README.md`;
   - `AGENTS.md`, si existe;
   - `docs/agent/`;
   - `docs/development/`;
   - `docs/user/`;
   - cualquier otra documentación que cumpla esas funciones.
3. Comprobar que todas las capas:
   - utilizan nombres compatibles;
   - describen el mismo comportamiento;
   - reflejan las mismas capacidades y limitaciones;
   - no mantienen como activo algo eliminado o sustituido;
   - no ofrecen instrucciones incompatibles.
4. Adaptar el nivel de detalle y el lenguaje a cada audiencia sin cambiar los hechos.
5. Si dos documentos se contradicen, determinar el comportamiento real a partir del repositorio y corregir todos los documentos afectados.
6. Comprobar además la autosuficiencia de cada capa y completar cualquier conocimiento necesario que solo aparezca en otra.
7. No considerar la documentación actualizada mientras existan contradicciones conocidas o dependencias evitables entre capas.
8. Comprobar que la documentación para agentes permite localizar el conocimiento de cada área del repositorio sin obligar a cargar documentación perteneciente a otras áreas conceptualmente independientes.
9. Si un cambio necesario deja la sección afectada menos coherente que una redacción integrada, redactar la sección de forma integrada en lugar de aplicar un parche mínimo, y verificar que conserva íntegramente toda la información preexistente sobre lo que no ha cambiado (principio 13).

## Información sensible y secretos

La documentación no debe contener información sensible. Esta sección define qué
se considera información sensible y cómo deben comportarse los skills
documentales (`docs-init`, `docs-init-full`, `docs-update`) y `commit-work`
frente a ella.

### Qué se considera información sensible

Se considera información sensible, de forma no exhaustiva:

- claves API, tokens de acceso o de sesión, contraseñas y passphrases;
- claves privadas y material criptográfico sensible que contenga secretos o
  permita autenticación o firma (p. ej. claves privadas SSH, `*.pem` con
  clave privada, material de firma). Los certificados **públicos** no se
  consideran información sensible;
- connection strings o URLs con credenciales embebidas (`user:pass@`);
- cualquier valor que el repositorio marque explícitamente como secreto
  (comentarios, nombres de fichero, `.env`, configuración de CI);
- credenciales de servicios externos (nubes, registros, bases de datos).

No es información sensible: el nombre de una variable de entorno, la ruta de un
fichero de configuración, o un comando o procedimiento para obtener o configurar
una credencial, siempre que no incluya su valor.

### Regla general

No incluyas el valor de información sensible en ningún documento que los
skills del framework generen o modifiquen, independientemente de su ruta:
capas documentales (`docs/agent/`, `docs/development/`, `docs/user/`),
`README.md`, `AGENTS.md`, documentación de trabajo o cualquier otro fichero
de texto bajo su responsabilidad.

Cuando un documento necesite referirse a una credencial, usa un marcador
(`<API_KEY>`, `<TOKEN>`, `your-password`) y señala dónde se configura
(archivo, variable de entorno o comando) sin mostrar el valor.

### Al generar o actualizar documentación

Al inspeccionar el código, la configuración, los scripts, los manifiestos o la
documentación existente:

- si encuentras información sensible en fuentes del repositorio, no la copies
  en la documentación nueva;
- si encuentras información sensible ya presente en documentación existente,
  avisa siempre al usuario indicando el fichero y la ubicación, sin mostrar el
  valor completo, e incluye en la propuesta su eliminación o redacción, sujeta
  a la confirmación humana obligatoria;
- si no puedes determinar con suficiente seguridad si un valor es sensible, no
  decidas por tu cuenta: trátalo provisionalmente como potencialmente
  sensible (no lo documentes y no lo dejes avanzar hacia el commit), avisa al
  usuario indicando fichero y ubicación sin mostrar el valor completo y
  pregúntale explícitamente antes de aprobarlo, documentarlo o permitir que
  continúe hacia el commit; una vez recibida la respuesta, si el usuario
  confirma que el valor no es un secreto, regístralo en `AGENTS.md` como falso
  positivo conocido identificando el caso concreto (fichero, campo, variable o
  contexto), sin registrar el valor completo si pudiera ser sensible y sin
  generalizar la decisión, para que futuras ejecuciones no vuelvan a preguntar
  por él; ese registro es un cambio documental más: en skills con flujo de
  propuesta y confirmación (p. ej. `docs-update`) forma parte de la propuesta y
  solo se aplica tras la confirmación humana, en la fase de aplicación;
- el aviso es obligatorio aunque el repositorio sea privado y aunque no se
  proponga cambio documental.

### Al preparar un commit

`commit-work` debe comprobar que los cambios pendientes no contienen
información sensible antes de proponer el commit. Si la encuentra, se detiene,
avisa al usuario indicando fichero y ubicación sin mostrar el valor completo, y
no propone el commit.

## Uso por agentes

Los agentes deben:

- leer solo los documentos necesarios para la tarea;
- no cargar toda la documentación al iniciar la sesión;
- empezar por `docs/agent/` cuando necesiten contexto del repositorio;
- cargar únicamente los módulos documentales relacionados con la tarea que están realizando;
- evitar cargar documentación perteneciente a áreas independientes del repositorio salvo que la tarea realmente lo requiera.
- tratar `docs/agent/` como una capa autosuficiente para el trabajo habitual;
- consultar `docs/development/` y `docs/user/` cuando deban actualizar esas capas, comprobar coherencia o evaluar impacto;
- utilizar rutas normales del repositorio;
- avisar si un cambio de código requiere actualizar documentación;
- no incluir información sensible en ningún documento que genere o modifique
  (ver «Información sensible y secretos»);
- avisar al usuario si detecta información sensible en el repositorio o en la
  documentación existente;
- ante la duda sobre si un valor es sensible, no decidir de forma unilateral:
  tratarlo provisionalmente como potencialmente sensible y preguntar al
  usuario;
- proponer o realizar cambios documentales basados en evidencias, sin inventarlos ni asumarlos: ante una cuestión no verificable, preguntar al usuario antes de documentarla (principio 11).

## Skills comunes

Las acciones reutilizables viven en:

```text
.agentic/skills/<skill>/SKILL.md
```

Cada arnés implementa un wrapper mínimo:

```text
.claude/skills/<skill>/SKILL.md
.opencode/skills/<skill>/SKILL.md
```

La lógica de cada skill vive una única vez en `.agentic/skills/`.

Los wrappers no deben contener lógica de negocio; únicamente deben invocar la implementación común.

## Ubicación de las normas

Cada tipo de norma vive en el lugar que le corresponde por su naturaleza y su
alcance, no por su forma: que una norma se escriba en imperativo no la convierte
en una instrucción de presentación.

- **Esta metodología** define qué documentar, cómo se organiza la documentación
  y los invariantes de integridad del contenido: no inventar ni asumir
  información, la política de «Información sensible y secretos», la coherencia
  y la autosuficiencia entre capas. Son reglas que se aplican siempre y que
  ninguna instrucción ni ningún repositorio puede sobrescribir.

- **`.agentic/instructions/docs-default.md` y `.agentic/instructions/docs-local.md`**
  definen cómo se presenta la documentación que las skills generan o modifican:
  estilo, formato, estructura de procedimientos, idioma. Son la capa de
  presentación y la única que un repositorio puede especializar:
  `docs-local.md` prevalece sobre `docs-default.md`.

- **`.agentic/skills/<skill>/SKILL.md`** define cómo ejecuta cada skill su
  acción: fases, verificaciones, detenciones obligatorias y comportamiento ante
  casos concretos. La confirmación humana previa a cualquier modificación
  (proponer antes de aplicar, aplicar únicamente lo aprobado) es parte del flujo
  de ejecución y vive en la skill, no en la capa de presentación.

Criterios de decisión al ubicar una norma:

1. Si regula la **presentación** de los documentos (cómo se ven):
   instrucciones. `docs-default.md` si la norma es del framework;
   `docs-local.md` si es propia del repositorio.

2. Si regula la **integridad o el contenido** de la documentación y debe
   aplicarse siempre, sin sobrescritura: esta metodología.

3. Si regula **cómo ejecuta una skill** una acción concreta: el `SKILL.md` de
   esa skill.

Una regla puede declararse como invariante en la metodología y aplicarse
concretamente en una skill (p. ej. la confirmación humana previa o la política
de secretos): la metodología declara la regla y la skill la aplica con su
mecanismo y su detalle operativo. Un invariante no se coloca en las
instrucciones: al ser una capa sobreescrible, es el lugar equivocado para una
regla que no admite sobrescritura.

## Instrucciones de documentación

Las skills documentales aplican normas de estilo y presentación a la
documentación que generan o modifican. Esas normas no están en este fichero:
viven en artefactos operativos consumidos por las skills.

### Ficheros

- `.agentic/instructions/docs-default.md`: normas por defecto del framework
  (comandos y código, instrucciones completas, formato general). Es un fichero
  **gestionado por `agentic-sync`**: se instala y se actualiza con el
  framework. En un repositorio consumidor **no se edita**: si se modifica, el
  sync lo marca como `CONFLICT` en el próximo `--plan`/`--apply` (la fuente de
  las normas por defecto es el framework).
- `.agentic/instructions/docs-local.md` (opcional): instrucciones propias del
  repositorio. **No es un fichero gestionado**: el sync no lo copia ni lo
  actualiza. El repositorio lo crea, lo edita y lo versiona a su antojo. Si no
  existe, no se aplica nada adicional.

### Aplicación y prioridad

- Las skills documentales (`docs-init`, `docs-init-full`, `docs-update`) leen
  `docs-default.md` inmediatamente después de esta metodología y, si existe,
  también `docs-local.md`, y aplican ambas a toda la documentación que
  generen o modifiquen.
- En caso de conflicto entre `docs-local.md` y `docs-default.md`, las
  instrucciones locales **prevalecen**: regulan estilo, formato, idioma y
  convenciones documentales del repositorio.
- Ni las instrucciones locales ni las por defecto pueden anular:
  - la política de «Información sensible y secretos»;
  - el principio de no inventar ni asumir información;
  - el flujo de propuesta y confirmación humana de las skills;
  - los requisitos de autosuficiencia y coherencia entre capas.
- Si una instrucción intentara anular cualquiera de esos puntos, la skill no la
  aplica en ese punto, la señala en el resultado de su ejecución y pide
  confirmación humana explícita.
- `docs-update` evalúa además la conformidad de la documentación existente
  cuando **cualquiera** de los dos ficheros de instrucciones
  (`.agentic/instructions/docs-default.md` o `docs-local.md`) cambia en el rango
  revisado (D9). Las correcciones resultantes se incluyen en la propuesta de
  actualización, sujeta a confirmación humana obligatoria: nunca se aplican
  directamente.

### Contenido recomendado de `docs-local.md`

Puede especializar o ampliar las normas de `docs-default.md` para el
repositorio concreto, por ejemplo: idioma o registro de la documentación,
convenciones de formato específicas (plantillas, secciones obligatorias
propias del repo, convenciones de encabezados), referencias a documentación
externa del equipo que deban citarse, o excepciones justificadas a las normas
por defecto. No debe contener información sensible (misma política que el
resto de la documentación).

## README principal

El `README.md` de la raíz es la puerta de entrada al proyecto y debe seguir convenciones habituales de la industria.

Debe permitir que una persona que no conoce el repositorio entienda:

- qué es el proyecto;
- qué problema resuelve;
- para quién está pensado;
- cuáles son sus funcionalidades principales;
- cómo instalarlo, ejecutarlo, sincronizarlo o empezar a utilizarlo;
- cuáles son sus puntos de entrada, comandos o flujos principales;
- cuál es su estado o madurez, cuando sea relevante;
- dónde encontrar la documentación detallada;
- cómo contribuir, obtener soporte o consultar la licencia, cuando proceda.

No debe duplicar toda la documentación interna. Debe presentar el proyecto, ofrecer un inicio mínimo útil y enlazar la documentación adecuada para usuarios y desarrolladores.

El contenido exacto debe adaptarse al tipo real de proyecto. No todos los repositorios necesitan las mismas secciones.

El `README.md` no se considera correcto solo por no contener afirmaciones falsas. Si es demasiado pobre, genérico, incompleto o no refleja funcionalidades visibles, debe actualizarse aunque no contenga errores factuales.