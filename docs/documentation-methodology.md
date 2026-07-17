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

11. No inventar información.

   Toda afirmación debe poder justificarse con el estado actual del repositorio. Si algo no puede verificarse, debe marcarse como pendiente de validar.

   No absorbas ni elimines artefactos operativos del framework por considerar que su contenido aparece también en la documentación.

   Antes de mover, sustituir o eliminar un fichero, determina si su función es:

   - documentación;
   - configuración;
   - manifiesto;
   - índice operativo;
   - interfaz pública;
   - entrada consumida por herramientas o agentes.

   La documentación puede explicar esos artefactos, pero no sustituirlos cuando cumplen una función operativa propia.

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
- proponer o realizar cambios documentales basados en evidencias, sin inventarlos.

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