# Instrucciones de documentación por defecto

Normas de estilo y presentación de la documentación que las skills
documentales generan o modifican. La metodología del repositorio
(`docs/documentation-methodology.md`) define qué documentar, cómo se organiza
y las reglas transversales de contenido (p. ej. «Información sensible y
secretos»); este fichero define cómo se presenta. Son normas por defecto: un
repositorio puede especializarlas mediante
`.agentic/instructions/docs-local.md` (ver «Instrucciones de documentación» en
la metodología).

## Comandos y código

1. Todo comando que se ejecute en una terminal va en un bloque de código
   cerrado con la etiqueta de lenguaje correcta:

   - `bash` para macOS, Linux y Git Bash;
   - `powershell` para Windows PowerShell;
   - `python`, `json`, `yaml`, `toml`, etc. según el contenido.

   No se escribe un comando suelto en prosa, en listas sin bloque ni en celdas
   de tabla.

2. Se usa código inline para:

   - rutas de ficheros y directorios;
   - nombres de ficheros;
   - comandos y opciones cuando aparecen dentro de una frase;
   - variables de entorno y nombres de variables;
   - valores de configuración y nombres de campos.

3. Los bloques de comandos son completos y copiables tal cual. Si un comando
   depende del directorio de trabajo, se indica explícitamente en el texto
   inmediatamente anterior al bloque (p. ej. «desde la carpeta de la app»).

4. Una secuencia de comandos que forma un flujo atómico se escribe en un único
   bloque, en orden. Cuando cada paso necesita su propia explicación, se usa
   una lista numerada y un bloque por paso.

5. Las variantes por plataforma (macOS/Linux frente a Windows) van en bloques
   separados y etiquetados. No se mezcla sintaxis incompatible en un mismo
   bloque; si no hay alternativa, se separan con comentarios explícitos dentro
   del bloque.

6. Los placeholders (`<bucket>`, `<API_KEY>`, `<versión>`) se explican
   inmediatamente después del bloque o en el texto precedente, indicando qué
   debe sustituir el lector y de dónde lo obtiene. Los valores sensibles siguen
   los marcadores de «Información sensible y secretos».

7. Cuando la salida de un comando ayuda a verificar que ha funcionado, se
   incluye el resultado esperado (un extracto breve o las líneas clave) junto
   al bloque.

## Instrucciones completas

1. Todo procedimiento incluye, cuando apliquen a ese procedimiento:

   - **Prerrequisitos**: qué se necesita antes y cómo comprobarlo.
   - **Pasos**: lista numerada; cada paso indica exactamente qué hace el lector
     (qué elemento de la interfaz, qué campo, qué valor, qué comando) y, cuando
     sea observable, qué debe ver después de hacerlo.
   - **Resultado esperado**: qué debe verse al terminar para confirmar que ha
     funcionado.
   - **Qué hacer si falla**: los fallos previsibles y la acción correspondiente.

   Un procedimiento al que le falte uno de estos apartados aplicables se
   considera incompleto.

2. Quedan prohibidos los pasos ambiguos o incompletos: no se escribe «configura
   lo necesario», «haz lo habitual», «según corresponda», «etc.» ni ninguna
   expresión que delegue en el lector una decisión que la documentación puede y
   debe resolver. Si la documentación no puede resolverla, se indica qué
   condiciona la decisión y quién la toma.

3. Cuando un valor (versión, duración, límite, ruta) es verificable en el
   repositorio, se documenta el valor exacto. No se usan aproximaciones vagas
   («varios días», «normalmente», «un poco») cuando la fuente de verdad está
   disponible.

4. Cada paso es autosuficiente: no depende de una acción previa no declarada.
   Si un paso requiere un estado previo, ese estado aparece en los
   prerrequisitos o en un paso anterior.

5. Cuando el motivo de una decisión afecta a lo que el lector debe elegir o
   hacer, se explica brevemente (una línea suele bastar).

6. Los elementos de la interfaz se citan por su nombre exacto como aparecen en
   la aplicación; los elementos del sistema por su ruta o nombre exacto. No se
   asume que el lector sabe dónde está un elemento.

## Formato general

1. Pasos ordenados → lista numerada. Elementos sin orden → lista de viñetas.
   Opciones, flags, variables o parámetros → tabla.

2. Un documento se redacta en un único idioma, coherente con el resto de la
   documentación del repositorio.

3. Estructura recomendada de una guía de tarea (capa de usuario):

   - Objetivo (qué consigue el lector);
   - Cuándo usarlo (y cuándo no);
   - Antes de empezar (prerrequisitos y cómo comprobarlos);
   - Cómo hacerlo (pasos);
   - Resultado esperado;
   - Limitaciones;
   - Ante errores (recuperación).

   La estructura se adapta a la tarea: no es obligatorio que todos los
   apartados aparezcan como secciones con ese nombre, pero el conocimiento que
   cubren debe estar presente cuando aplique.
