---
name: docs-init-full
description: Genera, adapta o completa de forma exhaustiva la documentación integral del repositorio para agentes, desarrolladores y usuarios, y valida el README principal.
---

# docs-init-full

Genera o adapta el corpus documental completo del repositorio mediante una revisión integral del estado actual, sin depender de un baseline previo.

Puede invocarse directamente o desde `docs-init` cuando el usuario solicite expresamente generar la documentación inicial exhaustiva.

Debe servir tanto para:

- generar la documentación integral de un repositorio;
- adaptar un repositorio que usa una convención documental anterior;
- integrar documentación creada fuera del framework;
- completar una documentación ya existente pero incompleta.

Primero lee:

```text
docs/documentation-methodology.md
```

Después inspecciona:

- la documentación existente;
- `README.md`;
- `AGENTS.md`, si existe;
- el código, la configuración, los scripts, los manifiestos y la superficie pública del repositorio.

## Objetivo documental

Debes asegurar que el repositorio disponga, de acuerdo con sus necesidades reales, de:

- documentación compacta, modular y autosuficiente para agentes;
- documentación técnica completa y autosuficiente para desarrolladores;
- documentación de uso completa y autosuficiente para usuarios;
- un `README.md` adecuado como puerta de entrada.

Utiliza preferentemente estas ubicaciones:

```text
docs/agent/
docs/development/
docs/user/
```

Estas ubicaciones son una organización recomendada, no una estructura rígida. No impongas nombres, subdirectorios ni un número fijo de documentos.

## Revisión integral

Analiza el repositorio completo y la documentación existente para identificar:

- qué conocimiento ya está documentado;
- qué afirmaciones siguen siendo válidas;
- qué conocimiento falta en cada capa;
- qué documentos mezclan audiencias o propósitos;
- qué rutas, comandos, interfaces, funcionalidades o limitaciones deben documentarse;
- qué referencias internas quedarían rotas si cambia la organización.

No limites el análisis a decidir dónde colocar cada documento.

La generación integral no se considera completa por repartir documentación existente entre carpetas.

## Proyección del conocimiento

La unidad de trabajo es el conocimiento del repositorio, no el documento existente.

Las tres capas deben derivarse directamente del conocimiento verificado del repositorio.

No construyas la documentación para agentes como un resumen mecánico de la documentación para desarrolladores, ni la documentación de usuarios como una simplificación mecánica de otra capa.

Utiliza las mismas fuentes de verdad para decidir qué debe aparecer en cada capa y cómo debe expresarse para su audiencia.

Para cada área relevante del sistema, determina qué necesita conocer cada audiencia y representa ese conocimiento en su capa correspondiente:

### Agentes

Incluye de forma compacta y modular el contexto necesario para localizar y modificar el código con seguridad:

- responsabilidades;
- componentes y rutas relevantes;
- interfaces;
- invariantes;
- convenciones;
- flujos operativos necesarios;
- restricciones y decisiones que condicionan cambios.

La capa para agentes debe ser suficiente para el trabajo habitual sin obligar a consultar `docs/development/`.

### Desarrolladores

Incluye el contexto necesario para comprender, mantener y ampliar el proyecto.

Para cada área relevante, documenta desde la intención hacia la implementación:

- qué problema o responsabilidad resuelve;
- cómo encaja en el sistema completo;
- por qué está estructurada de esa manera, cuando pueda verificarse;
- qué decisiones, restricciones, invariantes o compromisos condicionan el
  diseño;
- qué componentes participan y cómo colaboran;
- qué consecuencias tendría alterar sus límites o responsabilidades;
- cómo se prepara, ejecuta, prueba, depura, despliega, opera y amplía.

No conviertas esta capa en un catálogo de módulos, clases o funciones. Incluye
referencias técnicas cuando sean necesarias, pero úsalas para explicar el
diseño y los flujos del sistema.

No inventes razones arquitectónicas. Si el repositorio permite verificar el
comportamiento pero no la motivación, documenta el comportamiento y presenta
la motivación como una cuestión pendiente de confirmación humana.

La capa para desarrolladores debe ser suficiente sin obligar a consultar
`docs/agent/`.

### Usuarios

Identifica primero qué objetivos reales puede alcanzar una persona mediante el
producto.

Organiza la documentación principalmente alrededor de esos objetivos y casos
de uso. Para cada uno, explica:

- qué consigue el usuario;
- cuándo debe utilizarlo;
- qué necesita antes de empezar;
- qué flujo o funcionalidad debe elegir;
- cómo realizar la tarea;
- cuál es el resultado esperado;
- qué capacidades y limitaciones existen;
- qué hacer ante errores o resultados inesperados.

Explica los comandos, opciones y controles visibles dentro del objetivo al que
sirven. No estructures la guía principal como una descripción pantalla por
pantalla, función por función o botón por botón.

Cuando existan varias formas parecidas de actuar, ayuda al usuario a elegir la
adecuada explicando para qué sirve cada una.

La capa para usuarios debe permitir utilizar el producto sin consultar
documentación técnica.

## Reutilización y adaptación

Si el repositorio ya contiene documentación:

- conserva todo el conocimiento útil y verificable;
- reutilízalo para construir o completar las distintas capas;
- amplía documentos insuficientes;
- divide documentos que mezclen audiencias cuando mejore la claridad;
- crea resúmenes específicos para agentes cuando la documentación técnica existente sea demasiado extensa;
- crea documentación nueva cuando una capa carezca de información necesaria;
- actualiza referencias internas cuando cambien rutas;
- no regeneres toda la documentación desde cero sin necesidad.

No asumas que un documento pertenece a una capa por su nombre o ubicación.

Antes de tratar un fichero como documentación reutilizable o prescindible, comprueba si tiene una función operativa propia dentro del framework.

No muevas, absorbas ni elimines manifiestos, índices operativos, configuración, interfaces públicas o ficheros consumidos por scripts, skills o arneses solo porque su contenido también vaya a explicarse en la documentación.

No trates mover, renombrar o reclasificar ficheros como objetivo principal. Solo hazlo cuando mejore realmente la organización y la navegación.

Cuando un documento existente sea útil para desarrolladores pero demasiado extenso para agentes:

1. conserva su contenido completo en la capa de desarrollo;
2. crea un resumen específico y autosuficiente para agentes;
3. no sustituyas el resumen por un simple enlace a la documentación extensa;
4. no reduzcas ni pierdas información técnica para hacerla encajar en la capa de agentes.

En repositorios antiguos del framework, la documentación mínima existente puede reutilizarse como base para agentes, pero no asumas que con repartirla entre `docs/agent/` y `docs/development/` la adaptación queda resuelta.

En repositorios con documentación creada fuera del framework, respeta lo que ya sea útil y completa las capas que falten.

La redundancia entre capas está permitida cuando sea necesaria para que cada una resulte autosuficiente.

Antes de sobrescribir, mover, dividir o renombrar documentación existente, presenta una propuesta breve y pide confirmación al usuario.

La propuesta debe explicar:

- qué áreas de conocimiento se han identificado;
- qué fuentes de verdad confirman cada área;
- cómo se representará ese conocimiento para agentes;
- cómo se representará para desarrolladores;
- cómo se representará para usuarios;
- qué documentación existente se reutiliza como fuente;
- qué documentos se amplían o sustituyen;
- qué ficheros se mueven, renombran o eliminan y por qué esa acción es segura;
- qué referencias deberán actualizarse;
- qué artefactos operativos se conservan aunque parte de su contenido también
  se documente.
- qué objetivos principales de los usuarios se han identificado y cómo se
  organizará la documentación alrededor de ellos;
- qué intenciones, decisiones y restricciones de diseño deben explicarse en la
  documentación para desarrolladores;
- qué razones importantes no pueden verificarse desde el repositorio y
  requieren información humana.

La documentación existente es una fuente de conocimiento, no una plantilla que deba conservarse ni una estructura que deba mantenerse.

Analiza primero el conocimiento disponible y después decide cómo debe representarse para cada audiencia.

No asumas que un documento existente pertenece íntegramente a una única capa documental.

## README y AGENTS

Revisa siempre el `README.md` raíz para asegurar que actúa como puerta de entrada útil y que enlaza la documentación vigente.

Si existe `AGENTS.md`, comprueba únicamente que:

- sigue siendo un punto de entrada compacto para agentes;
- explica cómo consultar la documentación de forma selectiva;
- no obliga a cargar toda la documentación;
- referencia las rutas documentales reales después de la adaptación.

No crees ni propongas crear `AGENTS.md`. Su creación y mantenimiento estructural no forman parte de la responsabilidad de `docs-init-full`.

## Validación basada en evidencias

Antes de dar la generación integral por terminada:

1. Verifica las afirmaciones relevantes contra el estado actual del repositorio.
2. Comprueba que `README.md`, `AGENTS.md` si existe y las tres capas documentales no se contradicen.
3. Comprueba que cada capa es autosuficiente para su audiencia.
4. Comprueba que las rutas y enlaces internos siguen siendo válidos.
5. Busca referencias a rutas antiguas en documentación, skills, wrappers y otros ficheros del repositorio.
6. Comprueba que no se ha perdido información útil.
7. Comprueba que la documentación para agentes sigue siendo compacta sin resultar incompleta.
8. Comprueba que la documentación para desarrolladores no se limita a describir
   componentes e implementación, sino que explica su propósito, relaciones,
   decisiones, restricciones y consecuencias cuando estas puedan verificarse.
9. Comprueba que la documentación de usuario permite partir de un objetivo,
   elegir el flujo adecuado, completar la tarea y reconocer el resultado
   esperado, en lugar de limitarse a describir la interfaz.
10. Comprueba que las razones o intenciones no respaldadas por evidencias no se
    hayan presentado como hechos.
11. Comprueba que ningún fichero propuesto para eliminar, sustituir o mover cumple una función operativa, contractual o de integración que no pueda asumir la documentación nueva.
12. Marca como pendiente cualquier información que no pueda verificarse.

Para las afirmaciones técnicas o funcionales relevantes, identifica su fuente de verdad en:

- árbol actual del repositorio;
- código;
- configuración;
- scripts;
- manifests y lockfiles;
- interfaces públicas;
- salida de comandos de inspección.

No des la documentación por válida solo porque parezca coherente.

## Actualización del baseline

Al finalizar correctamente:

- actualiza `.agentic.lock.json`;
- establece `documentation.last_reviewed_commit` al commit actual de `HEAD`;
- establece `documentation.last_reviewed_at` a la fecha y hora actual real en formato ISO 8601;
- si no puedes obtener la fecha y hora real, usa `null` y avisa.

## Reglas

- No inventes APIs, servicios, comandos, funcionalidades ni arquitectura.
- Mantén compacta la documentación para agentes, pero asegúrate de que sea autosuficiente.
- En documentación para desarrolladores y usuarios, prioriza claridad, suficiencia y autosuficiencia sobre brevedad.
- No borres documentación útil.
- No impongas una estructura rígida.
- No clasifiques documentos únicamente por su nombre o ubicación.
- No reduzcas documentación técnica existente solo para convertirla en documentación para agentes.
- No consideres completada la adaptación por el mero hecho de mover o repartir documentos.
- No sustituyas información necesaria por enlaces a otra capa.
- No crees documentos vacíos para completar una estructura.
- No modifiques código.
- Si algo no está claro, márcalo como pendiente de verificar.
- No elimines un fichero solo porque su conocimiento haya sido absorbido por las nuevas capas documentales.
- No trates como documentación pura un fichero que sea consumido por scripts, skills, arneses o herramientas.
- Las tres capas deben derivarse del repositorio verificado, no unas de otras.

## Resultado esperado

Explica brevemente:

- si el corpus documental se generó, se adaptó o se completó;
- qué conocimiento y documentación se conservaron;
- qué documentación se amplió;
- qué resúmenes específicos se crearon;
- qué documentación nueva se creó y qué carencia resolvió;
- qué documentos se dividieron, movieron o renombraron y por qué;
- cómo se comprobó la autosuficiencia de agentes, desarrolladores y usuarios;
- qué evidencias principales se utilizaron;
- qué cambios estructurales requieren confirmación;
- qué queda pendiente de validar.