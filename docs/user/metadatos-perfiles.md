# Metadatos y perfiles

Cuando subes datos a MinIO con BIFrost Transfer (o cuando los etiquetas con el Tag Manager), la app te pide rellenar una serie de **metadatos** organizados en **perfiles**. Los metadatos son etiquetas que se guardan junto con los ficheros y sirven para identificarlos, clasificarlos y encontrarlos después.

## Qué es un perfil

Un **perfil** es un conjunto de campos pensado para un tipo de datos. BIFrost tiene dos perfiles:

- **IRB Standard** — para datos generales del IRB.
- **Histopathology** — para datos de histopatología, que necesitan información más específica.

Elige en el desplegable el perfil que encaje con tus datos. Si cambias de perfil habiendo relleno campos, la app te pedirá confirmación antes de borrarlos.

## Perfil IRB Standard

Para datos generales. Todos los campos son texto libre:

| Campo | Qué poner |
|---|---|
| **Project** | Nombre o identificador del proyecto al que pertenecen los datos. |
| **Host machine** | Nombre de la máquina o equipo desde donde se suben los datos (por ejemplo, el nombre del equipo del laboratorio). |
| **Sample type** | Tipo de muestra (por ejemplo, "células", "tejido", "ADN"). |
| **Input data type** | Tipo de datos de entrada (por ejemplo, "imágenes", "secuencias", "tablas"). |
| **Output data type** | Tipo de datos de salida (resultado). |
| **Requested by** | Persona que solicita la subida o a quien van destinados los datos. |
| **Research group** | Grupo de investigación al que pertenecen los datos. |

## Perfil Histopathology

Para datos de histopatología. Algunos campos son desplegables con opciones fijas; otros son texto libre.

| Campo | Tipo | Qué poner |
|---|---|---|
| **Owner** | Desplegable | Laboratorio propietario de los datos (lista de laboratorios del IRB). |
| **Users** | Lista libre | Usuarios de Linux que deben tener acceso, uno a uno. |
| **Date** | Fecha | Fecha de los datos (con calendario). |
| **Provider** | Desplegable | Proveedor de los datos (por defecto, "Histopathology IRB Core Facility"). |
| **Instrument** | Desplegable | Instrumento usado: "Phenoimager" o "Nanozoomer". |
| **Species** | Desplegable | Especie: ratón, humano, rata, cerdo, vaca. |
| **Sample Type** | Desplegable | Tipo de muestra: "tissue section", "organoid" o "cell pellet". |
| **Sample Origin** | Texto | Origen biológico de la muestra. Depende del tipo: para tejido, el tipo de tejido (pulmón, colon…); para organoide, el tipo de organoide; para pellet celular, la línea celular (HeLa, HEK293…). La app muestra una ayuda explicativa debajo. |
| **Magnification** | Desplegable | Aumento: 20x o 40x. |
| **Channels** | Desplegable | Canales de la imagen (combinaciones de DAPI y otros canales, o "4plex", "5plex", "6plex"). |

## Campos con varias opciones (desplegables)

En los campos con desplegable:

- Si el valor que necesitas no está en la lista, algunos campos permiten elegir **"✏️ Custom value…"** y escribir uno a mano.
- Otros campos solo admiten las opciones de la lista. Si crees que falta una opción necesaria, contacta con ITS para añadirlo.

## Campos con varios valores (listas)

Algunos campos (como **Users**) permiten meter varios valores. En esos casos:

1. Escribe un valor en la caja.
2. Pulsa el botón **+** (o Enter) para añadirlo.
3. Verás el valor como una "etiqueta" (chip) debajo.
4. Repite para cada valor.
5. Para quitar uno, pulsa la **×** encima del chip.

## Campos de fecha

Los campos de fecha se rellenan con un **calendario**:

1. Pulsa sobre el icono del calendario junto al campo.
2. Elige el día en el calendario que se abre.
3. La fecha aparece en formato `AAAA-MM-DD` (por ejemplo, `2026-03-15`).

## Filtro por laboratorio

En el navegador de buckets (tanto al copiar como en el Tag Manager) verás un campo **"Filter by lab…"**. Te ayuda a encontrar tus buckets si tienes acceso a muchos:

- Escribe el **nombre del laboratorio** o su **acrónimo** (por ejemplo, `ccl` o `Batlle`).
- Aparecen sugerencias; selecciona una para ver solo los buckets de ese laboratorio.
- Para quitar el filtro, pulsa la **×** del campo.

El filtro solo aparece en la **lista de buckets** (la raíz). Al entrar dentro de un bucket desaparece, porque dentro de un bucket ya no se filtra por laboratorio. Al volver a la raíz reaparece.

## Acrónimos de laboratorio

El campo **Owner** del perfil Histopathology y el filtro por laboratorio usan una lista de **acrónimos** de los laboratorios del IRB. Cada acrónimo corresponde a un investigador principal. Por ejemplo:

| Acrónimo | Laboratorio |
|---|---|
| ccl | Eduard Batlle |
| bbg | Nuria López-Bigas |
| gccm | Roger Gomis |
| cdl | Cayetano González |
| lmb | Xavier Salvatella |
| sccl | Angel R. Nebreda |
| gtl | Lluis Ribas |
| pnacmm | Miquel Coll |
| … | … |

La lista completa aparece en el desplegable **Owner** y en las sugerencias del filtro. Estos acrónimos deben coincidir con el identificador que tenga tu bucket en MinIO; si tu laboratorio no aparece, contacta con ITS.

## Por qué importan los metadatos

- **Para encontrar los datos después:** un fichero bien etiquetado se puede localizar por proyecto, por grupo, por tipo de muestra, etc. Un fichero sin etiquetar es prácticamente invisible.
- **Para saber de qué son:** las etiquetas explican el contenido sin tener que abrirlo.
- **Para compartir:** si varias personas acceden al mismo bucket, las etiquetas indican a quién pertenece cada cosa.
- **Para cumplir con las buenas prácticas de gestión de datos del IRB.**

Rellena siempre los metadatos con cuidado, aunque parezca un esfuerzo extra. Ahorra tiempo a futuro.

## Dónde se ven los metadatos

- En **BIFrost Transfer** → Tag Manager: al seleccionar un fichero, ves sus etiquetas actuales y puedes editarlas (ver `tag-manager.md`).
- En MinIO directamente (si accedes por consola web u otra herramienta) aparecerán como **tags** del objeto.
