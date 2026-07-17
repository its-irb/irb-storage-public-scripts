# Tag Manager — Revisar y editar etiquetas

El **Tag Manager** es una herramienta incluida en BIFrost Transfer que te permite **ver y modificar las etiquetas** (metadatos) de ficheros y carpetas que ya están en MinIO, **sin tener que volver a subirlos**.

## Cuándo usarlo

- Para **corregir** una etiqueta mal puesta al subir datos.
- Para **añadir** etiquetas a datos que se subieron sin etiquetar.
- Para **comprobar** qué etiquetas tiene un fichero o una carpeta.
- Para **etiquetar en lote** toda una carpeta o un bucket de golpe.

> El Tag Manager no copia ni mueve datos. Solo cambia las etiquetas. Los ficheros se quedan donde están.

## Cómo abrirlo

1. Abre **BIFrost Transfer** e inicia sesión normalmente (ver `bifrost-transfer.md`).
2. Tras llegar a la pantalla de copia, pulsa el botón **Tag Manager** (suele estar junto a los botones de copia).

Se abre la pantalla del Tag Manager, con un navegador de buckets a la izquierda y el panel de etiquetas a la derecha.

## Navegar por tus datos

- El **navegador** muestra tus **buckets**, **carpetas** y **ficheros** de MinIO, igual que en la pantalla de copia.
- **Filtro por laboratorio:** arriba del navegador hay un campo **"Filter by lab…"**. Escribe el nombre o acrónimo de un laboratorio para ver solo sus buckets.
  - El filtro solo aparece en la raíz (lista de buckets). Al entrar dentro de un bucket desaparece; al volver a la raíz reaparece.
- Navega hasta el fichero o carpeta que quieres etiquetar y selecciónalo.

## Ver las etiquetas actuales

Al seleccionar un fichero o una carpeta, el panel de la derecha muestra las **etiquetas actuales** que tiene en MinIO, en forma de lista de clave/valor.

## Editar etiquetas con un perfil

Si las etiquetas del fichero encajan con uno de los perfiles conocidos (**IRB Standard** o **Histopathology**), el editor cambia automáticamente a la **vista de perfil** y rellena los campos con los valores que ya tenía el fichero. Así puedes corregirlos usando los mismos desplegables, fechas y campos que al subir datos.

- Si quieres volver a ver la lista cruda de clave/valor, pulsa **Ver tags raw**.
- Si quieres volver a la vista de perfil, pulsa el botón correspondiente.
- Si las etiquetas no encajan con ningún perfil, se queda en la vista cruda.

El detalle de los campos de cada perfil está en `metadatos-perfiles.md`.

## Cambiar de perfil

Puedes cambiar el perfil en el desplegable de arriba. Si ya habías rellenado campos y cambias de perfil, la app te pedirá confirmación antes de borrarlos.

## Aplicar etiquetas

Una vez rellenados los campos:

1. Elige a qué quieres aplicar las etiquetas:
   - **Fichero seleccionado** — solo a ese fichero.
   - **Carpeta** (todos los ficheros de la carpeta actual).
   - **Bucket o prefijo** — a todo lo que cuelga de una ruta.
2. Pulsa **Aplicar**.
3. La app actualiza las etiquetas en MinIO directamente (usa la conexión S3, no re-sube los datos).
4. Verás un mensaje de confirmación.

> **Cuidado con aplicar a un bucket o prefijo entero:** sobrescribe las etiquetas de todos los ficheros afectados. Úsalo solo cuando estés seguro de que todos esos ficheros deben llevar las mismas etiquetas.

## Buenas prácticas

- **Revisa antes de aplicar:** si vas a etiquetar una carpeta entera, abre primero un par de ficheros para ver qué etiquetas tienen y confirma que el cambio es el deseado.
- **Usa el perfil correcto:** si tus datos son de histopatología, usa el perfil Histopathology para que los campos sean los adecuados. Si son datos generales, usa IRB Standard.
- **No mezcles:** un mismo conjunto de datos debería llevar un único perfil de etiquetas. Si tienes datos de tipos muy distintos, sepáralos en carpetas distintas y etiquétalos por separado.
- **Las etiquetas ayudan a encontrar los datos:** rellena todos los campos relevantes. Un fichero bien etiquetado se puede localizar después; uno sin etiquetar, prácticamente no.

## Resumen rápido

```
Abrir BIFrost Transfer → iniciar sesión → Tag Manager →
navegar al fichero/carpeta → ver etiquetas actuales →
elegir perfil (o vista raw) → rellenar/corregir campos →
Aplicar (a fichero / carpeta / prefijo) → confirmar
```
