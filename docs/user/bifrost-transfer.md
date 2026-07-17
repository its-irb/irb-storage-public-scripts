# BIFrost Transfer — Subir datos a MinIO

BIFrost Transfer te permite copiar carpetas o ficheros desde tu equipo (o desde una unidad de red) a tu espacio en MinIO, comprobando que los datos llegan íntegros y etiquetándolos para que luego se puedan identificar y encontrar.

## Cuándo usarlo

- Para **subir datos nuevos** a MinIO (resultados de un experimento, imágenes, ficheros de un proyecto).
- Para **dejar una copia** de datos en el almacenamiento del IRB.
- Para **etiquetar** lo que subes con información útil (proyecto, tipo de muestra, etc.).

> Si lo que quieres es abrir ficheros que ya están en MinIO como si fueran locales, usa **BIFrost Mount**. Si lo que quieres es **corregir etiquetas** de datos ya subidos, usa el **Tag Manager** (incluido en BIFrost Transfer).

## Abrir la aplicación

1. Conéctate a la VPN del IRB (Nexica / Forticlient).
2. Abre **BIFrost Transfer** desde el menú Inicio (Windows) o desde Aplicaciones (Mac).
3. Al arrancar, la app comprueba si hay actualizaciones. Puedes actualizar o pulsar **Continue anyway**.

## Iniciar sesión

1. Escribe tu **usuario** y **contraseña** del IRB y pulsa **Entrar**.
2. La app valida tu usuario contra el directorio del IRB.

> En algunas máquinas sin acceso al directorio del IRB (por ejemplo, IVIS), el login salta la validación y muestra `DESKTOP (NO LDAP)`. Sigue haciendo falta usuario y contraseña para acceder a MinIO.

## Elegir el servidor de MinIO

Tras iniciar sesión verás la lista de servidores de MinIO disponibles (por ejemplo `minio`, `minio-archive`, `irbminio`). Elige el que corresponda a tus datos y pulsa **Continuar**.

Si no sabes cuál elegir, pregunta a ITS o a tu laboratorio.

## Credenciales (automático)

La aplicación obtiene unas credenciales temporales para acceder a MinIO en tu nombre. Es automático:

- Si siguen siendo válidas (más de 3 días), va directa a la pantalla de copia.
- Si faltan menos de 3 días o no existen, renueva automáticamente por 7 días mostrando el progreso.

No tienes que hacer nada; espera a que termine.

## Pantalla de copia

Esta es la pantalla principal, dividida en varias zonas:

1. **Origen** — qué quieres copiar.
2. **Destino** — dónde guardarlo en MinIO.
3. **Metadatos** — etiquetas que describen los datos (solo aparece tras elegir destino).
4. **Botones de copia y verificación** (aparecen tras elegir destino).
5. **Log** — mensaje de progreso en vivo (aparece tras elegir destino).

Hasta que no elijas un bucket de destino, las zonas de metadatos, botones y log estarán ocultas.

### Elegir el origen (qué copiar)

Puedes elegir entre:

- **Carpeta local** — una carpeta de tu equipo. Pulsa el botón de explorar y navega hasta ella.
- **Unidad de red (CIFS/SMB)** — una carpeta compartida del IRB a la que tengas acceso (por ejemplo, una unidad de red del laboratorio). En el modo escritorio aparecerán las unidades disponibles.

Puedes seleccionar una carpeta (se copia todo su contenido) o ficheros sueltos.

### Elegir el destino (dónde guardarlo)

1. En el navegador de carpetas de la derecha verás tus **buckets** de MinIO.
2. **Filtro por laboratorio:** arriba del navegador hay un campo **"Filter by lab…"**. Si escribes el nombre o acrónimo de un laboratorio, la lista de buckets se reduce a los de ese laboratorio. Útil si tienes acceso a muchos buckets.
   - El filtro solo aparece en la raíz (lista de buckets). Al entrar dentro de un bucket desaparece; al volver a la raíz reaparece.
3. Navega hasta la carpeta destino dentro del bucket. Puedes crear subcarpetas escribiendo el nombre en el navegador.
4. En cuanto seleccionas un bucket o carpeta, aparecerán las zonas de **Metadatos**, **botones** y **Log** que antes estaban ocultas.

### Rellenar los metadatos

Antes de copiar, la app te pide etiquetar los datos con un **perfil**. Elige el perfil que encaje con tus datos en el desplegable de arriba:

- **IRB Standard** — metadatos generales (proyecto, máquina, tipo de muestra, etc.).
- **Histopathology** — metadatos específicos para datos de histopatología (propietario, especie, instrumento, etc.).

El detalle de cada campo está en `metadatos-perfiles.md`. Cambiar de perfil borra los campos rellenos (te pedirá confirmación si ya habías escrito algo).

Estas etiquetas se guardan en MinIO junto con los ficheros y sirven para identificarlos y buscarlos después. Rellénalos con cuidado.

### Copiar

1. Cuando tengas origen, destino y metadatos, pulsa **Copy**.
2. La app lanza la copia y muestra el progreso en el **Log** en vivo.
3. La copia usa verificación de integridad (checksum): comprueba que los datos llegan exactos.
4. Durante la copia:
   - **Cancelar** — detiene el proceso. Lo que ya se haya copiado se queda en MinIO.
5. Al terminar verás **✅ Copy completed successfully.** o un mensaje de error.

### Verificar (opcional)

Tras copiar, puedes pulsar **Check** para verificar que todos los ficheros del destino coinciden con el origen. Es una comprobación extra de integridad.

## Log y dónde encontrarlo

Mientras se copia, el **Log** muestra el progreso línea a línea. Al terminar, la app guarda automáticamente una copia completa del log en tu equipo:

- **Windows y Mac:** en `~/bifrost-logs/` (es decir, dentro de tu carpeta de usuario, en `bifrost-logs`).
- El fichero se llama `bifrost-YYYY-MM-DD_HH-MM-SS.log`.

Si algo falla y necesitas pedir ayuda, puedes enviar ese fichero de log a ITS; ahí está toda la información de qué pasó.

## Cerrar la aplicación

Cierra la ventana normalmente. Si tienes unidades de red montadas (modo cluster), se desmontan al cerrar.

## Buenas prácticas

- **Elige bien el destino:** dentro de MinIO no es trivial mover datos entre buckets. Antes de copiar, asegúrate de estar en el bucket y carpeta correctos.
- **Rellena bien los metadatos:** son la única forma de identificar y buscar los datos después. Un proyecto bien etiquetado se encuentra; uno sin etiquetar, no.
- **Usa el filtro por laboratorio** si tienes muchos buckets: te ahorrará buscar.
- **Verifica tras copiar** datos críticos: el botón Check confirma que todo llegó íntegro.
- **No cierres la app a mitad de copia:** si necesitas parar, usa **Cancelar** y espera a que termine de forma limpia.

## Resumen rápido

```
VPN → abrir BIFrost Transfer → usuario/contraseña →
elegir servidor → (credenciales automáticas) →
elegir origen → elegir bucket destino (y carpeta) →
elegir perfil y rellenar metadatos → Copy →
esperar al ✅ → (opcional) Check
```

Para corregir etiquetas de datos ya subidos sin volver a copiarlos, usa el **Tag Manager** (ver `tag-manager.md`).
