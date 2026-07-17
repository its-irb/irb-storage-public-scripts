# Guías de uso — BIFROST

BIFROST son dos aplicaciones para guardar y consultar datos en el almacenamiento MinIO S3 del IRB Barcelona. No hacen falta conocimientos técnicos para usarlas: se instalan como un programa normal y se manejan con ventanas y botones.

| Aplicación | Para qué sirve |
|---|---|
| **BIFrost Transfer** | Subir carpetas o ficheros desde tu equipo (o desde una unidad de red) a tu espacio en MinIO, comprobando que los datos lleguen íntegros y etiquetándolos para que luego se puedan encontrar. Incluye un **Tag Manager** para revisar y corregir las etiquetas sin tener que volver a subir nada. |
| **BIFrost Mount** | Ver tus carpetas de MinIO como si fueran una unidad más del equipo (un disco o carpeta), para abrir y leer ficheros directamente desde cualquier programa. La unidad es **solo lectura**: para subir o modificar datos usa BIFrost Transfer. |

## Dónde encontrar cada guía

| Guía | Qué explica |
|---|---|
| `instalacion.md` | Cómo instalar las dos aplicaciones en Windows y en Mac |
| `bifrost-mount.md` | Cómo montar y desmontar tus carpetas de MinIO como unidad local |
| `bifrost-transfer.md` | Cómo subir datos a MinIO desde tu equipo o desde una unidad de red |
| `bifrost-transfer-web.md` | Cómo usar BIFrost Transfer desde el navegador (cluster Linux / Open OnDemand) |
| `tag-manager.md` | Cómo revisar y editar las etiquetas de ficheros y carpetas ya subidos |
| `metadatos-perfiles.md` | Qué información pide la app al subir (perfiles IRB Standard e Histopathology) y qué significa cada campo |
| `resolucion-problemas.md` | Soluciones a los problemas más habituales (VPN, instalación, actualizaciones, etc.) |

## Antes de empezar

Para usar cualquiera de las dos aplicaciones necesitas:

1. **Estar conectado a la VPN del IRB (Nexica / Forticlient).** Sin VPN la aplicación no puede llegar al almacenamiento ni validar tu usuario.
2. **Tu usuario y contraseña del IRB** (los mismos que usas en tu equipo o en el portal del personal). La app los usa para identificarte ante el almacenamiento.
3. **Permiso de acceso a algún bucket de MinIO.** Si no tienes buckets asignados, contacta con el servicio de ITS.

## En una frase

- **Transfer**: eliges qué quieres subir, eliges dónde guardarlo en MinIO, rellenas unas etiquetas y le das a copiar. La app verifica que todo llega bien.
- **Mount**: eliges una carpeta de MinIO y le dices "montar". A partir de ese momento la ves como una unidad más del equipo (solo lectura) hasta que la desmontes.

Para detalles, abre la guía específica de la aplicación que quieres usar.
