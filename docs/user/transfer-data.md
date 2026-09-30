# Subir datos a un bucket (bifrost-transfer)

Objetivo: copiar archivos desde tu equipo, una carpeta de red (SMB/CIFS) o un
servidor SFTP hasta un bucket de MinIO, verificando la integridad de la copia
y aplicando metadatos (tags) según un perfil.

## Cuándo usarlo

- Necesitas **subir datos** a MinIO (la operación principal).
- Quieres que los objetos subidos lleven **metadatos gestionados** por
  laboratorio.
- Necesitas **comprobar la integridad** de una copia ya realizada.

## Antes de empezar

- VPN de Nexica activa y login completado (ver [getting-started.md](getting-started.md)).
- Ya estás en la pantalla de **copia** (`view_copy`), tras elegir el servidor MinIO.
- Ten claro:
  - **Origen**: de dónde salen los datos (carpeta local, share SMB o servidor SFTP).
  - **Destino**: el bucket y la ruta dentro de MinIO.
  - **Perfil de metadatos**: qué tipo de datos son (IRB Standard, Histopathology, …).

## Origen disponible

Puedes elegir como origen:

- **Carpetas de red (SMB/CIFS)**: las shares accesibles que la app detecta.
- **Carpeta local** del equipo.
- **Servidor SFTP**: pulsa el botón **"🌐 SFTP"** para conectarte. El diálogo
  de conexión solo exige **host** y **usuario** (la **contraseña es
  opcional**, porque algunas cuentas SFTP no la tienen). Podrás navegar y
  elegir como origen **una carpeta o un archivo individual**.

> Nota: el origen SFTP es efímero. La app crea un perfil rclone temporal para
> la sesión y lo borra al terminar (al cerrar la conexión, al salir de la
> pantalla de copia y al volver a iniciar sesión), por lo que no quedan
> perfiles SFTP huérfanos en tu máquina.

## Destino

El navegador de destino te permite recorrer **buckets → carpetas** dentro de
MinIO.

- En la **raíz** (nivel de buckets) aparece el campo **"Filter by lab…"**:
  escribe el nombre o acrónimo de un laboratorio para ver sugerencias y
  filtrar solo los buckets de ese lab. Este filtro se oculta al entrar dentro
  de un bucket y vuelve a aparecer al volver a la raíz.
- Los botones de copia/verificación, la sección de metadatos y el panel de log
  **solo aparecen una vez que has seleccionado un bucket** destino en el
  navegador.

## Perfiles de metadatos

Los metadatos se organizan en **perfiles**. En la parte superior de la sección
**METADATA** eliges el perfil con un desplegable. Los perfiles disponibles:

- **IRB Standard** — metadatos generales: proyecto, máquina, tipo de muestra,
  tipos de datos, solicitante, grupo de investigación.
- **Histopathology** — campos especializados: propietario, usuarios, fecha,
  proveedor, instrumento, especie, tipo de muestra, aumento, canales.

Rellena los campos y los tags se aplicarán automáticamente a los objetos
subidos. **Si cambias de perfil se borran los campos actuales** (si algún
campo tiene datos, se muestra un diálogo de confirmación antes de borrarlos).

## Ejecutar la copia

1. Selecciona el **origen** (share/local/SFTP).
2. Navega al **bucket destino** y, si procede, a la carpeta.
3. Elige el **perfil de metadatos** y rellena los campos.
4. Pulsa **Copiar**. La app ejecuta `rclone copy` en segundo plano y muestra el
   progreso en el panel de log en vivo.
5. Al terminar, puedes lanzar la **verificación de integridad** (rclone
   `check`) para confirmar que origen y destino coinciden.

## Resultado esperado

- Los objetos aparecen en el bucket destino con la jerarquía de carpetas
  seleccionada.
- Llevan los **tags del perfil** rellenado.
- El log en vivo muestra el progreso y, al final, un resumen de éxito o
  error. En modo web, el log completo se guarda en el servidor
  (`~/bifrost-logs/…`).

## Limitaciones

- El filtro "Filter by lab…" solo funciona en el **nivel de buckets (raíz)**,
  no dentro de un bucket.
- El origen SFTP **no** permite crear carpetas en remoto (tiene sentido crear
  carpetas solo en el destino S3, que es virtual hasta que se copia).
- Si la copia falla a mitad, los objetos ya subidos permanecen en el destino;
  relanza la copia para reintentar (rclone no re-copia lo que ya existe y es
  idéntico).

## Ante errores

- **Error de red / no conecta**: comprueba la VPN de Nexica.
- **Permisos / no ves el bucket**: es probable que no tengas acceso; contacta
  con el responsable de datos de tu grupo.
- **Detalle del log**: en modo web, si se pierde la vista, el log completo
  está en `~/bifrost-logs/` del servidor (ver [web-mode-ood.md](web-mode-ood.md)).
