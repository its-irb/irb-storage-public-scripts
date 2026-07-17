# BIFrost Mount — Montar tus carpetas de MinIO

BIFrost Mount te permite ver tus carpetas de MinIO como si fueran una unidad más de tu equipo (un disco en Windows o una carpeta en Mac). Así puedes abrir y leer tus ficheros de MinIO directamente desde cualquier programa, sin tener que copiarlos antes a tu escritorio.

> **Solo lectura:** BIFrost Mount es **solo para lectura**. Puedes abrir, visualizar y procesar los ficheros, pero **no puedes modificar los ficheros existentes ni copiar ficheros nuevos** a través de la unidad montada. Para subir datos nuevos o actualizar ficheros en MinIO usa **BIFrost Transfer**.

## Cuándo usarlo

- Para abrir ficheros grandes que están en MinIO directamente desde tu programa (Excel, ImageJ, un visor de imágenes, etc.) sin descargarlos antes.
- Para explorar tus carpetas con el Finder o el Explorador de archivos.
- Para leer resultados o datos de MinIO desde un script o un programa sin tener que descargarlos primero.

> Si necesitas **guardar resultados** o **actualizar ficheros** en MinIO, usa **BIFrost Transfer**. BIFrost Mount no permite escritura.

> **Nota:** Montar no copia los datos a tu equipo. Los ficheros siguen en MinIO; el equipo los lee a través de la conexión. Necesitas VPN activa todo el rato. Para dejar una copia permanente en tu equipo usa **BIFrost Transfer** (que sí copia los datos).

## Abrir la aplicación

1. Conéctate a la VPN del IRB (Nexica / Forticlient).
2. Abre **BIFrost Mount** desde el menú Inicio (Windows) o desde Aplicaciones (Mac).
3. Al arrancar, la app comprueba si hay actualizaciones. Puedes actualizar o pulsar **Continue anyway** para seguir.

## Iniciar sesión

1. Escribe tu **usuario** y **contraseña** del IRB y pulsa **Entrar**.
   - El usuario es el mismo que usas en tu equipo del IRB.
   - La contraseña es la misma que usas para entrar en el correo o el portal del personal.
2. La app valida tu usuario contra el directorio del IRB. Si falla, revisa usuario/contraseña y que la VPN esté activa.

> En algunas máquinas sin acceso al directorio del IRB (por ejemplo, IVIS), el login salta la validación y muestra el aviso `DESKTOP (NO LDAP)`. Aunque en ese caso no se comprueba la contraseña contra el directorio, sigue siendo necesaria para acceder a MinIO.

## Elegir el servidor de MinIO

Tras iniciar sesión verás la lista de servidores de MinIO disponibles (por ejemplo `minio`, `minio-archive`, `irbminio`). Elige el que contenga tus datos y pulsa **Continuar**.

Si no sabes cuál elegir, pregunta a ITS o al responsable de tu laboratorio.

## Credenciales (automático)

La aplicación obtiene unas credenciales temporales para acceder a MinIO en tu nombre. Este paso es automático:

- Si tus credenciales siguen siendo válidas (más de 3 días), la app va directa a la pantalla de montaje.
- Si faltan menos de 3 días o no existen, renueva automáticamente las credenciales por 7 días y muestra el progreso.

No tienes que hacer nada en esta pantalla; espera a que termine.

## Montar una carpeta

1. En la pantalla principal verás un **navegador de carpetas** con tus buckets y subcarpetas de MinIO.
2. Navega hasta la carpeta que quieres montar.
3. Pulsa el botón **Montar**.
4. La aplicación asigna una letra de unidad (en Windows, por ejemplo `Z:`) o un punto de montaje (en Mac) a esa carpeta.

Una vez montado, puedes abrir esa unidad desde el Explorador de archivos (Windows) o desde el Finder (Mac) como cualquier otra carpeta y **leer** los ficheros. Recuerda que es **solo lectura**: no puedes guardar cambios, crear ficheros nuevos ni borrar nada desde la unidad montada (para eso usa BIFrost Transfer).

### En Windows: ¿pide instalar WinFsp?

Si es la primera vez que montas algo y no tienes **WinFsp** instalado, la app te avisará y te ofrecerá instalarlo automáticamente:

1. Acepta el aviso.
2. Se descargará el instalador oficial de WinFsp desde internet.
3. Confirma el permiso de administrador cuando lo pida Windows.
4. Cuando termine, vuelve a pulsar **Montar**.

Solo tienes que hacer esto una vez. Para más detalle ver `instalacion.md` § "BIFrost Mount en Windows: WinFsp".

## Desmontar

Cuando hayas terminado, desmonta la carpeta para liberar la unidad:

- Pulsa el botón **Desmontar** junto a la carpeta montada, o
- Usa la opción de desmontar todo antes de cerrar la aplicación.

Si cierras BIFrost Mount sin desmontar, las unidades se desmontan automáticamente al cerrar.

## Cerrar la aplicación

Cierra la ventana normalmente. Al cerrar, BIFrost Mount desmonta todas las carpetas que tengas montadas y limpia su estado.

## Cosas a tener en cuenta

- **Solo lectura:** la unidad montada es **solo para lectura**. No puedes modificar ficheros existentes, guardar cambios, copiar ficheros nuevos ni borrar nada desde la unidad. Para subir o actualizar datos en MinIO usa **BIFrost Transfer**.
- **Velocidad:** trabajar con ficheros montados es más lento que con ficheros locales, porque cada lectura viaja por la red hasta MinIO. Para tareas intensivas (procesar muchos datos, abrir ficheros muy grandes repetidamente) suele ser mejor **copiar** los datos a tu equipo con BIFrost Transfer, trabajar en local, y luego subir el resultado.
- **VPN:** si pierdes la VPN mientras tienes una carpeta montada, la unidad puede dejar de responder. Reconecta la VPN; si no se recupera, desmonta y vuelve a montar.
- **No es una copia de seguridad:** montar no guarda una copia en tu equipo; los ficheros siguen en MinIO.
- **Una carpeta a la vez:** monta solo las carpetas que vayas a usar y desmonta cuando termines.

## Resumen rápido

```
VPN → abrir BIFrost Mount → usuario/contraseña →
elegir servidor → (credenciales automáticas) →
navegar a la carpeta → Montar → usar la unidad → Desmontar al terminar
```
