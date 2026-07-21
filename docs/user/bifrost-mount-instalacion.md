# Instalar bifrost-mount

Esta guía cubre la instalación de **bifrost-mount**, la aplicación que
monta carpetas de MinIO S3 como unidades locales para explorarlas y abrir
ficheros sin descargarlos previamente.

## Antes de instalar: comprueba si ya lo tienes

El departamento de ITS ha realizado una instalación remota masiva de
bifrost-mount en los ordenadores de los usuarios de Windows y macOS. Es muy
probable que ya lo tengas instalado.

- **Windows**: abre el Menú de Inicio y busca "Bifrost-mount".
- **macOS**: busca en Launchpad o en la carpeta Aplicaciones.

Si ya aparece, no reinstales — ábrela directamente.

## Para qué sirve bifrost-mount

Bifrost-mount monta buckets de MinIO S3 como carpetas locales de **solo
lectura**. Permite:

- **Explorar buckets sin descargarlos**: navega por los datos S3 con el
  Finder o el Explorador de archivos como si fueran carpetas locales.
- **Abrir ficheros S3 directamente** en aplicaciones como ImageJ, Fiji u
  otros sin copiarlos antes al disco.
- **Inspeccionar el resultado de una transferencia** realizada con
  bifrost-transfer.
- **Consumir datos S3 desde scripts o CLI** que esperan rutas locales; el
  mount aparece como una carpeta normal.

**Bifrost-mount es de solo lectura por diseño.** Esto evita problemas de
buffer y asegura que no se pierdan datos. Para subir, modificar o borrar
datos en MinIO S3, utiliza **bifrost-transfer**.

## Requisitos previos

- **VPN de Nexica (Forticlient)** activa. Sin ella no se puede acceder a
  los servidores MinIO del IRB.
- **Windows**: [WinFsp](https://winfsp.dev) debe estar instalado. ITS lo
  instala junto con bifrost-mount, así que normalmente ya lo tienes. Si
  falta, la app lo detecta al intentar montar y ofrece descargarlo e
  instalarlo automáticamente (requiere permisos de administrador).
- **macOS**: el framework fuse-t va embebido en la aplicación — no hace
  falta instalarlo.

## Instalación

Si tras comprobar lo anterior no tienes bifrost-mount, descarga el binario
desde
[GitHub Releases](https://github.com/its-irb/irb-storage-public-scripts/releases):

- **Windows**: descarga el archivo `.exe` (instalador Inno Setup) y
  ejecútalo.
- **macOS**: descarga el archivo `.dmg`, ábrelo y arrastra la aplicación a
  Aplicaciones.
- **Linux**: *pendiente de completar.* No se ha confirmado si el binario
  Linux se distribuye a usuarios finales.

## Actualizaciones

Cuando hay una release nueva en GitHub, la app pregunta al usuario al
iniciar si quiere actualizarse y descarga el binario nuevo automáticamente.
No es necesario desinstalar la versión anterior.
