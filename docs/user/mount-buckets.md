# Montar un bucket como unidad local (bifrost-mount)

Objetivo: abrir una carpeta de un bucket de MinIO **como si fuera una unidad
local** del equipo, para poder trabajar con los archivos con el explorador o
con otras herramientas.

## Cuándo usarlo

- Necesitas **acceder directamente** a los archivos de un bucket, sin subir ni
  bajar nada.
- Quieres **abrir, editar o mover** archivos dentro de MinIO como si estuvieran
  en un disco.
- No necesitas aplicar metadatos (para eso, usa bifrost-transfer).

> bifrost-mount **solo funciona en modo escritorio** (Windows, macOS, Linux).
> No está disponible en el modo web del clúster.

## Antes de empezar

- VPN de Nexica activa y login completado.
- **Windows**: el sistema debe tener **WinFsp** instalado. Si falta, la app te
  lo avisa y ofrece instalarlo (requiere permisos de administrador).

## Requisitos específicos por sistema

- **Windows**: necesita **WinFsp** (driver de montaje). No se empaqueta dentro
  de la app porque incluye un driver de kernel.
  - **Automático**: al montar, si falta WinFsp, la app detecta su ausencia y
    **ofrece descargar e instalar** la última versión oficial desde
    `github.com/winfsp/winfsp` (requiere UAC/administrador; el instalador se
    cachea en la carpeta temporal).
  - **Manual**: también puedes instalarlo tú desde `winfsp.dev`.
- **macOS**: usa el framework `fuse-t`, que ya está empaquetado dentro de la
  app; no necesitas instalar nada.
- **Linux**: montaje vía FUSE del sistema.

## Cómo funciona

1. Entra a **bifrost-mount** y **inicia sesión**.
2. **Selecciona el servidor MinIO** correspondiente a tu grupo.
3. Las **credenciales STS** se obtienen/renuevan automáticamente (igual que en
   bifrost-transfer).
4. En la pantalla de **montado**, navega hasta la **carpeta del bucket** que
   quieres montar.
5. Pulsa **Montar**. La app asigna una **unidad/punto de montaje** y la
   carpeta del bucket queda disponible como directorio local.

## Resultado esperado

- Aparece una **nueva unidad** (en Windows, una letra; en macOS/Linux, un punto
  de montaje) que refleja el contenido de la carpeta del bucket.
- Puedes **abrir, copiar, mover o editar** archivos a través de ella.
- Los cambios que hagas se reflejan en MinIO.

## Desmontar

Cuando termines, **desmonta** la unidad para liberar el recurso. La app permite
desmontar la unidad seleccionada o desmontar todos los shares montados a la
vez.

## Limitaciones

- **Solo modo escritorio**: no está disponible en el modo web de Open
  OnDemand.
- El rendimiento al **listar** carpetas grandes de MinIO puede ser lento
  (MinIO sobre discos HDD tarda más en listar); si notas lentitud, considera
  usar bifrost-transfer para copiar en bloque y trabajar en local.
- En **Windows** el montado depende de que WinFsp esté presente y funcional.

## Ante errores

- **Windows: no se monta / error de driver**: asegúrate de que **WinFsp** está
  instalado (acepta la instalación automática de la app o instala manualmente
  desde `winfsp.dev`).
- **No conecta**: comprueba la **VPN de Nexica**.
- **No ves el bucket**: revisa que tienes **acceso** a ese bucket.
