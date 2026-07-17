# Instalación de BIFROST

BIFROST se instala como un programa normal en Windows y en Mac. No hace falta instalar nada más a mano: los componentes internos que necesita (como la herramienta `rclone` que copia los datos) ya vienen incluidos en el instalador.

## Requisitos

- **Equipo con Windows 10/11 o macOS.**
- **Conexión a la VPN del IRB (Nexica / Forticlient)** activa durante el uso.
- Tu usuario y contraseña del IRB.
- Permisos de administrador para instalar (igual que cualquier otro programa).

## Instalación en Windows

1. Descarga el instalador de la aplicación que necesites desde la página de releases del repositorio interno del IRB. El fichero se llama:
   - `bifrost-transfer-<rama>-windows.exe` para BIFrost Transfer.
   - `bifrost-mount-<rama>-windows.exe` para BIFrost Mount.

   Donde `<rama>` suele ser `main` o `develop`. Para uso normal elige la versión `main`.
2. Haz doble clic en el `.exe` descargado.
3. Si Windows muestra una advertencia de "Protección de Windows" o "Archivo no firmado habitualmente", confirma que quieres ejecutarlo. Los instaladores del IRB van firmados; si aun así aparece el aviso, elige **Más información → Ejecutar de todas formas**.
4. Sigue los pasos del asistente (siguiente, siguiente, instalar). Puedes dejar todas las opciones por defecto.
5. Al terminar puedes marcar "Launch Bifrost" para abrir la aplicación. También encontrarás el icono en el menú Inicio y, si lo dejaste marcado, en el escritorio.

### BIFrost Mount en Windows: WinFsp

BIFrost Mount necesita un componente del sistema llamado **WinFsp** para poder mostrar tus carpetas de MinIO como una unidad. WinFsp **no viene incluido** en el instalador porque contiene un driver del sistema.

- **Si ya tienes WinFsp instalado**, BIFrost Mount funcionará directamente.
- **Si no lo tienes**, la propia aplicación te avisará la primera vez que intentes montar una carpeta y te ofrecerá descargarlo e instalarlo automáticamente. Solo tienes que aceptar y dar permisos de administrador cuando lo pida.
- Si prefieres instalarlo tú a mano, puedes descargarlo desde [winfsp.dev](https://winfsp.dev) y seguir su instalador.

## Instalación en macOS

1. Descarga el instalador de la aplicación desde la página de releases interna del IRB. El fichero se llama:
   - `bifrost-transfer-macos.dmg` para BIFrost Transfer.
   - `bifrost-mount-macos.dmg` para BIFrost Mount.
2. Haz doble clic en el `.dmg` descargado.
3. En la ventana que se abre, arrastra el icono de BIFrost a la carpeta **Aplicaciones**.
4. Cierra la ventana del DMG y expúlsalo (botón derecho sobre el icono del DMG en el Finder → Expulsar).
5. Abre la carpeta **Aplicaciones** y haz doble clic en BIFrost para arrancarla.

### La primera vez en macOS

La primera vez que abres una app descargada fuera de la Mac App Store, macOS puede mostrar "No se puede abrir BIFrost porque proviene de un desarrollador no identificado". Para abrirlo:

1. Abre **Preferencias del Sistema → Seguridad y privacidad**.
2. Abajo verás un mensaje que dice que BIFrost se bloqueó. Pulsa **Abrir de todas formas**.
3. Confirma en el diálogo que aparece.

O bien: haz clic derecho sobre BIFrost en Aplicaciones → **Abrir** → **Abrir** en el diálogo.

En macOS **no hace falta instalar nada extra** para BIFrost Mount: el componente `fuse-t` que necesita ya viene dentro de la aplicación.

## Actualizaciones

Cuando sale una versión nueva, la aplicación te avisará al arrancarla con un mensaje tipo **"New version available: X"** y dos botones:

- **Update now** — descarga e instala la nueva versión y reinicia la app. En Windows puede pedir permisos de administrador para reemplazar el programa.
- **Continue anyway** — sigue usando la versión actual. Te volverá a avisar en próximos arranques.

Recomendamos aceptar las actualizaciones para tener las mejoras y correcciones.

## Desinstalación

- **Windows**: Ajustes → Aplicaciones → Bifrost-<app> → Desinstalar. O usa "Agregar o quitar programas".
- **macOS**: Arrastra BIFrost desde Aplicaciones a la Papelera. Para limpiar del todo, puedes borrar también la carpeta `~/bifrost-logs/` (transfer) o `~/bifrost-mount-logs/` (mount) si no quieres conservar los logs.

## ¿No sabes cuál instalar?

- Si lo que quieres es **subir datos** a MinIO (copiarlos desde tu equipo o desde una unidad de red al almacenamiento) → instala **BIFrost Transfer**.
- Si lo que quieres es **trabajar con datos que ya están en MinIO** como si estuvieran en una carpeta local (abrirlos, editarlos, guardarlos desde tus programas) → instala **BIFrost Mount**.
- Puedes tener las dos instaladas a la vez; no interfieren entre sí.
