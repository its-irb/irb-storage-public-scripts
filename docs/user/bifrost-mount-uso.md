# Usar bifrost-mount

Esta guía explica para qué sirve bifrost-mount y cómo utilizarlo. Para
instalar la aplicación, consulta `bifrost-mount-instalacion.md`.

## Para qué sirve

Bifrost-mount monta buckets de MinIO S3 como carpetas locales de **solo
lectura**. Te permite:

- **Explorar buckets sin descargarlos** — navega por los datos S3 con el
  Finder o el Explorador de archivos como si fueran carpetas locales.
- **Abrir ficheros S3 directamente** en aplicaciones como ImageJ, Fiji u
  otras sin copiarlos antes al disco.
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
- **bifrost-mount** instalado (ver `bifrost-mount-instalacion.md`).
- **Windows**: [WinFsp](https://winfsp.dev) debe estar instalado. ITS lo
  instala junto con bifrost-mount, así que normalmente ya lo tienes. Si
  falta, la app lo detecta al intentar montar y ofrece descargarlo e
  instalarlo automáticamente (requiere permisos de administrador).

## Primer arranque

Al abrir bifrost-mount por primera vez, la app te guía por tres pasos
antes de llegar a la interfaz de montado:

1. **Autenticación LDAP** — introduce tu usuario y contraseña de red del
   IRB. Si la app no puede alcanzar la red del IRB, te avisará de que
   compruebes la VPN.
2. **Selección del servidor MinIO** — elige el servidor al que quieres
   conectarte. Un clic selecciona; un doble clic selecciona y continúa
   directamente.
3. **Renovación automática de credenciales STS** — la primera vez (o si
   tus credenciales caducan en menos de 3 días), la app solicita
   credenciales temporales de 7 días automáticamente. No tienes que hacer
   nada; verás el progreso en un log en pantalla.

Una vez completados estos pasos, llegas a la vista **Mount**, donde
puedes montar y desmontar buckets.

## Montar un bucket

1. En la vista **Mount**, verás la lista de buckets disponibles en tu
   perfil.
2. **Un clic** selecciona el bucket; el botón **Mount bucket** lo monta.
   También puedes hacer **doble clic** en un bucket para montarlo
   directamente.
3. Cuando termina, la app abre automáticamente el explorador de archivos
   (Finder en macOS, Explorador en Windows, `xdg-open` en Linux) en la
   carpeta montada.

El mount aparece en:

- **Windows**: `C:\rclone-mounts\<perfil>\<bucket>`
- **macOS / Linux**: `~/rclone-mounts/<perfil>/<bucket>`

donde `<perfil>` es el perfil rclone del servidor MinIO seleccionado y
`<bucket>` el nombre del bucket.

Los buckets ya montados se muestran con la etiqueta "mounted". Puedes
montar varios buckets a la vez.

## Trabajar con los datos montados

Una vez montado, el bucket se comporta como una carpeta local de solo
lectura:

- Navega por carpetas y ficheros con el Finder o el Explorador de
  archivos.
- Abre ficheros directamente en ImageJ, Fiji u otras aplicaciones — se
  cargan en streaming desde S3 sin copiarse al disco local.
- Usa la ruta del mount en scripts, notebooks o CLI que esperan rutas
  locales.

Las operaciones de escritura (modificar, borrar, crear ficheros) fallan
o se ignoran silenciosamente — es el comportamiento esperado. Para
modificar datos en S3, usa **bifrost-transfer**.

## Desmontar buckets

- **Unmount all** (visible solo cuando hay buckets montados) desmonta
  todos los mounts activos.
- Al **cerrar la app**, todos los mounts se desmontan automáticamente.

Si cierras la app de forma abrupta o se cae la conexión, los procesos
rclone pueden quedar colgados. La próxima vez que abras bifrost-mount,
la app detecta los mounts previos y los marca como "mounted" para que
puedas seguir usándolos o desmontarlos.

## Renovar credenciales

Las credenciales STS caducan. La app te avisa con un badge en la vista
**Mount**:

```
🔑 Credentials expire in Xd Yh
```

El color indica la urgencia:

- **Verde** — más de 3 días de validez.
- **Amarillo** — 3 días o menos.
- **Rojo** — menos de 1 día.

Para renovar manualmente:

1. Pulsa **🔑 Renew credentials**.
2. Introduce el número de días (entre 1 y 30).
3. La app solicita nuevas credenciales STS y las guarda en la
   configuración de rclone.

La renovación manual es necesaria si llevas más de 3 días sin abrir la
app o si quieres extender la validez más allá de los 7 días por defecto.

## Resolución de problemas

### "Cannot reach the IRB network. Are you connected to the VPN?"

Conecta la VPN de Nexica (Forticlient) e inténtalo de nuevo.

### "Invalid credentials. Please try again."

Verifica tu usuario y contraseña de red del IRB. Si el problema persiste,
contacta con ITS.

### "WinFsp not detected" (Windows)

WinFsp es necesario para montar carpetas S3 en Windows. La app te
ofrece descargarlo e instalarlo automáticamente (requiere permisos de
administrador). También puedes instalarlo manualmente desde
[winfsp.dev](https://winfsp.dev).

### "FUSE not detected" (Linux)

Instala FUSE:

```bash
sudo apt install fuse      # Debian/Ubuntu
sudo dnf install fuse      # Fedora/RHEL
```

### "fuse-t not detected" (macOS)

Esto no debería ocurrir en instalaciones empaquetadas, ya que fuse-t va
embebido en la app. Si aparece, reinstala bifrost-mount desde
[GitHub Releases](https://github.com/its-irb/irb-storage-public-scripts/releases).
Si persiste, contacta con ITS.

### El mount no responde o aparece vacío

- Desmonta con **Unmount all** y vuelve a montar.
- Si el proceso rclone quedó colgado, cerrar y reabrir la app debería
  limpiarlo.
- Verifica que la VPN sigue activa.

### Credenciales caducadas

Si intentas montar y falla, comprueba el badge de expiración. Si está
caducado, usa **🔑 Renew credentials** para obtener credenciales nuevas.

## Logs

La app guarda un log de cada sesión en:

- **Windows**: `C:\Users\<usuario>\bifrost-mount-logs\`
- **macOS / Linux**: `~/bifrost-mount-logs/`

Si necesitas reportar un problema a ITS, adjunta el log más reciente.

## Actualizaciones

Cuando hay una release nueva en GitHub, la app pregunta al iniciar si
quieres actualizarse y descarga el binario nuevo automáticamente. No es
necesario desinstalar la versión anterior. Para más detalle, consulta
`bifrost-mount-instalacion.md`.
