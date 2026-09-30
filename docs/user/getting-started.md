# Instalación y primeros pasos

## Requisitos previos

- **VPN de Nexica (Forticlient)** activa. Sin ella, BIFROST no puede
  conectarse a LDAP ni a MinIO.
- **Cuenta de usuario del IRB**: tu usuario y contraseña habituales (LDAP).
- **Windows + bifrost-mount**: el sistema necesita **WinFsp** (driver de
  montaje). No se puede empaquetar dentro de la app porque incluye un driver
  de kernel, por lo que:
  - la app detecta que falta al montar y **ofrece descargar e instalar** la
    última versión oficial desde `github.com/winfsp/winfsp` (requiere permisos
    de administrador), o
  - puedes instalarlo manualmente desde `winfsp.dev`.

**No necesitas** instalar `rclone` ni `fuse-t`: viajan empaquetados dentro de
la aplicación.

## Obtener e instalar la aplicación

Las versiones se publican en las **releases de GitHub** del repositorio
`its-irb/irb-storage-public-scripts` (cada release lleva la etiqueta
`v1.0.<número de build>`).

- **Windows**: descarga el instalador `.exe`
  (`bifrost-<app>-<rama>-windows.exe`, **firmado digitalmente**) e instálalo.
  Si Windows muestra una advertencia, comprueba que el archivo procede de la
  release de GitHub del repositorio oficial.
- **macOS**: descarga el archivo **`.dmg`** (`bifrost-<app>-macos.dmg`),
  ábrelo y copia la app a la carpeta Aplicaciones.
- **Linux / clúster**: bifrost-transfer se sirve en modo web a través de Open
  OnDemand (ver [web-mode-ood.md](web-mode-ood.md)); no hay que instalar nada
  local.

Una vez instalada, la aplicación se **auto-actualiza**: al abrir la app, si
existe una versión nueva en GitHub, te pregunta si quieres actualizarla y
descarga la release correspondiente.

## Primeros pasos

1. **Inicia sesión** con tu usuario y contraseña LDAP.
   - Si tu máquina no tiene acceso a LDAP pero sí a MinIO (p. ej. IVIS), se
     usa la variable `BIFROST_NO_LDAP=1` para saltar la validación LDAP; en ese
     caso igualmente introduces usuario y contraseña porque se necesitan para
     obtener credenciales temporales (STS). Ver [troubleshooting.md](troubleshooting.md).
2. **Selecciona el servidor MinIO** que corresponde a tu grupo de trabajo.
3. **Credenciales temporales**: la app obtiene credenciales STS
   automáticamente (por defecto con una vida de varios días). No necesitas
   introducir claves; si están por expirarse, se renuevan solas mostrando un
   progreso.
4. **Elige la vista final** según tu objetivo:
   - `bifrost-transfer` → pantalla de **copia** (ver [transfer-data.md](transfer-data.md)).
   - `bifrost-mount` → pantalla de **montado** (ver [mount-buckets.md](mount-buckets.md)).

## Opciones al iniciar (para desarrolladores)

```bash
flet run                # ejecución normal
flet run --customuser   # iniciar sesión con un usuario distinto al del sistema
flet run --update       # forzar la comprobación de auto-actualización
flet run --web          # (solo transfer) modo web para desarrollo local
```

## Resultado esperado

Tras el login deberías ver, en `bifrost-transfer`, la pantalla de copia con el
navegador de destino; en `bifrost-mount`, la pantalla de montado. Si en su
lugar ves un error de red o de login, consulta
[troubleshooting.md](troubleshooting.md).
