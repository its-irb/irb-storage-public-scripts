# Resolución de problemas

Guía de los problemas más habituales y cómo recuperarse de ellos.

## No conecta / errores de red

**Síntoma**: la app no llega al login o falla al seleccionar el servidor MinIO.

- **Comprueba la VPN de Nexica (Forticlient)**: debe estar activa y
  conectada. BIFROST no funciona sin ella.
- Si usas el modo web en el clúster, asegúrate de estar en la red del clúster
  y con el acceso OOD correcto.
- Reinicia la app después de reconectar la VPN.

## Problemas de login (LDAP)

**Síntoma**: error al iniciar sesión.

- Confirma que el **usuario y la contraseña** son correctos (son tus credenciales
  LDAP del IRB).
- **Máquinas sin acceso a LDAP pero con acceso a MinIO** (p. ej. IVIS): se usa
  la variable de entorno `BIFROST_NO_LDAP=1` para saltar la validación LDAP.
   - En Windows, defínela como **variable de sistema** para que aplique a
     todos los usuarios:

     ```powershell
     setx BIFROST_NO_LDAP 1 /M
     ```
  - Con esta variable, **sigues introduciendo usuario y contraseña** (se
    necesitan para obtener las credenciales STS), pero no se valida contra
    LDAP. El badge del encabezado mostrará `DESKTOP (NO LDAP)`.

## No veo el servidor MinIO o el bucket que espero

- Es probable que **no tengas acceso** a ese servidor o bucket. Contacta con el
  responsable de datos de tu grupo de trabajo para que te otorgue permisos.
- Revisa que has iniciado sesión con el **usuario correcto**.

## bifrost-mount: el montaje falla (Windows)

**Síntoma**: al montar, aparece un error o la unidad no aparece.

- En **Windows** necesitas **WinFsp**. Si falta:
  - Acepta la **instalación automática** que la app ofrece al detectar la
    ausencia (requiere permisos de administrador; descarga la última versión
    oficial).
  - O instálalo **manualmente** desde `winfsp.dev`.
- Tras instalar WinFsp, reintenta el montaje.

## La copia es lenta o el listado tarda

- El **listado de MinIO sobre discos HDD** es lento. En lugar de navegar
  carpeta a carpeta en el destino, considera:
  - usar el campo **"Filter by lab…"** (en la raíz de buckets) para ir directo al bucket de tu laboratorio, y
  - para mover grandes volúmenes, usar **bifrost-transfer** para copiar en bloque y trabajar en local.
- La copia en sí (rclone) suele ser más rápida que el listado; espera a que termine.

## Perdí el log de una copia (modo web)

- En el navegador solo se muestran las **últimas líneas**. El **log completo**
  se guarda en el **servidor OOD**, en la carpeta de logs, al terminar cada
  copia o verificación.
- Si te desconectaste, el log sigue en el servidor: búscalo allí.

## La app pregunta por una actualización

- Es el **auto-actualización**: si hay una release nueva en GitHub, la app te
  pregunta si quieres actualizarte y descarga la nueva versión. Acepta para
  instalar la versión más reciente (o espera y volverá a preguntar más tarde).

## Errores al aplicar metadatos (Tag Manager)

- Revisa el **log** en pantalla: suelen indicarse errores de **permisos** o de
  **credenciales STS**.
- Si los STS están vencidos, la app los renueva automáticamente; reinicia la
  operación.
- Si persiste, contacta con el responsable de datos para verificar permisos
  sobre el bucket.

## Aún no lo resuelvo

- Revisa el **log** de la app para el mensaje de error más específico.
- Contacta con el equipo que mantiene BIFROST en el IRB, indicando:
  - la **aplicación** (bifrost-transfer / bifrost-mount) y su **versión**,
  - el **sistema operativo**,
  - el **mensaje de error** exacto y, si procede, un **fragmento del log**.
