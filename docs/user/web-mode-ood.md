# Usar BIFROST desde el clúster (Open OnDemand / modo web)

Objetivo: trabajar con **bifrost-transfer** a través del **navegador** en el
clúster Linux (Open OnDemand), sin instalar nada en tu equipo.

## Cuándo usarlo

- Trabajas en el **clúster** y prefieres (o necesitas) usar BIFROST **desde el
  navegador**.
- Quieres que la **copia siga corriendo en el servidor** aunque cierres la
  pestaña o te desconectes brevemente.

> El modo web solo aplica a **bifrost-transfer**. bifrost-mount no está
> disponible aquí.

## Cómo se abre

En el clúster, BIFROST se lanza como un proceso estándar a través de Open
OnDemand: la app detecta que se está usando en modo web y se sirve por
navegador (a través de un servidor WebSocket). No hay nada que instalar:
abres la app desde la interfaz de OOD e **inicias sesión** como siempre.

## Diferencias respecto al modo escritorio

En modo web, el proceso del servidor **sigue vivo** aunque cierres la pestaña
del navegador. Esto cambia el comportamiento en dos puntos importantes:

1. **La copia no se interrumpe al cerrar la pestaña.** El proceso de copia
   sigue corriendo en el servidor.
2. **Puedes volver a conectar y retomar** donde estabas.

## Cerrar y volver a abrir la pestaña (reconexión)

Si cierras la pestaña mientras hay una copia en curso y luego la vuelves a
abrir:

1. La app te pide **solo la contraseña** (tu usuario va ya relleno); no
   repites la selección del servidor MinIO ni la descarga de shares.
2. Si la contraseña es correcta, vuelves directamente a la **pantalla de
   copia**.
3. Se muestra un **banner de reconexión** con el estado actual y se
   **reproducen las últimas líneas del log** en pantalla.
4. Si la copia **sigue en curso**, se restaura el botón de **Cancelar** y la
   app espera a que termine.
5. Si la copia **ya terminó** mientras estabas fuera, el estado se ajusta a
   *completada* o *error* según el resultado.

## Dónde se guardan los logs

En modo web, al terminar cada copia o verificación, el **log completo** se
guarda en el **servidor** OOD, en una carpeta de logs. En pantalla solo se
muestran las últimas líneas; si quieres el historial completo de una copia,
búscalo en la carpeta de logs del servidor.

> Esto es importante porque en el navegador el log está limitado a las últimas
> líneas; el registro completo solo existe en disco, en el servidor.

## Sesión y límite de tiempo

- La **sesión web** vive mientras el **proceso del servidor** (el "job" de OOD)
  esté activo.
- La **contraseña LDAP no se guarda** en la sesión: por eso, al reconectar,
  vuelves a introducirla (es tu re-autenticación).
- Si el job de OOD termina o se reinicia, la sesión y el estado se pierden; en
  ese caso, reinicia el flujo normalmente.

## Limitaciones

- **No hay bifrost-mount** en modo web (no se puede montar una unidad desde el
  navegador).
- El **log en pantalla** está limitado a las últimas líneas; el log completo
  solo está en el servidor.
- Si el **job de OOD** se cierra, se pierde la sesión y cualquier copia en
  curso.

## Ante problemas

- **Tarda mucho / se queda en "checking for updates"**: suele ser una
  reconexión en curso; espera a que el banner de reconexión termine de cargar.
- **Pide la contraseña al reconectar**: es el comportamiento esperado (re-
  autenticación). Introduce tu contraseña LDAP.
- **No conecta**: comprueba que estás en la **red/clúster** y que la VPN de
  Nexica está activa (según la configuración de acceso de tu centro).
