# BIFrost Transfer en el navegador (cluster / Open OnDemand)

Además del programa de escritorio, BIFrost Transfer se puede usar **desde el navegador** cuando trabajas en el cluster Linux del IRB a través de Open OnDemand (OOD). La forma de usarlo es casi igual que la de escritorio, pero hay algunas diferencias importantes que se explican aquí.

## Cuándo usar el modo web

- Cuando trabajas en el **cluster Linux** del IRB y quieres subir datos al almacenamiento sin bajártelos a tu equipo.
- Cuando no puedes o no quieres instalar el programa de escritorio.
- Para copiar datos grandes que ya están en una unidad de red del cluster a MinIO.

## Cómo acceder

1. Entra en el portal de **Open OnDemand** del IRB con tu usuario y contraseña del IRB.
2. Lanza una sesión de **BIFrost Transfer** (es una de las aplicaciones disponibles en OOD).
3. Se abre una pestaña del navegador con la aplicación. Verás el mismo aspecto que en el escritorio, con el aviso **WEB** en la cabecera.

> No necesitas instalar nada en tu equipo. Toda la aplicación corre en el cluster; el navegador solo la muestra.

## Iniciar sesión

Como en el escritorio, escribe tu **usuario** y **contraseña** del IRB y pulsa **Entrar**.

### Si ya tenías una sesión abierta

El modo web recuerda tu sesión mientras el proceso del cluster esté activo (es decir, mientras no caduque tu job de OOD). Esto significa que:

- Si **cierras la pestaña** del navegador por error o se cae la conexión **mientras se está copiando algo**, la copia **sigue corriendo** en el cluster. No se pierde.
- Si **vuelves a abrir** BIFrost Transfer en OOD, la app detectará que tenías una sesión y te pedirá **solo la contraseña** (no vuelves a pasar por la elección de servidor ni de unidades de red).
- Tras poner la contraseña volverás a ver la pantalla de copia con un **aviso de reconexión** y las últimas líneas del log, para que sepas en qué estado quedó la copia.

Por eso, si se te cierra la pestaña durante una copia grande, **no te asustes**: vuelve a abrir BIFrost, pon la contraseña y verás cómo sigue.

## Unidades de red (CIFS) en el cluster

En el cluster Linux, además de carpetas locales, puedes copiar desde **unidades de red** (CIFS/SMB) a las que tengas acceso. Tras el login, en el modo cluster aparece una pantalla extra donde puedes **montar** las unidades de red disponibles antes de elegir el origen de la copia.

> **Solo lectura:** las unidades de red que montas aquí son **solo para lectura**. Sirven únicamente como **origen** de una copia hacia MinIO; no puedes modificar, crear ni borrar ficheros en ellas a través del montaje.

1. En la pantalla de unidades, marca las que quieras montar.
2. Pulsa **Montar** (o el botón equivalente).
3. Esas unidades quedarán disponibles como carpetas y podrás elegirlas como **origen** en la pantalla de copia.
4. Antes de cerrar sesión, puedes **desmontarlas** para limpiar.

En la pantalla de copia verás el botón **Mount CIFS** para volver a gestionar las unidades si lo necesitas.

## Pantalla de copia

La pantalla de copia funciona igual que en el escritorio (ver `bifrost-transfer.md`):

1. Elige el **origen** (carpeta local del cluster o unidad de red montada).
2. Elige el **destino** (bucket y carpeta en MinIO). El filtro **"Filter by lab…"** está disponible igual que en escritorio.
3. Rellena los **metadatos** con el perfil que toque (ver `metadatos-perfiles.md`).
4. Pulsa **Copy** y sigue el progreso en el **Log**.

### Diferencias respecto al escritorio

- **El log va un poco más lento en pantalla** (se actualiza cada cierto tiempo en lugar de línea a línea) para no saturar la conexión del navegador. No te preocupes: la copia avanza igual.
- Si el log tiene muchas líneas, en pantalla solo verás las últimas; el **log completo** se guarda en disco en el cluster, en `~/bifrost-logs/`.
- **No hay autoupdate:** la versión que corra OOD es la que hayas lanzado. Las actualizaciones las gestiona el servicio, no el usuario.

## Cerrar sesión bien

Cuando termines:

1. Pulsa el botón de **cerrar sesión** / **logout** de la app (no basta con cerrar la pestaña si quieres limpiar del todo).
2. La app desmonta las unidades de red que tengas montadas y borra tu sesión interna.
3. Verás un mensaje **"Session closed. You can close this browser tab."**
4. Cierra la pestaña y, si lo deseas, termina el job de OOD desde el portal.

Si simplemente cierras la pestaña sin cerrar sesión, el proceso del cluster sigue activo (y cualquier copia en curso sigue corriendo). Volverás a poder reconectar mientras el job esté vivo.

## Dónde está el log completo

El log completo de cada copia se guarda en el cluster, en:

```
~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log
```

(`~` es tu carpeta de usuario en el cluster). Si necesitas ayuda con un fallo, puedes buscar ahí el fichero correspondiente y enviárselo a ITS.

## Cosas a tener en cuenta

- **Job de OOD:** mientras tu job de OOD esté activo, tu sesión de BIFrost se mantiene. Si el job caduca o lo cancelas, la sesión se pierde (y cualquier copia en curso se corta).
- **Contraseña:** la app nunca guarda tu contraseña. Solo la usa para identificarte durante la sesión.
- **Copias largas:** si vas a copiar muchos datos, asegúrate de que tu job de OOD tiene tiempo suficiente antes de caducar.
- **Múltiples pestañas:** puedes abrir BIFrost en varias pestañas a la vez con el mismo usuario; verás el mismo log en todas. Útil para monitorizar una copia desde otra pestaña.

## Resumen rápido

```
VPN/portal IRB → Open OnDemand → lanzar BIFrost Transfer →
usuario/contraseña → (si ya había sesión: solo contraseña) →
montar unidades de red si hace falta →
elegir origen → elegir bucket destino →
elegir perfil y rellenar metadatos → Copy →
seguir el log → al terminar, cerrar sesión
```
