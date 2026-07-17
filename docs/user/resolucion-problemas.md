# Resolución de problemas

Soluciones a los problemas más habituales al usar BIFROST. Si tu caso no está aquí o la solución no funciona, contacta con ITS y adjunta el fichero de log correspondiente (ver más abajo "Cómo pedir ayuda").

## Índice

- [La app no conecta / se queda colgada al arrancar](#la-app-no-conecta--se-queda-colgada-al-arrancar)
- [No puedo iniciar sesión](#no-puedo-iniciar-sesión)
- [No veo mis buckets / no veo el bucket que busco](#no-veo-mis-buckets--no-veo-el-bucket-que-busco)
- [BIFrost Mount me pide instalar WinFsp (Windows)](#bifrost-mount-me-pide-instalar-winfsp-windows)
- [La unidad montada no responde / se ha quedado colgada](#la-unidad-montada-no-responde--se-ha-quedado-colgada)
- [La copia va muy lenta](#la-copia-va-muy-lenta)
- [La copia da error](#la-copia-da-error)
- [Al cerrar y reabrir la pestaña web, ¿pierdo la copia?](#al-cerrar-y-reabrir-la-pestaña-web-pierdo-la-copia)
- [No aparece el botón de Copiar / no veo los metadatos](#no-aparece-el-botón-de-copiar--no-veo-los-metadatos)
- [El filtro "Filter by lab…" ha desaparecido](#el-filtro-filter-by-lab-ha-desaparecido)
- [La app me pide actualizar](#la-app-me-pide-actualizar)
- [macOS dice que no puede abrir la app](#macos-dice-que-no-puede-abrir-la-app)

## La app no conecta / se queda colgada al arrancar

**Causa más frecuente:** no estás conectado a la VPN del IRB.

**Solución:**

1. Conéctate a la **VPN del IRB (Nexica / Forticlient)**.
2. Espera a que la VPN muestre "conectado".
3. Vuelve a abrir BIFROST.

Si ya estás en la VPN y sigue sin conectar, comprueba que tienes conexión a internet (abre una web en el navegador). Si el problema persiste, contacta con ITS.

## No puedo iniciar sesión

**Posibles causas:**

- Usuario o contraseña incorrectos.
- La VPN no está activa.
- Estás en una máquina sin acceso al directorio del IRB (por ejemplo, IVIS).

**Solución:**

1. Revisa usuario y contraseña (los mismos que usas en tu equipo del IRB).
2. Confirma que la VPN está conectada.
3. Si ves el aviso `DESKTOP (NO LDAP)` en la cabecera, significa que la máquina no valida contra el directorio del IRB; aun así, necesitas usuario y contraseña correctos para MinIO.
4. Si acabas de cambiar la contraseña, espera unos minutos a que se replique e inténtalo de nuevo.

## No veo mis buckets / no veo el bucket que busco

**Posibles causas:**

- El bucket no te tiene asignado.
- Tienes muchos buckets y no lo encuentras a simple vista.

**Solución:**

1. Usa el campo **"Filter by lab…"** arriba del navegador de buckets: escribe el nombre o acrónimo de tu laboratorio para reducir la lista.
2. Si el bucket no aparece, es probable que no tengas permiso sobre él. Contacta con ITS o con el responsable del bucket para que te dé acceso.
3. Recuerda: el filtro **solo aparece en la lista de buckets** (la raíz). Si estás dentro de un bucket, no lo verás; vuelve a la raíz para usarlo.

## BIFrost Mount me pide instalar WinFsp (Windows)

**Es normal la primera vez** en Windows si no tienes WinFsp instalado. BIFrost Mount lo necesita para mostrar las carpetas de MinIO como una unidad.

**Solución:**

1. Acepta el aviso que aparece.
2. La app descargará el instalador oficial de WinFsp desde internet.
3. Confirma el permiso de administrador cuando lo pida Windows.
4. Cuando termine, vuelve a pulsar **Montar**.

Solo tienes que hacer esto una vez. Si prefieres instalarlo tú a mano, descárgalo desde [winfsp.dev](https://winfsp.dev).

## La unidad montada no responde / se ha quedado colgada

**Causa más frecuente:** se ha caído o pausado la VPN mientras tenías la carpeta montada.

**Solución:**

1. Reconecta la VPN y espera a que esté activa.
2. Prueba a acceder a la unidad de nuevo.
3. Si no responde, **desmonta** la carpeta desde BIFrost Mount y vuelve a montarla.
4. Si la app misma no responde, ciérrala (puedes forzar el cierre), vuelve a abrirla y monta de nuevo.

## La copia va muy lenta

**Posibles causas:**

- Conexión de red lenta o saturada.
- Estás copiando muchos ficheros pequeños (rclone los procesa uno a uno).
- El equipo está haciendo otras tareas pesadas a la vez.

**Solución:**

- Si es posible, copia en horarios de menos carga.
- Si copias muchos ficheros pequeños, considera comprimirlos antes en un único fichero y subir ese.
- Cierra otros programas que estén usando la red.
- En el modo web del cluster, la copia corre en el cluster, no en tu equipo; si tu conexión de navegador es lenta no afecta a la velocidad de copia (solo a cómo de rápido ves el log).

## La copia da error

1. **Lee el mensaje de error** en el log: suele indicar qué pasó (permisos, espacio, fichero bloqueado, etc.).
2. **Comprueba el destino:** ¿tienes permiso de escritura en ese bucket/carpeta?
3. **Comprueba el origen:** ¿la carpeta existe y tienes acceso? Si es una unidad de red, ¿está montada?
4. **Comprueba el espacio:** ¿queda espacio en MinIO? (Consulta con ITS si lo dudas.)
5. Si el error menciona `checksum` o `integrity`, puede que un fichero cambiara mientras se copiaba. Cierra el programa que lo tenga abierto y reintenta.
6. Si no logras resolverlo, **guarda el log** (ver abajo) y escríbeselo a ITS.

## Al cerrar y reabrir la pestaña web, ¿pierdo la copia?

**No.** En el modo web (OOD), si cierras la pestaña del navegador mientras se está copiando, **la copia sigue corriendo en el cluster**. No se pierde.

Para recuperarla:

1. Vuelve a abrir BIFrost Transfer en Open OnDemand.
2. La app detectará tu sesión previa y te pedirá **solo la contraseña**.
3. Tras ponerla volverás a la pantalla de copia, con un aviso de reconexión y las últimas líneas del log.

Eso sí: si tu **job de OOD caduca** o lo cancelas, la sesión se pierde y la copia se corta. Asegúrate de que el job tiene tiempo suficiente para copias largas.

## No aparece el botón de Copiar / no veo los metadatos

**Es normal si todavía no has elegido un destino.** En la pantalla de copia, las zonas de **metadatos**, **botones de acción** y **log** están ocultas hasta que selecciones un bucket o carpeta de destino.

**Solución:**

1. Ve al navegador de buckets de destino.
2. Navega hasta el bucket o carpeta donde quieres copiar.
3. En cuanto selecciones un destino, aparecerán los metadatos, los botones y el log.

## El filtro "Filter by lab…" ha desaparecido

**Es normal:** el filtro **solo aparece en la raíz**, es decir, en la lista de buckets. Cuando entras dentro de un bucket desaparece, porque dentro de un bucket no se filtra por laboratorio.

**Solución:** vuelve a la raíz (sube hasta la lista de buckets) y verás el filtro de nuevo.

## La app me pide actualizar

Cuando hay una versión nueva, al arrancar la app aparece un mensaje tipo **"New version available: X"** con dos botones:

- **Update now** — descarga e instala la nueva versión y reinicia la app. En Windows puede pedir permisos de administrador.
- **Continue anyway** — sigue con la versión actual.

**Recomendación:** acepta la actualización para tener las mejoras y correcciones. Si estás en mitad de una tarea urgente puedes posponerla con "Continue anyway" y actualizar en el próximo arranque.

> En el modo web (OOD) no hay autoupdate: la versión la gestiona el servicio.

## macOS dice que no puede abrir la app

**"No se puede abrir BIFrost porque proviene de un desarrollador no identificado."**

Es normal la primera vez en Mac, porque la app no está firmada por Apple. Para abrirla:

1. Abre **Preferencias del Sistema → Seguridad y privacidad**.
2. Abajo verás un mensaje que dice que BIFrost se bloqueó. Pulsa **Abrir de todas formas**.
3. Confirma en el diálogo.

O bien: en la carpeta Aplicaciones, haz **clic derecho** sobre BIFrost → **Abrir** → **Abrir** en el diálogo.

Solo se pide la primera vez.

## Cómo pedir ayuda

Si ninguna solución te sirve:

1. **Guarda el log de la sesión.** BIFROST escribe un fichero de log con timestamp en tu equipo:
   - **BIFrost Transfer (escritorio y web):** `~/bifrost-logs/bifrost-YYYY-MM-DD_HH-MM-SS.log`
   - **BIFrost Mount:** `~/bifrost-mount-logs/bifrost-mount-YYYY-MM-DD_HH-MM-SS.log`
   
   En el cluster (modo web), `~` es tu carpeta de usuario del cluster.
2. **Apunta** qué estabas haciendo cuando falló (qué app, qué paso, qué mensaje salió).
3. **Escribe a ITS** con esa información y adjunta el fichero de log.

El log contiene el comando completo que se ejecutó y el detalle del error, lo que ayuda mucho a diagnosticar el problema.
