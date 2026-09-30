# Etiquetar datos ya subidos (Tag Manager)

Objetivo: aplicar o corregir **metadatos (tags)** en objetos que ya están en
MinIO, **sin re-subir** los datos.

## Cuándo usarlo

- Los datos ya están subidos, pero **falta** etiquetarlos o los tags están
  **mal/parciales**.
- Quieres **aplicar un tagset en bloque** a una carpeta o a un prefijo de
  bucket.
- No quieres pagar el coste (ni el tiempo) de re-copiar archivos grandes.

> El Tag Manager vive dentro de **bifrost-transfer**.

## Antes de empezar

- VPN activa y login completado.
- Conoces el **bucket**, la **carpeta** o el **archivo** que quieres etiquetar.
- Sabes qué **perfil de metadatos** corresponde (IRB Standard, Histopathology, …).

## Cómo funciona

El Tag Manager te deja **navegar** buckets, carpetas y archivos dentro de S3 y
aplicar tags en bloque.

1. Entra al **Tag Manager**.
2. **Navega** hasta el objetivo:
   - un **archivo individual**,
   - una **carpeta**, o
   - un **prefijo de bucket** (varias carpetas).
   - Como en la copia, en la raíz de buckets hay un **"Filter by lab…"** para
     filtrar por acrónimo de laboratorio.
3. **Selecciona** el perfil de metadatos y rellena los campos.
4. **Aplica** el tagset. La app usa boto3 para poner los tags directamente en
   los objetos existentes (o a todo el prefijo), sin tocar los datos.

## Pre-rellenado automático

Cuando seleccionas un **archivo individual** y sus tags existentes **encajan
con un perfil conocido**, el editor se conmuta automáticamente a la vista del
perfil con los **valores ya rellenos**. Así puedes revisar y corregir usando
los mismos desplegables, selectores de fecha y campos multi-valor que se usan
al subir.

- El botón **"Ver tags raw"** te deja volver en cualquier momento a la lista
  cruda de pares clave/valor.
- Esto evita tener que re-introducir a mano lo que ya estaba.

## Resultado esperado

- Los objetos del objetivo llevan el **tagset aplicado** (nuevo o corregido).
- **No se mueve ni se re-copia ningún dato**: solo cambia la información de
  metadatos asociada.
- Si aplicas a un prefijo, todos los objetos bajo esa jerarquía reciben los
  tags.

## Limitaciones

- El Tag Manager opera sobre **metadatos**, no sobre el contenido: no sirve
  para mover, renombrar ni copiar archivos (para eso, usa la vista de copia).
- El pre-rellenado automático solo ocurre cuando los tags existentes **se
  reconocen como un perfil**; si no, parte en blanco (o usa "Ver tags raw").
- Aplicar a un prefijo extenso puede tardar; el log muestra el progreso.

## Ante errores

- **No ves el bucket/archivo**: revisa que el login es correcto y que tienes
  acceso a ese bucket.
- **Los tags no se aplican**: comprueba en el log los errores de permisos o de
  credenciales STS; si persiste, consulta [troubleshooting.md](troubleshooting.md).
