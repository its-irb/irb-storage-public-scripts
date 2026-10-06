# Instrucciones para redactar la documentación de usuario

## Audiencia
Los usuarios son investigadores y personal de laboratorio con muy poco perfil técnico. Escribe con frases cortas y sin jerga. Si un concepto técnico es imprescindible, explícalo con una analogía sencilla.

## Reglas de lenguaje
- **Nunca digas "S3"**. Di siempre **MinIO**, que es como lo conocen los usuarios.
- **No uses "CIFS/SMB"**. Di "la Z", "carpeta compartida con el laboratorio" o "NetApp" (algunos usuarios la llaman así).
- **No uses "montar" sin explicarlo**. Define: *montar una carpeta = hacer que esa carpeta aparezca disponible en tu ordenador/sesión, como si fuera local*.
- **Habla de copiar, no de transferir ni mover.** MinIO copia los datos desde su origen al destino y **nunca los borra del origen**. Explícalo siempre que se hable de pasar datos a MinIO.
  - Excepción: el nombre de la app es "Bifrost transfer". Úsalo tal cual para que el usuario la encuentre, pero explica que lo que hace es una copia.
- Escribe siempre "MinIO" (no "Minio" ni "MiniO") y "Open OnDemand" (no uses la sigla OOD sin definirla).
- Evita cualquier otro término técnico que el usuario no conozca.

## Conceptos que hay que explicar

### Permisos en MinIO
- Por defecto, **solo lectura**: puedes ver y copiar los datos, pero **no borrar**.
- En algunas carpetas puedes escribir (ver la estructura de carpetas).
- Los datos son **WORM** (se escriben una vez y no se pueden modificar ni borrar) y se conservan 10 años, etc. Explícalo en lenguaje llano y remarca que **no se puede borrar**.

### Estructura de carpetas
Explica con detalle y con un ejemplo visual (árbol de carpetas) qué es cada una:

- `facility_data`: hay una carpeta por cada core facility (CF) del IRB.
  - Cada CF tiene permisos de escritura en su propia carpeta.
  - Excepción: Biostats puede leer las carpetas de las demás CF, porque normalmente analiza sus datos.
  - Para el resto de usuarios es solo visualización.
  - Cuando una CF quiere compartir datos contigo, te los deja en su carpeta dentro de `facility_data`.
  - Excepción: si el propio laboratorio hace una migración de datos, se le da acceso de escritura a `facility_data`.
- `internal`: raw data que genera el propio laboratorio.
- `external`: raw data que generan core facilities externas al IRB u otras entidades.

> Para cada carpeta indica: quién puede escribir, quién puede leer y qué se guarda en ella.

### Bifrost en Open OnDemand

**Bifrost mount** — para leer datos de MinIO desde una app del clúster:
1. Abre una sesión DCV.
2. Dentro de DCV, usa Bifrost mount para montar los buckets de MinIO que contengan los datos que necesitas analizar.
3. Desde esa misma sesión DCV puedes abrir el resto de apps (por ejemplo, QuPath) y leer los datos de MinIO.
4. Importante: **no lances el job en el nodo ccn01**; usa otros (por ejemplo, sphr).

**Bifrost transfer** — úsalo en Open OnDemand para copias grandes de datos a MinIO, o cuando necesites copiar datos de la Z a MinIO (es decir, algo que no puedes hacer desde tu ordenador):
1. Lanza Bifrost desde Sandbox Apps.
2. Elige el **origen** de los datos:
   - **La Z:** primero monta la carpeta NetApp con Bifrost mount. Una vez montada, la tendrás disponible dentro de la carpeta `netapp-folder`.
   - **SFTP:** selecciona esta opción e introduce host, usuario y contraseña (opcional).
   - **Scratch o carpetas del clúster.**
3. Elige el **destino** en MinIO.
4. Lanza la copia.
5. Recuerda al usuario que los datos originales siguen en su origen.

## Formato esperado de cada guía
- Título claro orientado a la tarea ("Cómo copiar datos de la Z a MinIO").
- Pasos numerados, uno por acción.
- Un aviso destacado cuando algo no se pueda deshacer (por ejemplo, el borrado).
- Si falta información para escribir una sección, **pregunta; no inventes**.