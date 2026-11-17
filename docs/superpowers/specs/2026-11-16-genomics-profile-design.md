# Spec: perfil de metadatos "Genomics"

## Context
Los perfiles de tags S3 viven en `TAG_PROFILES` (`bifrost-transfer/src/meta_fields.py:117`). Hoy hay dos: "IRB Standard" y "Histopathology". Se añade "Genomics", cuyo nombre es el de su facility: `Advanced Genomic Technologies IRB Core Facility`. A la vez, el nombre de cada perfil pasa a ser el valor de su tag `provider` (ver §4). La spec marca campos obligatorios, pero el código no soporta ese concepto (las tuplas no llevan flag y nadie comprueba campos vacíos), así que se implementa. Los valores con apóstrofes y paréntesis se sanean porque S3 los rechaza (`_TAG_VALUE_RE`).

## Cambios

### 1. `bifrost-transfer/src/meta_fields.py`
- **Tuplas con `required`:** ampliar a 7 elementos `(label, key, FieldType, allow_custom, options, helper, required)`. En `build_meta_fields` leer `required = item[6] if len(item) > 6 else False`, de modo que los perfiles existentes no cambian. Si es `True`, añadir ` *` al label mostrado (los 4 tipos de control usan `label` en un `ft.Text` o `styled_field(label)`).
- **Nueva función `missing_required(profile_name, values) -> list[str]`:** devuelve los labels de los campos `required` cuyo valor está vacío. Es interna: las vistas llaman a `validate_profile_tagset` (§3).
- **Nueva entrada `"Advanced Genomic Technologies IRB Core Facility"` en `TAG_PROFILES`**, reutilizando `LAB_ACRONYMS` para `Owner` igual que Histopathology. El campo `provider` no se declara aquí: lo añade automáticamente `profile_fields` (§4).

| label | key | tipo | required | valores |
|---|---|---|---|---|
| Owner | owner | UNISELECT | sí | `(acr, f"{name} ({acr})")` ordenado por nombre |
| Users | users | MULTIFREETEXT | sí | helper igual que Histopathology |
| Date | date | DATE | sí | |
| Application | application | MULTISELECT | sí | ver lista abajo |
| Library Kit | library_kit | MULTISELECT | sí | ver lista abajo |
| Species | species | UNISELECT | sí | human, mouse, rat, Drosophila, zebrafish, other |
| Sample Type | sample_type | UNISELECT | sí | cells, nuclei, fresh frozen tissue, FFPE tissue, RNA, DNA, organoids |
| Comments | comments | TEXT | no | helper: "Incidents, QC deviations, notes" |

**Application:** Qubit, Bioanalyzer, Tapestation, Qubit+Bioanalyzer, Qubit+Tapestation, RNA extraction, DNA extraction, RNA purification, DNA purification, Bulk RNA-seq, Low-input RNA-seq, ChIP-seq, ATAC-seq, scRNA-seq 3prime, scRNA-seq 3prime OCM, scRNA-seq 5prime/VDJ, scRNA-seq 5prime/TCR, scRNA-seq 5prime/BCR, scRNA-seq Flex, scATAC-seq, Multiome, Xenium, Sequencing, RIP-seq, Ribo-seq, Other

**Library Kit:** Illumina Stranded mRNA, NEBNext mRNA, SMART-Seq Total RNA Takara, 10x GEM-X 3prime, 10x GEM-X 5prime, 10x Flex, 10x ATAC, 10x Multiome, Xenium panel, Other

Correcciones respecto a la spec original: `Qubit+Tapesation` pasa a `Qubit+Tapestation`, y se quita el punto final de `DNA purification.`. Se sanean apóstrofes (`3'` → `3prime`) y paréntesis (`(Takara)` → `Takara`).

- **`allow_custom`:** `False` en todos los selects. "Other" ya cubre el caso libre y evita valores no validados.

### 2. Enforcement de obligatorios
- `bifrost-transfer/src/views/copy.py` en `do_copy` (~l.915): sustituir `validate_tagset(metadatos)` por `validate_profile_tagset(active_copy_profile["name"], metadatos)`; el diálogo y el `return` existentes sirven para todos los errores (formato, longitud y obligatorios).
- `bifrost-transfer/src/views/tag_manager.py` en `do_apply` (~l.563): lo mismo con `active_profile["name"]`; y en `_on_save_file_tags` (~l.820) solo cuando el modo es `profile`.
- No se toca el editor libre de key/value de `tag_manager.py:815`, porque no es de perfil.

### 3. Validación unificada de tags (caracteres y longitud)
S3 limita las keys a 128 caracteres y los valores a 256. Application es multiselección y se une con `:` (las 26 opciones juntas superan los 256 caracteres), así que puede pasarse; `users` (multifreetext) y `comments` (texto libre) también. Hoy solo el editor manual de `tag_manager.py` (l.691 y l.707) tiene `max_length`; los perfiles no comprueban la longitud. Además, el regex de caracteres se repite en `_validate_tag_value` (l.17), `check_tag_value` (l.38), `validate_tagset` (l.45) y dos veces inline (l.326 multiselect, l.408 multifreetext). Se unifica todo en `meta_fields.py`:
- Constantes `TAG_KEY_MAX = 128` y `TAG_VALUE_MAX = 256`.
- `check_tag_value(text, max_len=TAG_VALUE_MAX) -> str | None` comprueba caracteres y longitud. Las keys se comprueban con `max_len=TAG_KEY_MAX`.
- `validate_tagset` llama a `check_tag_value` para cada key y valor. Se llama al pulsar Copy o Aplicar (`copy.py:915`, `tag_manager.py:563` y `:820`), no mientras se escribe.
- `_validate_tag_value` (UI) delega en `check_tag_value` en lugar de repetir el regex.
- Multiselect (`_add_custom`) y multifreetext (`_add`): sustituyen su copia inline del regex por `check_tag_value(val)` (solo caracteres de cada opción, en el `Text` de error que ya existe). **No hay bloqueo inline por longitud:** la longitud del valor unido la valida `validate_profile_tagset` al pulsar Copy o Aplicar, que nombra el campo. Así la validación está en un solo sitio.
- **`validate_profile_tagset(profile_name, tags) -> list[str]`:** única entrada de validación para las vistas. Concatena los errores de `validate_tagset` y, si faltan obligatorios (`missing_required`, interna), `Missing required fields: ...`. Las vistas hacen una llamada y un diálogo. El editor manual de key/value sigue usando `validate_tagset`.
- `tag_manager.py`: se mantienen `max_length` en los `TextField` del editor manual (tope duro de escritura en la UI), pero leyendo `TAG_KEY_MAX` y `TAG_VALUE_MAX` en lugar de los literales 128 y 256. La key pasa `TAG_KEY_MAX` a `check_tag_value` en `on_change` (l.722).
- `comments` no necesita `max_length` propio: su `on_change` ya pasa por `_validate_tag_value`, que ahora comprueba también la longitud.

### 4. El nombre del perfil es el valor de `provider`
Hasta ahora, si un objeto solo tenía keys comunes con Histopathology (owner, users, date, provider, species, sample_type), ambos perfiles calificaban con el mismo score y ganaba Histopathology por orden. Se resuelve haciendo que el perfil lo marque `provider`, que es el mismo string que el nombre del perfil y lo llevan todos, incluido IRB Standard.

| Perfil (= provider) | Antes |
|---|---|
| `IRB Standard` | `IRB Standard` (mismo nombre y mismos 7 campos; solo gana el tag `provider`) |
| `Histopathology IRB Core Facility` | `Histopathology` |
| `Advanced Genomic Technologies IRB Core Facility` | (nuevo) |

- **`profile_fields(profile_name) -> list[tuple]`** (nueva en `meta_fields.py`): devuelve `[("Provider", "provider", FieldType.UNISELECT, False, [profile_name], None, True)] + TAG_PROFILES[profile_name]`. El provider va primero. Lo usan `build_meta_fields`, `missing_required` y `detect_profile` en lugar de leer `TAG_PROFILES[...]` directamente. Reutiliza la rama UNISELECT con `_single` (una opción, sin blanco, autoseleccionada, `meta_fields.py:224`) más `disabled=True`, así que el provider queda bloqueado sin código de render nuevo.
- **`TAG_PROFILES` no declara `provider`:** se quita la tupla de Histopathology (queda con 9 campos + el automático = 10 tags, el máximo de S3). Se renombra su clave a `Histopathology IRB Core Facility`.
- **Provider forzado al abrir:** `apply_provider(profile_name, values)` devuelve una copia con `provider = profile_name` y se aplica al prefill de `build_meta_fields`. Un objeto detectado por fallback con un provider antiguo o desconocido se muestra con el provider del perfil (bloqueado), no como opción extra `valor *`, y queda corregido al guardar.
- **`detect_profile`:** si `tags.get("provider")` es una clave de `TAG_PROFILES` y todas las keys de `tags` son de ese perfil, devuelve ese perfil; si hay keys ajenas devuelve `None` (modo raw), porque guardar en modo perfil las borraría sin aviso. Si no, mantiene el fallback actual por subconjunto de keys. El fallback cubre los objetos antiguos de IRB Standard, que no tienen `provider`, y los que traen un provider desconocido. No hay mapa valor→perfil.
- **Desplegables de perfil:** `Advanced Genomic Technologies IRB Core Facility` son 47 caracteres y `tag_manager.py:552` tiene `width=220`. Se ensanchan ese desplegable y los de `copy.py:215` y `tag_manager.py:875` (`prefill_profile_dd`).
- **Sesión web:** `_WEB_SESSIONS` (`web_session.py:45`) es solo memoria, así que renombrar perfiles no deja valores obsoletos guardados.
- Efecto secundario: renombrar un perfil en el futuro cambia un tag que ya está en los objetos subidos; esos objetos caerían al fallback por keys. Es seguro, pero hay que tenerlo en cuenta.

### 5. Documentación
- Lanzar `docs-update` para `docs/agent/` y `docs/development/` si describen la estructura de las tuplas de `TAG_PROFILES`, la validación de tags o `detect_profile`.
- Entrada en `docs/wiki/log.md` con las decisiones: saneado de caracteres, flag `required`, validación unificada y `provider` como criterio de detección.

## Notas
- **Separador `:`:** ninguna opción nueva contiene `:`, así que el split del prefill de los multiselect es seguro.
- **Límite de 10 tags por objeto de S3:** con el `provider` automático, IRB Standard tiene 8 tags, Genomics 9 y Histopathology 10 (el máximo). El control existente de `tag_manager.py:680` y `:767` no cambia, pero añadir un campo a Histopathology exige quitar otro.
- **Nombres de perfil como tags de S3:** son un valor de tag, así que deben pasar `check_tag_value` (sin paréntesis, apóstrofes ni comas, máximo 256 caracteres).

## Verificación
1. Con la app arrancada, abrir Copy y Tag Manager y comprobar que "Genomics" aparece en el selector, con `*` en los obligatorios y Provider autoseleccionado.
2. Intentar copiar y aplicar con campos obligatorios vacíos: debe salir el diálogo "Missing required fields".
3. Rellenar todo, copiar un fichero de prueba y comprobar los tags en MinIO. Application y Library Kit deben salir separados por `:`.
4. Comprobar que "IRB Standard" e "Histopathology IRB Core Facility" se comportan igual que antes salvo por Provider (bloqueado, primero, con `*`): no se bloquea Copy.
5. Prueba rápida en Python: `validate_tagset` sobre todas las opciones nuevas debe devolver `[]`, y debe devolver error para un valor de 257 caracteres y una key de 129.
6. En Application, seleccionar las 26 opciones (más de 256 caracteres unidas) y pulsar Copy o Aplicar: el diálogo de errores nombra el campo Application.
7. Autodetección: un objeto con solo los tags comunes (owner, users, date, provider, species, sample_type) y `provider` de Genomics debe abrirse con el perfil Genomics, y con `provider` de Histopathology, con Histopathology.
