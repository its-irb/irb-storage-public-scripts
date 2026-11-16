# Spec: perfil de metadatos "Genomics"

## Context
Los perfiles de tags S3 viven en `TAG_PROFILES` (`bifrost-transfer/src/meta_fields.py:117`). Hoy hay dos: "IRB Standard" y "Histopathology". Se añade "Genomics" (Advanced Genomic Technologies IRB Core Facility). La spec marca campos obligatorios, pero el código no soporta ese concepto (las tuplas no llevan flag y nadie comprueba campos vacíos), así que se implementa. Los valores con apóstrofes y paréntesis se sanean porque S3 los rechaza (`_TAG_VALUE_RE`).

## Cambios

### 1. `bifrost-transfer/src/meta_fields.py`
- **Tuplas con `required`:** ampliar a 7 elementos `(label, key, FieldType, allow_custom, options, helper, required)`. En `build_meta_fields` leer `required = item[6] if len(item) > 6 else False`, de modo que los perfiles existentes no cambian. Si es `True`, añadir ` *` al label mostrado (los 4 tipos de control usan `label` en un `ft.Text` o `styled_field(label)`).
- **Nueva función `missing_required(profile_name, values) -> list[str]`:** devuelve los labels de los campos `required` cuyo valor está vacío. Es el mismo patrón que `validate_tagset`.
- **Nueva entrada `"Genomics"` en `TAG_PROFILES`**, reutilizando `LAB_ACRONYMS` para `Owner` igual que Histopathology:

| label | key | tipo | required | valores |
|---|---|---|---|---|
| Owner | owner | UNISELECT | sí | `(acr, f"{name} ({acr})")` ordenado por nombre |
| Users | users | MULTIFREETEXT | sí | helper igual que Histopathology |
| Date | date | DATE | sí | |
| Provider | provider | UNISELECT | sí | `["Advanced Genomic Technologies IRB Core Facility"]` (opción única, se autoselecciona) |
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
- `bifrost-transfer/src/views/copy.py` en `do_copy` (~l.915): tras `validate_tagset`, llamar a `missing_required(perfil_activo, metadatos)`. Si hay faltantes, `show_dialog(page, "Missing required fields", ", ".join(...), C_ERROR)` y `return`. Hay que localizar la variable que guarda el perfil activo (el dropdown de `copy.py:216`).
- `bifrost-transfer/src/views/tag_manager.py` en `do_apply` (~l.563): lo mismo con `active_profile["name"]`.
- No se toca el editor libre de key/value de `tag_manager.py:815`, porque no es de perfil.

### 3. Validación unificada de tags (caracteres y longitud)
S3 limita las keys a 128 caracteres y los valores a 256. Application es multiselección y se une con `:` (26 opciones juntas = 355 caracteres), así que puede pasarse; `users` (multifreetext) y `comments` (texto libre) también. Hoy solo el editor manual de `tag_manager.py` (l.691 y l.707) tiene `max_length`; los perfiles no comprueban la longitud. Además, el regex de caracteres se repite en `_validate_tag_value` (l.17), `check_tag_value` (l.38), `validate_tagset` (l.45) y dos veces inline (l.326 multiselect, l.408 multifreetext). Se unifica todo en `meta_fields.py`:
- Constantes `TAG_KEY_MAX = 128` y `TAG_VALUE_MAX = 256`.
- `check_tag_value(text, max_len=TAG_VALUE_MAX) -> str | None` comprueba caracteres y longitud. Las keys se comprueban con `max_len=TAG_KEY_MAX`.
- `validate_tagset` llama a `check_tag_value` para cada key y valor. Se llama al pulsar Copy o Aplicar (`copy.py:915`, `tag_manager.py:563` y `:820`), no mientras se escribe.
- `_validate_tag_value` (UI) delega en `check_tag_value` en lugar de repetir el regex.
- Multiselect (`_on_select`) y multifreetext (`_add`): antes de añadir una opción calculan el valor unido candidato `":".join(sorted(sel | {val}))` y llaman a `check_tag_value`. Como `:` está permitido por el regex, una llamada cubre caracteres y longitud. Si hay error, no se añade la opción y se muestra inline. El multiselect hoy solo tiene `Text` de error con `allow_custom=True`, así que hay que crearlo siempre. Desaparecen las copias inline del regex.
- `tag_manager.py`: se mantienen `max_length` en los `TextField` del editor manual (tope duro de escritura en la UI), pero leyendo `TAG_KEY_MAX` y `TAG_VALUE_MAX` en lugar de los literales 128 y 256. La key pasa `TAG_KEY_MAX` a `check_tag_value` en `on_change` (l.722).
- `comments` no necesita `max_length` propio: su `on_change` ya pasa por `_validate_tag_value`, que ahora comprueba también la longitud.

### 4. `detect_profile` con `provider` como criterio principal
Sin cambios, si un objeto solo tiene keys comunes con Histopathology (owner, users, date, provider, species, sample_type), ambos perfiles califican con el mismo score y gana Histopathology por orden.
- `provider` es fijo dentro de cada perfil: una única opción, `allow_custom=False`, ya autoseleccionada por `_single` (`meta_fields.py:224`). Se bloquea visualmente con `disabled=True` cuando `_single`.
- `detect_profile` primero mira `tags.get("provider")` y devuelve el perfil cuya opción de provider coincide. El mapa valor→perfil se deriva de `TAG_PROFILES`, sin tabla aparte.
- Si no hay `provider` o no coincide (p. ej. "IRB Standard" o datos antiguos), se aplica la lógica actual de subconjunto de keys.
- Efecto secundario: renombrar el texto de un provider hace que los objetos ya etiquetados caigan al fallback por keys. Es seguro, pero hay que tenerlo en cuenta.

### 5. Documentación
- Lanzar `docs-update` para `docs/agent/` y `docs/development/` si describen la estructura de las tuplas de `TAG_PROFILES`, la validación de tags o `detect_profile`.
- Entrada en `docs/wiki/log.md` con las decisiones: saneado de caracteres, flag `required`, validación unificada y `provider` como criterio de detección.

## Notas
- **Separador `:`:** ninguna opción nueva contiene `:`, así que el split del prefill de los multiselect es seguro.
- **Límite de 10 tags por objeto de S3:** Genomics tiene 9 campos. El control existente de `tag_manager.py:680` y `:767` no cambia.

## Verificación
1. Con la app arrancada, abrir Copy y Tag Manager y comprobar que "Genomics" aparece en el selector, con `*` en los obligatorios y Provider autoseleccionado.
2. Intentar copiar y aplicar con campos obligatorios vacíos: debe salir el diálogo "Missing required fields".
3. Rellenar todo, copiar un fichero de prueba y comprobar los tags en MinIO. Application y Library Kit deben salir separados por `:`.
4. Comprobar que "IRB Standard" e "Histopathology" se comportan igual que antes, sin `*` ni bloqueos.
5. Prueba rápida en Python: `validate_tagset` sobre todas las opciones nuevas debe devolver `[]`, y debe devolver error para un valor de 257 caracteres y una key de 129.
6. En Application, añadir opciones hasta pasar de 256 caracteres unidas: la que lo supere no se añade y sale el error inline.
7. Autodetección: un objeto con solo los tags comunes (owner, users, date, provider, species, sample_type) y `provider` de Genomics debe abrirse con el perfil Genomics, y con `provider` de Histopathology, con Histopathology.
