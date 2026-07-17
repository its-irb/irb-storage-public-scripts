# Meta-fields — `bifrost-transfer/src/meta_fields.py`

Diseño de perfiles de metadatos, acrónimos de laboratorio y filtro por lab. **Fuente canónica** para el formulario de copia y el Tag Manager. Cualquier cambio en campos, perfiles o labs se hace **solo** aquí.

## `FieldType` (Enum)

```python
class FieldType(Enum):
    TEXT          = "text"
    UNISELECT     = "uniselect"
    MULTISELECT   = "multiselect"
    MULTIFREETEXT = "multifreetext"
    DATE          = "date"
    NUMBER        = "number"   # sin uso actual
```

## `TAG_PROFILES: dict[str, list[tuple]]`

Estructura de cada tupla: `(label, key, field_type, allow_custom, options_list, helper)`.

### `IRB Standard`

Campos de metadatos generales, todos `TEXT`:

| Label | key |
|---|---|
| Project | `project_name` |
| Host machine | `compute_node` |
| Sample type | `sample_type` |
| Input data type | `input_data_type` |
| Output data type | `output_data_type` |
| Requested by | `requested_by` |
| Research group | `research_group` |

### `Histopathology`

Campos especializados para datos de histopatología:

| Label | key | type | opciones / helper |
|---|---|---|---|
| Owner | `owner` | `UNISELECT` | opciones = `LAB_ACRONYMS` ordenadas por nombre (`(acr, f"{name} ({acr})")`) |
| Users | `users` | `MULTIFREETEXT` | helper: "Enter Linux usernames, add each one separately" |
| Date | `date` | `DATE` | — |
| Provider | `provider` | `UNISELECT` | `["Histopathology IRB Core Facility"]` |
| Instrument | `instrument` | `UNISELECT` | `["Phenoimager", "Nanozoomer"]` |
| Species | `species` | `UNISELECT` | `["mouse", "human", "rat", "pig", "cow"]` |
| Sample Type | `sample_type` | `UNISELECT` | `["tissue section", "organoid", "cell pellet"]` |
| Sample Origin | `sample_origin` | `TEXT` | helper explica formato según sample_type (tissue/organoid/cell pellet) |
| Magnification | `magnification` | `UNISELECT` | `["20x", "40x"]` |
| Channels | `channels` | `UNISELECT` | combinaciones DAPI + canales, `4plex`/`5plex`/`6plex` |

## `LAB_ACRONYMS: dict[str, str]`

29 acrónimos → nombre de PI/lab del IRB Barcelona. **Los acrónimos deben coincidir exactamente con el tag `acronym` de los buckets MinIO** (lo lee `backend.get_bucket_tags`). Ejemplos:

```
ccl → Eduard Batlle          bbg → Nuria López-Bigas
itpc → Direna Alonso-Curbelo sccl → Angel R. Nebreda
gccm → Roger Gomis           lmb → Xavier Salvatella
cdl → Cayetano González      gtl → Lluis Ribas
scc → Salvador Aznar Benitah pnacmm → Miquel Coll
```

Lista completa en `meta_fields.py`. Si un laboratorio nuevo aparece en MinIO con un tag `acronym`, hay que añadirlo aquí para que el filtro por lab lo ofrezca.

## `build_meta_fields(profile_name, page, fields_dict, prefill_values=None) → ft.Column`

Construye los controles Flet para `TAG_PROFILES[profile_name]`. Vacía y repuebla `fields_dict` in-place: `key → control con .value`. **No llama `page.update()`** (responsabilidad del caller).

Comportamiento por tipo:

- **`UNISELECT`**: dropdown + `hidden_tf` (guarda el valor real) + `custom_tf` (visible si el usuario selecciona `__custom__`). Si `prefill_values[key]` no está en las opciones, se añade `ft.DropdownOption(key=v, text=f"{v} *")` para mostrarlo marcado.
- **`MULTISELECT`**: dropdown de opciones + chips de seleccionados + `hidden_tf` con `":".join(sorted(vals))`. Permite añadir custom values si `allow_custom`.
- **`MULTIFREETEXT`**: input de texto + botón add + chips + `hidden_tf` con `":".join(sorted(vals))`.
- **`DATE`**: `ft.DatePicker` (locale `en_GB`), formato `YYYY-MM-DD`, `TextField` read-only + icono de calendario.
- **`TEXT`**: `styled_field(label)` de `frontend.py`.

`prefill_values: dict[str, str]` pre-rellena los controles. Usado por el Tag Manager cuando detecta un perfil a partir de los tags existentes de un objeto.

## `detect_profile(tags: dict[str, str]) → str | None`

Detecta automáticamente qué perfil encaja con un dict de tags:

- Criterio: `set(tags.keys()) ⊆ profile_keys` (las keys de los tags deben ser subconjunto de las keys del perfil).
- Si varios perfiles califican, devuelve el de **mayor solapamiento** (`len(tag_keys & profile_keys)`).
- Devuelve `None` si ninguno encaja o si `tags` está vacío.

Usado por el Tag Manager: al seleccionar un fichero, `get_object_tags` → `detect_profile` → si hay match, `build_meta_fields(prefill_values=tags)` para editar con el perfil correcto.

## `build_lab_filter_widget(page, on_select) → (widget, clear_fn)`

Widget "Filter by lab…" con búsqueda en tiempo real:

- `on_select(acronym|None)` — callback al elegir un laboratorio o al limpiar el filtro.
- `clear_fn` — función para resetear el filtro programáticamente.
- Sugerencias = `_matches(query)` contra `LAB_ACRONYMS` (busca en acrónimo y en nombre, case-insensitive).
- Si no hay resultados: "No results".
- Al focar el campo sin texto, muestra todos los labs.

## Uso cruzado

### Formulario de copia (`_build_copy_content`)

- Dropdown de perfil → `build_meta_fields(profile, page, fields_dict)` rellena `fields_dict`.
- Al copiar: se lee `fields_dict[key].value` para cada campo y se pasa a `backend.ejecutar_rclone_copy(..., metadatos_dict=...)`.
- El navegador de buckets de destino incluye `build_lab_filter_widget`; al seleccionar un lab, se filtra la lista de buckets raíz.
- Las secciones METADATA, botones y LOG están ocultas hasta que se selecciona un bucket destino (`on_browser_select` toggle `bottom_col.visible`).

### Tag Manager (`_build_tag_manager_content`)

- Navega buckets/carpetas/ficheros S3 con `list_prefix_contents`.
- Al seleccionar un fichero: `get_object_tags(s3_client, bucket, key)` → `detect_profile(tags)`:
  - Si hay match → `build_meta_fields(profile, page, fields_dict, prefill_values=tags)` para editar con dropdowns/date pickers del perfil.
  - Botón "Ver tags raw" → vuelve a la vista clave/valor cruda.
- Aplica tags con `apply_tags_to_object` (fichero) o `apply_tags_to_prefix` (carpeta/bucket).
- El browser incluye `build_lab_filter_widget`.

## Regla de visibilidad del filtro

El widget "Filter by lab…" solo aparece en el **nivel de buckets (root)** del browser. Al navegar dentro de un bucket se oculta; al volver al root reaparece. **Solo filtra buckets**, no objetos dentro de un bucket. Esto aplica tanto al browser de destino del formulario de copia como al browser del Tag Manager.

## Cómo extender

### Añadir un campo a un perfil existente

1. Añadir la tupla `(label, key, field_type, allow_custom, options, helper)` en `TAG_PROFILES[perfil]`.
2. Si es `UNISELECT` con opciones de lab, reutilizar `LAB_ACRONYMS`.
3. Verificar que el formulario de copia y el Tag Manager lo muestran (no hace falta tocar `main.py`).
4. Si el campo debe ser pre-rellenable, comprobar que `build_meta_fields(prefill_values=...)` lo maneja para ese `field_type`.

### Añadir un perfil nuevo

1. Añadir entrada en `TAG_PROFILES["NuevoPerfil"] = [(...), ...]`.
2. `detect_profile` lo considerará automáticamente (busca superconjunto de keys).
3. El dropdown del formulario de copia y del Tag Manager lo ofrecerá (iteran `TAG_PROFILES`).

### Añadir un laboratorio

1. Añadir `"acr": "Nombre PI"` en `LAB_ACRONYMS`.
2. El filtro por lab y el dropdown `owner` de Histopathology lo ofrecerán automáticamente.
3. Verificar que el `acr` coincide con el tag `acronym` real del bucket en MinIO.
