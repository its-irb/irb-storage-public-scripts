# Meta-fields — `bifrost-transfer/src/meta_fields.py`

Solo existe en `bifrost-transfer`. **Fuente canónica** de perfiles, campos de metadatos y filtro por laboratorio. Tanto el formulario de copia como el Tag Manager usan este módulo. Si hay que añadir, renombrar o reordenar un campo, perfil o lab, cambiarlo **solo** aquí.

## `FieldType` (Enum)

`TEXT`, `UNISELECT`, `MULTISELECT`, `MULTIFREETEXT`, `DATE`, `NUMBER` (NUMBER sin uso actual).

## `TAG_PROFILES: dict[str, list[tuple]]`

Cada tupla: `(label, key, field_type, allow_custom, options_list, helper)`.

### `IRB Standard`
- `project_name`, `compute_node`, `sample_type`, `input_data_type`, `output_data_type`, `requested_by`, `research_group` — todos `TEXT`.

### `Histopathology`
- `owner` — `UNISELECT` con opciones = `LAB_ACRONYMS` ordenadas por nombre (`acr, f"{name} ({acr})"`).
- `users` — `MULTIFREETEXT` (helper: "Enter Linux usernames, add each one separately").
- `date` — `DATE`.
- `provider` — `UNISELECT` (`["Histopathology IRB Core Facility"]`).
- `instrument` — `UNISELECT` (`["Phenoimager", "Nanozoomer"]`).
- `species` — `UNISELECT` (`["mouse", "human", "rat", "pig", "cow"]`).
- `sample_type` — `UNISELECT` (`["tissue section", "organoid", "cell pellet"]`).
- `sample_origin` — `TEXT` (helper explica formato según sample_type).
- `magnification` — `UNISELECT` (`["20x", "40x"]`).
- `channels` — `UNISELECT` (lista de combinaciones DAPI + canales, 4plex/5plex/6plex).

## `LAB_ACRONYMS: dict[str, str]`

29 acrónimos → nombre de PI/lab. **Los acrónimos deben coincidir exactamente con el tag `acronym` de los buckets MinIO** (lo lee `backend.get_bucket_tags`). Ej: `ccl → Eduard Batlle`, `bbg → Nuria López-Bigas`, `pnacmm → Miquel Coll`.

## `build_meta_fields(profile_name, page, fields_dict, prefill_values=None) → ft.Column`

Construye los controles Flet para `TAG_PROFILES[profile_name]`. Vacía y repuebla `fields_dict` in-place: `key → control con .value`. **No llama `page.update()`** (responsabilidad del caller).

- `UNISELECT`: dropdown + `hidden_tf` (valor real) + `custom_tf` (visible si selecciona `__custom__`). Si `prefill_values[key]` no está en opciones, añade `ft.DropdownOption(key=v, text=f"{v} *")`.
- `MULTISELECT` / `MULTIFREETEXT`: chips + `hidden_tf` con valor `":".join(sorted(vals))`.
- `DATE`: `ft.DatePicker` (locale en_GB), formato `YYYY-MM-DD`.
- `TEXT`: `styled_field(label)` de `frontend.py`.

`prefill_values: dict[str, str]` pre-rellena los controles (usado por Tag Manager al detectar perfil).

## `detect_profile(tags: dict[str, str]) → str | None`

Detecta automáticamente qué perfil encaja con un dict de tags. Criterio: `set(tags.keys()) ⊆ profile_keys`. Si varios califican, devuelve el de mayor solapamiento. `None` si ninguno encaja o `tags` vacío. Usado por Tag Manager al seleccionar un fichero.

## `build_lab_filter_widget(page, on_select) → (widget, clear_fn)`

Widget "Filter by lab…" con búsqueda en tiempo real. `on_select(acronym|None)` se llama al elegir/borrar. `clear_fn` resetea el filtro. Sugerencias = `_matches(query)` contra `LAB_ACRONYMS` (acr y nombre, case-insensitive). Vacío → "No results".

## Uso cruzado

- **Formulario de copia** (`_build_copy_content`): dropdown de perfil → `build_meta_fields` rellena `fields_dict`; al copiar, lee `fields_dict[key].value` y pasa a `backend.ejecutar_rclone_copy(..., metadatos_dict=...)`. El navegador de buckets destino incluye `build_lab_filter_widget`.
- **Tag Manager** (`_build_tag_manager_content`): al seleccionar fichero, `get_object_tags` → `detect_profile` → `build_meta_fields(prefill_values=tags)` para editar con el perfil correcto. Botón "Ver tags raw" muestra el dict crudo. Aplica con `apply_tags_to_object` / `apply_tags_to_prefix`. El browser incluye `build_lab_filter_widget`.

## Regla de visibilidad del filtro

El widget "Filter by lab…" solo aparece en el nivel de buckets (root). Al navegar dentro de un bucket se oculta; al volver al root reaparece. Solo filtra buckets, no objetos dentro.
