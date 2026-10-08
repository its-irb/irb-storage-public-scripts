# Tag Manager — Auto-detección de perfil al abrir fichero

**Fecha:** 2026-06-10  
**Estado:** Aprobado

## Objetivo

Cuando el usuario selecciona un fichero en el Tag Manager y sus tags tienen keys que corresponden a un perfil conocido de `TAG_PROFILES`, mostrar automáticamente la UI de perfil (dropdowns, date pickers, chips, etc.) con los valores pre-rellenados, en lugar del editor raw de clave/valor.

## Criterios de diseño

- **Detección de perfil**: un perfil hace match si `set(tags.keys()) ⊆ set(profile_keys)`. Es decir, todas las keys del fichero deben estar definidas en el perfil (el fichero puede tener menos campos que el perfil, pero ninguna key desconocida).
- **Empate entre perfiles**: se elige el que tiene más keys en común con los tags del fichero (mayor solapamiento). Si aún hay empate, el primero en `TAG_PROFILES`.
- **Valores no reconocidos en dropdown (UNISELECT)**: si el valor guardado no existe entre las opciones del campo, se añade dinámicamente como opción extra al final del dropdown y queda preseleccionado.
- **Escape al modo raw**: cuando el editor está en modo "profile" (sea por autodetección o por "Pre-fill" manual), aparece un botón/link "Ver tags raw" que vuelve al editor de k/v con los tags originales del fichero.

## Cambios

### `bifrost-transfer/src/meta_fields.py`

#### 1. Nueva función `detect_profile`

```python
def detect_profile(tags: dict[str, str]) -> str | None:
    """Devuelve el nombre del perfil cuyas keys son superconjunto de las keys de tags.
    Si varios perfiles califican, devuelve el de mayor solapamiento.
    Devuelve None si ningún perfil encaja.
    """
```

Lógica:
1. Para cada `(profile_name, fields)` en `TAG_PROFILES`:
   - `profile_keys = {item[1] for item in fields}`
   - Si `set(tags.keys()) ⊆ profile_keys` → candidato con score = `len(set(tags.keys()) & profile_keys)`
2. Devolver el candidato con mayor score, o `None` si no hay ninguno.

#### 2. `build_meta_fields` — nuevo parámetro `prefill_values`

```python
def build_meta_fields(
    profile_name: str,
    page: ft.Page,
    fields_dict: dict,
    prefill_values: dict[str, str] = {},
) -> ft.Column:
```

Pre-relleno por tipo de campo (aplicado después de construir el control, antes de añadirlo al layout):

| FieldType | Control en `fields_dict` | Acción |
|---|---|---|
| TEXT / NUMBER | `tf` (TextField) | `tf.value = v` |
| DATE | `date_tf` (TextField read-only) | `date_tf.value = v` |
| UNISELECT | `hidden_tf` | Si `v` en opciones → `dd.value = v`, `hidden_tf.value = v`. Si no → añadir `ft.DropdownOption(key=v, text=f"{v} *")` al final, `dd.value = v`, `hidden_tf.value = v` |
| MULTIFREETEXT | `hidden_tf` | Parsear `v.split(":")`, añadir items a `selected_vals["s"]`, llamar `_sync()` |
| MULTISELECT | `hidden_tf` | Ídem MULTIFREETEXT |

### `bifrost-transfer/src/main.py`

#### `_populate_file_editor(tags)`

Añadir al inicio:
```python
detected = detect_profile(tags)
if detected:
    # guardar tags originales en _current_file_tags para el botón "Ver raw"
    _current_file_tags["tags"] = dict(tags)
    _switch_to_profile_mode(detected, prefill_values=tags)
    return
# si no hay perfil → flujo actual (lista raw)
```

#### `_rebuild_tag_fields` — nuevo parámetro `prefill_values`

```python
def _rebuild_tag_fields(profile_name, target_container=None, target_fields=None, prefill_values=None):
    ...
    col = build_meta_fields(profile_name, page, fields, prefill_values=prefill_values or {})
```

#### `_switch_to_profile_mode(profile_name, prefill_values={})`

Nueva función que encapsula la lógica de `_on_prefill_from_profile` y acepta `prefill_values`. Centraliza el cambio de modo para no duplicar lógica.

#### Botón "Ver tags raw"

- Un `ft.TextButton("Ver tags raw", on_click=_on_show_raw)` visible solo cuando `file_editor_mode["mode"] == "profile"`.
- `_on_show_raw`: restaura `_file_tags_col`, `add_tag_btn`, `file_list_headers` y oculta `file_card_container`. Llama a `_populate_raw_list(_current_file_tags["tags"])`.
- `_populate_raw_list` es el cuerpo actual de `_populate_file_editor` sin la lógica de detección (solo construye filas raw).

#### Estado adicional

```python
_current_file_tags: dict = {"tags": {}}  # tags originales del fichero seleccionado
```

### Documentación

- **`README.md`**: actualizar la sección del Tag Manager para mencionar la auto-detección de perfil y el botón "Ver tags raw".
- **`CLAUDE.md`**: actualizar el gotcha #8 (sobre `TAG_PROFILES` y `build_meta_fields`) para mencionar `detect_profile` y el nuevo parámetro `prefill_values` de `build_meta_fields`.

## Lo que NO cambia

- El flujo de "Pre-fill" manual (dropdown + botón) permanece igual, ahora también usando `_switch_to_profile_mode` internamente.
- La lógica de guardado (`_on_save_file_tags`) no cambia — ya maneja ambos modos.
- El Tag Manager para carpetas (bulk apply) no cambia.
- `build_lab_filter_widget` no cambia.

## Edge cases

- Fichero sin tags: ningún perfil detectado → modo raw (lista vacía, como ahora).
- Fichero con tags que no son subconjunto de ningún perfil: modo raw.
- El botón "Ver tags raw" siempre muestra los tags tal como están en S3 (el snapshot en `_current_file_tags`), no el estado editado.
