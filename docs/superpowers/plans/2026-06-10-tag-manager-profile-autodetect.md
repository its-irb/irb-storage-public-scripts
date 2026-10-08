# Tag Manager — Auto-detección de perfil al abrir fichero

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cuando el usuario selecciona un fichero en el Tag Manager, si sus tags coinciden con un perfil conocido, mostrar automáticamente la UI de perfil pre-rellenada con los valores existentes, en lugar de la lista raw de clave/valor.

**Architecture:** Se añade `detect_profile()` a `meta_fields.py` para detectar qué perfil encaja con un diccionario de tags. `build_meta_fields` acepta un nuevo parámetro `prefill_values` para pre-rellenar los controles. En `main.py`, `_populate_file_editor` usa la detección automática y un nuevo botón "Ver tags raw" permite escapar al editor raw.

**Tech Stack:** Python, Flet (UI), `bifrost-transfer/src/meta_fields.py`, `bifrost-transfer/src/main.py`

---

## Mapa de ficheros

| Fichero | Qué cambia |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | Nueva función `detect_profile`; `build_meta_fields` acepta `prefill_values`; `make_multifreetext` y `make_multiselect` devuelven `_sync` |
| `bifrost-transfer/src/main.py` | Import `detect_profile`; nuevo estado `_current_file_tags`; nuevas funciones `_populate_raw_list`, `_switch_to_profile_mode`; `_rebuild_tag_fields` acepta `prefill_values`; `_on_prefill_from_profile` usa `_switch_to_profile_mode`; `_populate_file_editor` detecta perfil; `_select_file` limpia líneas redundantes; botón "Ver tags raw" en layout |
| `README.md` | Sección Tag Manager |
| `CLAUDE.md` | Gotcha #8 |

---

## Task 1: `detect_profile` en `meta_fields.py`

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py` (al final del fichero, antes de `build_lab_filter_widget`)

- [ ] **Añadir la función `detect_profile`**

Insertar justo antes de `def build_lab_filter_widget(` (línea ~373):

```python
def detect_profile(tags: dict[str, str]) -> str | None:
    """Devuelve el perfil cuyas keys son superconjunto de las keys de tags.

    Criterio: set(tags.keys()) ⊆ profile_keys.
    Si varios califican, devuelve el de mayor solapamiento.
    Devuelve None si ninguno encaja o si tags está vacío.
    """
    if not tags:
        return None
    tag_keys = set(tags.keys())
    best_name: str | None = None
    best_score = -1
    for profile_name, fields in TAG_PROFILES.items():
        profile_keys = {item[1] for item in fields}
        if tag_keys <= profile_keys:
            score = len(tag_keys & profile_keys)
            if score > best_score:
                best_score = score
                best_name = profile_name
    return best_name
```

- [ ] **Verificar manualmente la lógica con un test rápido en REPL**

```python
# Desde bifrost-transfer/ con .venv activo:
python -c "
import sys; sys.path.insert(0, 'src')
from meta_fields import detect_profile, TAG_PROFILES

# Debe devolver 'IRB Standard'
print(detect_profile({'project_name': 'X', 'compute_node': 'Y'}))

# Debe devolver 'Histopathology'
print(detect_profile({'owner': 'ccl', 'date': '2024-01-01', 'species': 'mouse'}))

# Key desconocida → None
print(detect_profile({'project_name': 'X', 'unknown_key': 'Y'}))

# Vacío → None
print(detect_profile({}))
"
```

Salida esperada:
```
IRB Standard
Histopathology
None
None
```

- [ ] **Commit**

```bash
git add bifrost-transfer/src/meta_fields.py
git commit -m "feat: add detect_profile to meta_fields"
```

---

## Task 2: `prefill_values` en `build_meta_fields`

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py`

Este task modifica `build_meta_fields` para aceptar valores iniciales. Hay 5 tipos de campo; cada uno necesita su propia lógica de pre-relleno. También modifica `make_multifreetext` y `make_multiselect` para devolver la función `_sync` interna, que se usará para renderizar el estado inicial.

- [ ] **Actualizar la firma de `build_meta_fields`**

Cambiar la línea:
```python
def build_meta_fields(
    profile_name: str,
    page: ft.Page,
    fields_dict: dict,
) -> ft.Column:
```
por:
```python
def build_meta_fields(
    profile_name: str,
    page: ft.Page,
    fields_dict: dict,
    prefill_values: dict[str, str] | None = None,
) -> ft.Column:
```

Y en la primera línea del cuerpo, justo después del docstring, añadir:
```python
    _pre = prefill_values or {}
```

- [ ] **Pre-relleno de TEXT (y NUMBER)**

Al final del bloque `else:  # TEXT (y NUMBER...)`, después de:
```python
            if helper:
                c.controls.append(
                    ft.Text(helper, size=11, color=C_TEXT_DIM, italic=True)
                )
```
añadir:
```python
            if key in _pre:
                tf.value = _pre[key]
```

- [ ] **Pre-relleno de DATE**

Al final del bloque `elif field_type == FieldType.DATE:`, después de:
```python
            col.controls.append(ft.Column([
                ft.Text(label, size=12, color=C_TEXT_DIM),
                ft.Row([
                    date_tf,
                    ft.IconButton(icon=ft.Icons.CALENDAR_MONTH, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=open_fn),
                ], spacing=4),
            ], spacing=4))
```
añadir:
```python
            if key in _pre:
                date_tf.value = _pre[key]
```

- [ ] **`make_multifreetext` debe devolver `_sync`**

Localizar la función `make_multifreetext` dentro de `build_meta_fields`. Cambiar la línea final:
```python
                return input_tf, _add
```
por:
```python
                return input_tf, _add, _sync
```

Y el call site justo debajo:
```python
            input_tf, add_fn = make_multifreetext(selected_vals, chips_row, hidden_tf)
```
por:
```python
            input_tf, add_fn, sync_fn = make_multifreetext(selected_vals, chips_row, hidden_tf)
```

Después del bloque `col.controls.append(field_col)` del tipo MULTIFREETEXT, añadir:
```python
            if key in _pre and _pre[key]:
                for item in [x for x in _pre[key].split(":") if x]:
                    selected_vals["s"].add(item)
                sync_fn()
```

- [ ] **`make_multiselect` debe devolver `_sync`**

Localizar `make_multiselect` dentro de `build_meta_fields`. Cambiar las dos líneas de `return` al final:
```python
                return ctf, _add_custom
            return None, None
```
por:
```python
                return ctf, _add_custom, _sync
            return None, None, _sync
```

Y el call site:
```python
            custom_tf2, add_custom_fn = make_multiselect(
                selected_vals, chips_row, options_dd, hidden_tf, options_list, allow_custom
            )
```
por:
```python
            custom_tf2, add_custom_fn, sync_fn = make_multiselect(
                selected_vals, chips_row, options_dd, hidden_tf, options_list, allow_custom
            )
```

Después del bloque `col.controls.append(ft.Column(col_controls, spacing=6))` del tipo MULTISELECT, añadir:
```python
            if key in _pre and _pre[key]:
                for item in [x for x in _pre[key].split(":") if x]:
                    selected_vals["s"].add(item)
                sync_fn()
```

- [ ] **Pre-relleno de UNISELECT**

En el bloque `if field_type == FieldType.UNISELECT:`, después de `make_uniselect(dd, custom_tf, hidden_tf)` y antes de `fields_dict[key] = hidden_tf`, añadir:

```python
            if key in _pre:
                v = _pre[key]
                option_keys = {
                    opt[0] if isinstance(opt, tuple) else opt
                    for opt in options_list
                }
                if v not in option_keys:
                    dd.options.append(ft.DropdownOption(key=v, text=f"{v} *"))
                dd.value = v
                hidden_tf.value = v
```

- [ ] **Verificar manualmente**

```python
python -c "
import sys; sys.path.insert(0, 'src')
from meta_fields import build_meta_fields, TAG_PROFILES
import flet as ft

# Verificar que la firma acepta prefill_values sin error
class FakePage:
    overlay = []
    def update(self): pass

page = FakePage()
fields = {}
col = build_meta_fields('IRB Standard', page, fields,
    prefill_values={'project_name': 'TestProject', 'compute_node': 'n1'})
print('project_name value:', fields['project_name'].value)
print('compute_node value:', fields['compute_node'].value)
print('sample_type value:', fields['sample_type'].value)  # vacío
"
```

Salida esperada:
```
project_name value: TestProject
compute_node value: n1
sample_type value: 
```

- [ ] **Commit**

```bash
git add bifrost-transfer/src/meta_fields.py
git commit -m "feat: add prefill_values param to build_meta_fields"
```

---

## Task 3: Refactoring de lógica en `main.py`

**Files:**
- Modify: `bifrost-transfer/src/main.py`

Este task hace los cambios de lógica (sin tocar el layout todavía): nuevo estado, nuevas funciones helper, y actualización de las funciones existentes.

- [ ] **Actualizar el import de `meta_fields`**

Localizar la línea (aprox. línea 87):
```python
from meta_fields import FieldType, TAG_PROFILES, build_meta_fields, LAB_ACRONYMS, build_lab_filter_widget
```
Cambiarla por:
```python
from meta_fields import FieldType, TAG_PROFILES, build_meta_fields, detect_profile, LAB_ACRONYMS, build_lab_filter_widget
```

- [ ] **Añadir `_current_file_tags` al estado**

Localizar la línea (aprox. línea 2678):
```python
    _file_tag_rows: list[dict] = []          # freeform editor rows
```
Añadir inmediatamente después:
```python
    _current_file_tags: dict = {"tags": {}}
```

- [ ] **Actualizar `_rebuild_tag_fields` para aceptar `prefill_values`**

Localizar (aprox. línea 3177):
```python
    def _rebuild_tag_fields(profile_name: str, target_container=None, target_fields=None) -> None:
        container = target_container if target_container is not None else card_container
        fields    = target_fields    if target_fields    is not None else tag_fields
        active_profile["name"] = profile_name
        col = build_meta_fields(profile_name, page, fields)
        container.content = card(col, padding=16)
        page.update()
```
Reemplazar por:
```python
    def _rebuild_tag_fields(profile_name: str, target_container=None, target_fields=None, prefill_values=None) -> None:
        container = target_container if target_container is not None else card_container
        fields    = target_fields    if target_fields    is not None else tag_fields
        active_profile["name"] = profile_name
        col = build_meta_fields(profile_name, page, fields, prefill_values=prefill_values)
        container.content = card(col, padding=16)
        page.update()
```

- [ ] **Añadir `_switch_to_profile_mode` y `_populate_raw_list` (antes de `_on_prefill_from_profile`)**

Localizar (aprox. línea 3398):
```python
    def _on_prefill_from_profile(e) -> None:
```

Insertar ANTES de esa función:

```python
    def _switch_to_profile_mode(profile_name: str, prefill_values: dict | None = None) -> None:
        active_profile["name"] = profile_name
        file_editor_mode["mode"] = "profile"
        _file_tags_col.visible      = False
        add_tag_btn.visible         = False
        file_list_headers.visible   = False
        file_card_container.visible = True
        view_raw_btn.visible        = True
        _rebuild_tag_fields(profile_name, target_container=file_card_container,
                            target_fields=file_tag_fields, prefill_values=prefill_values)

    def _populate_raw_list(tags: dict[str, str]) -> None:
        _file_tag_rows.clear()
        _file_tags_col.controls = []
        _file_save_status.visible = False
        for k, v in tags.items():
            rd = _build_file_editor_row(k, v)
            _file_tag_rows.append(rd)
            _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        file_editor_mode["mode"] = "list"
        file_card_container.visible = False
        _file_tags_col.visible      = True
        add_tag_btn.visible         = True
        file_list_headers.visible   = True
        view_raw_btn.visible        = False
        page.update()

```

Nota: `view_raw_btn` se definirá en el Task 4. Como es una closure en Python, la referencia se resuelve en tiempo de llamada, no de definición — no hay problema de orden.

- [ ] **Refactorizar `_on_prefill_from_profile` para usar `_switch_to_profile_mode`**

Localizar:
```python
    def _on_prefill_from_profile(e) -> None:
        profile_name = prefill_profile_dd.value
        active_profile["name"] = profile_name
        file_editor_mode["mode"] = "profile"
        
        _file_tags_col.visible      = False
        add_tag_btn.visible         = False
        file_list_headers.visible   = False
        file_card_container.visible = True
        
        _rebuild_tag_fields(profile_name, target_container=file_card_container, target_fields=file_tag_fields)
```
Reemplazar por:
```python
    def _on_prefill_from_profile(e) -> None:
        _switch_to_profile_mode(prefill_profile_dd.value)
```

- [ ] **Actualizar `_populate_file_editor` para auto-detectar perfil**

Localizar:
```python
    def _populate_file_editor(tags: dict[str, str]) -> None:
        _file_tag_rows.clear()
        _file_tags_col.controls = []
        _file_save_status.visible = False
        for k, v in tags.items():
            rd = _build_file_editor_row(k, v)
            _file_tag_rows.append(rd)
            _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()
```
Reemplazar por:
```python
    def _populate_file_editor(tags: dict[str, str]) -> None:
        _current_file_tags["tags"] = dict(tags)
        detected = detect_profile(tags)
        if detected:
            _switch_to_profile_mode(detected, prefill_values=tags)
            return
        _populate_raw_list(tags)
```

- [ ] **Limpiar líneas redundantes en `_select_file`**

Localizar en la función `_upd()` dentro de `_select_file` (aprox. línea 3140):
```python
                _populate_file_editor(tags_cp)
                file_editor_mode["mode"] = "list"
                file_card_container.visible = False
                _file_tags_col.visible = True
                add_tag_btn.visible = True
                file_list_headers.visible = True
```
Reemplazar por:
```python
                _populate_file_editor(tags_cp)
```
Las líneas de visibilidad son ahora responsabilidad de `_populate_file_editor` (vía `_switch_to_profile_mode` o `_populate_raw_list`).

- [ ] **Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: auto-detect profile in file tag editor"
```

---

## Task 4: Botón "Ver tags raw" en el layout

**Files:**
- Modify: `bifrost-transfer/src/main.py`

- [ ] **Definir `view_raw_btn` y `_on_show_raw`**

Localizar (aprox. línea 3450):
```python
    add_tag_btn = btn_secondary("+ Add tag", on_click=_on_add_tag_row)
    _add_btn_ref["btn"] = add_tag_btn
```
Añadir ANTES de esas líneas:

```python
    def _on_show_raw(e) -> None:
        _populate_raw_list(_current_file_tags["tags"])

    view_raw_btn = ft.TextButton(
        "Ver tags raw",
        on_click=_on_show_raw,
        style=ft.ButtonStyle(color=C_TEXT_DIM),
        visible=False,
    )

```

- [ ] **Insertar `view_raw_btn` en el layout de `_file_editor_section`**

Localizar en el contenido de `_file_editor_section` la sección:
```python
                _file_name_label,
                ft.Container(height=8),
                file_list_headers,
```
Reemplazar por:
```python
                ft.Row(
                    [_file_name_label, view_raw_btn],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=8),
                file_list_headers,
```

- [ ] **Arrancar la app y verificar manualmente**

```bash
# Desde bifrost-transfer/ con .venv activo:
flet run
```

Flujo a verificar:
1. Login → MinIO → entrar al Tag Manager
2. Navegar a un bucket con ficheros tagueados con perfil conocido (p.ej. "IRB Standard")
3. Hacer clic en el fichero → debe aparecer el formulario de perfil con los valores pre-rellenados (no la lista raw)
4. El botón "Ver tags raw" debe estar visible → al pulsarlo debe mostrar la lista raw con los tags originales
5. Navegar a un fichero sin tags → debe aparecer la lista raw vacía (sin botón "Ver tags raw")
6. Navegar a un fichero con tags desconocidos → debe aparecer la lista raw con sus pares clave/valor
7. El botón "Pre-fill" manual (dropdown + botón) sigue funcionando igual
8. Guardar tags en modo perfil y en modo raw debe funcionar correctamente
9. Si un valor de dropdown no existe en las opciones, debe aparecer con `*` al final de las opciones y quedar seleccionado

- [ ] **Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: add 'Ver tags raw' button to file tag editor"
```

---

## Task 5: Documentación

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Actualizar `README.md` — sección Tag Manager**

Localizar (aprox. línea 82-86):
```markdown
### Tag Manager

The Tag Manager lets you browse buckets, folders, and files in S3 and apply metadata tags in bulk — without re-uploading any data. Select a profile, fill in the fields, and apply the tagset to a file, a folder, or an entire bucket prefix.

The Tag Manager bucket browser also includes the same **"Filter by lab…"** field, which works identically to the one in the copy form.
```
Reemplazar por:
```markdown
### Tag Manager

The Tag Manager lets you browse buckets, folders, and files in S3 and apply metadata tags in bulk — without re-uploading any data. Select a profile, fill in the fields, and apply the tagset to a file, a folder, or an entire bucket prefix.

When you select an individual file, if its existing tags match a known profile, the editor automatically switches to the profile view with the values pre-filled — so you can review and edit them using the same dropdowns, date pickers, and multi-value fields used during upload. A **"Ver tags raw"** button lets you switch back to the raw key/value list at any time.

The Tag Manager bucket browser also includes the same **"Filter by lab…"** field, which works identically to the one in the copy form.
```

- [ ] **Actualizar `CLAUDE.md` — gotcha #8**

Localizar:
```markdown
8. **`TAG_PROFILES` y `LAB_ACRONYMS` son la fuente canónica en `bifrost-transfer`**: tanto el formulario de copia como el Tag Manager usan `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS` y `build_lab_filter_widget` de `meta_fields.py`. Si hay que añadir, renombrar o reordenar un campo, perfil o lab, cambiarlo **solo** en `bifrost-transfer/src/meta_fields.py`. El diccionario `LAB_ACRONYMS` debe tener los acrónimos exactos que aparecen en el tag `acronym` de los buckets MinIO.
```
Reemplazar por:
```markdown
8. **`TAG_PROFILES` y `LAB_ACRONYMS` son la fuente canónica en `bifrost-transfer`**: tanto el formulario de copia como el Tag Manager usan `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS` y `build_lab_filter_widget` de `meta_fields.py`. Si hay que añadir, renombrar o reordenar un campo, perfil o lab, cambiarlo **solo** en `bifrost-transfer/src/meta_fields.py`. El diccionario `LAB_ACRONYMS` debe tener los acrónimos exactos que aparecen en el tag `acronym` de los buckets MinIO. La función `detect_profile(tags)` (también en `meta_fields.py`) detecta automáticamente qué perfil encaja con un `dict[str, str]` de tags; `build_meta_fields` acepta un parámetro opcional `prefill_values: dict[str, str]` para pre-rellenar los controles con valores existentes.
```

- [ ] **Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document profile auto-detection in Tag Manager"
```
