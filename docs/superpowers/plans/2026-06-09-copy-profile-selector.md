# Copy Profile Selector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir un selector de perfil de metadatos al formulario de copia de bifrost-transfer, con los mismos controles ricos que el Tag Manager, confirmación al cambiar y persistencia en sesión web.

**Architecture:** Se extrae `FieldType`, `TAG_PROFILES` y la lógica de construcción de controles a un nuevo módulo `src/meta_fields.py`. El formulario de copia y el Tag Manager usan la nueva función `build_meta_fields`. El formulario de copia gana un dropdown de perfil + contenedor dinámico + diálogo de confirmación.

**Tech Stack:** Python 3.11+, Flet (ft), bifrost_frontend.frontend

---

## Ficheros afectados

| Fichero | Cambio |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | **Nuevo** — FieldType, TAG_PROFILES, build_meta_fields |
| `bifrost-transfer/src/main.py` | Eliminar FieldType+TAG_PROFILES, importar desde meta_fields, refactorizar sección de metadatos en _build_copy_content, simplificar _rebuild_tag_fields, actualizar _ws_save |

---

### Task 1: Crear `bifrost-transfer/src/meta_fields.py`

**Files:**
- Create: `bifrost-transfer/src/meta_fields.py`

- [ ] **Step 1: Crear el fichero con FieldType, TAG_PROFILES y build_meta_fields**

Crear `bifrost-transfer/src/meta_fields.py` con el contenido completo siguiente. Es código extraído de `main.py` (líneas 92–133 para FieldType/TAG_PROFILES, y lógica adaptada de `_rebuild_tag_fields` líneas 3057–3394 para build_meta_fields):

```python
from __future__ import annotations
from enum import Enum
import flet as ft
from bifrost_frontend.frontend import (
    C_SURFACE2, C_BORDER, C_PRIMARY, C_TEXT, C_TEXT_DIM, C_ACCENT,
    styled_field,
)


class FieldType(Enum):
    TEXT          = "text"
    UNISELECT     = "uniselect"
    MULTISELECT   = "multiselect"
    MULTIFREETEXT = "multifreetext"
    DATE          = "date"
    NUMBER        = "number"


TAG_PROFILES: dict[str, list[tuple]] = {
    "IRB Standard": [
        ("Project",          "project_name",     FieldType.TEXT, False, None, None),
        ("Host machine",     "compute_node",      FieldType.TEXT, False, None, None),
        ("Sample type",      "sample_type",       FieldType.TEXT, False, None, None),
        ("Input data type",  "input_data_type",   FieldType.TEXT, False, None, None),
        ("Output data type", "output_data_type",  FieldType.TEXT, False, None, None),
        ("Requested by",     "requested_by",      FieldType.TEXT, False, None, None),
        ("Research group",   "research_group",    FieldType.TEXT, False, None, None),
    ],
    "Histopathology": [
        ("Owner", "owner", FieldType.UNISELECT, False, [
            "Eduard Batlle", "Direna Alonso-Curbelo", "Alexandra Avgustinova", "Roger Gomis",
            "Cayetano González", "Nuria López-Bigas", "Angel R. Nebreda", "Antoni Riera",
            "Fran Supek", "Salvador Aznar Benitah", "Xavier Salvatella",
            "Ana Victoria Lechuga-Vieco", "Manuel Palacín", "Lluis Ribas",
            "Alejo Rodríguez-Fraticelli", "Stefanie Wculek", "Antonio Zorzano",
            "Marco Milán", "Patrick Aloy", "Toni Gabaldón", "Jens Lüders",
            "María Macías", "Cristina Mayor-Ruiz", "Raúl Méndez",
            "Francesc Posas/ Eulalia de Nadal", "Modesto Orozco", "Ferran Azorin",
            "Jordi Casanova", "Miquel Coll",
        ], None),
        ("Users",         "users",         FieldType.MULTIFREETEXT, False, None,
         "Enter Linux usernames, add each one separately"),
        ("Date",          "date",          FieldType.DATE,      False, None, None),
        ("Provider",      "provider",      FieldType.UNISELECT, False,
         ["Histopathology IRB Core Facility"], None),
        ("Instrument",    "instrument",    FieldType.UNISELECT, False,
         ["Phenoimager", "Nanozoomer"], None),
        ("Species",       "species",       FieldType.UNISELECT, False,
         ["mouse", "human", "rat", "pig", "cow"], None),
        ("Sample Type",   "sample_type",   FieldType.UNISELECT, False,
         ["tissue section", "organoid", "cell pellet"], None),
        ("Sample Origin", "sample_origin", FieldType.TEXT, False, None,
         "Specify the biological source depending on the sample type:\n"
         "- For Tissue: enter tissue type (e.g., Lung, Colon)\n"
         "- For Organoid: enter organoid type/model (e.g., Colorectal Organoid)\n"
         "- For Cell Pellet: enter cell line origin (e.g., HeLa, HEK293)"),
        ("Magnification", "magnification", FieldType.UNISELECT, False,
         ["20x", "40x"], None),
        ("Channels",      "channels",      FieldType.UNISELECT, False, [
            "Brightfield", "DAPI", "DAPI + 488", "DAPI + 568", "DAPI + 647",
            "DAPI + 488 + 568", "DAPI + 488 + 647", "DAPI + 568 + 647",
            "DAPI + 488 + 568 + 647", "4plex", "5plex", "6plex",
        ], None),
    ],
}


def build_meta_fields(
    profile_name: str,
    page: ft.Page,
    fields_dict: dict,
) -> ft.Column:
    """Builds Flet controls for TAG_PROFILES[profile_name].

    Clears and repopulates fields_dict in-place: key → control with .value.
    Returns a ft.Column ready to insert into the widget tree.
    Does NOT call page.update() — that is the caller's responsibility.
    """
    fields_dict.clear()
    col = ft.Column(spacing=10)

    for item in TAG_PROFILES[profile_name]:
        label        = item[0]
        key          = item[1]
        field_type   = item[2]
        allow_custom = item[3]
        options_list = item[4]
        helper       = item[5] if len(item) > 5 else None

        if field_type == FieldType.UNISELECT:
            CUSTOM_KEY = "__custom__"

            custom_tf = ft.TextField(
                hint_text="Custom value...",
                bgcolor=C_SURFACE2,
                border_color=C_BORDER,
                focused_border_color=C_PRIMARY,
                color=C_TEXT,
                text_size=12,
                border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                expand=True,
                visible=False,
            )
            hidden_tf = ft.TextField(visible=False, value="")

            def make_uniselect(dd_ref, custom_ref, hidden_ref):
                def _on_select(e):
                    val = dd_ref.value
                    if val == CUSTOM_KEY:
                        custom_ref.visible = True
                        hidden_ref.value = custom_ref.value or ""
                    else:
                        custom_ref.visible = False
                        hidden_ref.value = val or ""
                    page.update()

                def _on_custom_change(e):
                    hidden_ref.value = custom_ref.value or ""

                dd_ref.on_select   = _on_select
                custom_ref.on_change = _on_custom_change

            dd = ft.Dropdown(
                options=(
                    [ft.DropdownOption(key="", text="")] +
                    [ft.DropdownOption(key=opt, text=opt) for opt in options_list] +
                    ([ft.DropdownOption(key=CUSTOM_KEY, text="✏️ Custom value...")]
                     if allow_custom else [])
                ),
                value="",
                bgcolor=C_SURFACE2,
                border_color=C_BORDER,
                focused_border_color=C_PRIMARY,
                color=C_TEXT,
                text_size=13,
                border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                expand=True,
            )
            make_uniselect(dd, custom_tf, hidden_tf)
            fields_dict[key] = hidden_tf
            col.controls.append(ft.Column(
                [ft.Text(label, size=12, color=C_TEXT_DIM), dd, custom_tf, hidden_tf],
                spacing=4,
            ))

        elif field_type == FieldType.MULTISELECT:
            selected_vals = {"s": set()}
            chips_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
            hidden_tf = ft.TextField(visible=False, value="")
            fields_dict[key] = hidden_tf

            def make_multiselect(sel, chips, dd_ref, hidden, opts, custom):
                def _sync():
                    chips.controls.clear()
                    for v in sorted(sel["s"]):
                        def make_delete(val):
                            def _del(e):
                                sel["s"].discard(val)
                                _sync()
                                page.update()
                            return _del
                        chips.controls.append(ft.Chip(
                            label=ft.Text(v, size=12, color=C_TEXT),
                            bgcolor=f"{C_ACCENT}22",
                            on_delete=make_delete(v),
                            delete_icon_color=C_TEXT_DIM,
                        ))
                    hidden.value = ":".join(sorted(sel["s"]))
                    dd_ref.options = [
                        ft.DropdownOption(
                            key=opt, text=opt,
                            content=ft.Row([
                                ft.Icon(ft.Icons.CHECK, size=14, color=C_ACCENT,
                                        visible=opt in sel["s"]),
                                ft.Text(opt, size=12, color=C_TEXT),
                            ]),
                        )
                        for opt in opts
                    ]

                def _on_select(e):
                    val = dd_ref.value
                    if val and val not in sel["s"]:
                        sel["s"].add(val)
                    dd_ref.value = None
                    _sync()
                    page.update()

                dd_ref.on_select = _on_select

                if custom:
                    ctf = ft.TextField(
                        hint_text="Custom value...",
                        bgcolor=C_SURFACE2, border_color=C_BORDER,
                        focused_border_color=C_PRIMARY, color=C_TEXT,
                        text_size=12, border_radius=6,
                        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                        expand=True,
                    )
                    def _add_custom(e):
                        val = ctf.value.strip()
                        if val and val not in sel["s"]:
                            sel["s"].add(val)
                            ctf.value = ""
                            _sync()
                            page.update()
                    return ctf, _add_custom
                return None, None

            options_dd = ft.Dropdown(
                options=[ft.DropdownOption(key=opt, text=opt) for opt in options_list],
                hint_text="Select...",
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                text_size=12, border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                expand=True,
            )
            custom_tf2, add_custom_fn = make_multiselect(
                selected_vals, chips_row, options_dd, hidden_tf, options_list, allow_custom
            )
            col_controls = [ft.Text(label, size=12, color=C_TEXT_DIM), options_dd, chips_row]
            if allow_custom and custom_tf2:
                col_controls.insert(2, ft.Row([
                    custom_tf2,
                    ft.IconButton(icon=ft.Icons.ADD, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=add_custom_fn),
                ], spacing=4))
            col_controls.append(hidden_tf)
            col.controls.append(ft.Column(col_controls, spacing=6))

        elif field_type == FieldType.MULTIFREETEXT:
            selected_vals = {"s": set()}
            chips_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
            hidden_tf = ft.TextField(visible=False, value="")
            fields_dict[key] = hidden_tf

            def make_multifreetext(sel, chips, hidden):
                def _sync():
                    chips.controls.clear()
                    for v in sorted(sel["s"]):
                        def make_delete(val):
                            def _del(e):
                                sel["s"].discard(val)
                                _sync()
                                page.update()
                            return _del
                        chips.controls.append(ft.Chip(
                            label=ft.Text(v, size=12, color=C_TEXT),
                            bgcolor=f"{C_ACCENT}22",
                            on_delete=make_delete(v),
                            delete_icon_color=C_TEXT_DIM,
                        ))
                    hidden.value = ":".join(sorted(sel["s"]))

                input_tf = ft.TextField(
                    hint_text="Add value...",
                    bgcolor=C_SURFACE2, border_color=C_BORDER,
                    focused_border_color=C_PRIMARY, color=C_TEXT,
                    text_size=12, border_radius=6,
                    content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                    expand=True,
                )

                def _add(e):
                    val = input_tf.value.strip()
                    if val and val not in sel["s"]:
                        sel["s"].add(val)
                        input_tf.value = ""
                        _sync()
                        page.update()

                input_tf.on_submit = _add
                return input_tf, _add

            input_tf, add_fn = make_multifreetext(selected_vals, chips_row, hidden_tf)
            field_col = ft.Column([
                ft.Text(label, size=12, color=C_TEXT_DIM),
                ft.Row([
                    input_tf,
                    ft.IconButton(icon=ft.Icons.ADD, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=add_fn),
                ], spacing=4),
                chips_row,
                hidden_tf,
            ], spacing=6)
            if helper:
                field_col.controls.append(
                    ft.Text(helper, size=11, color=C_TEXT_DIM, italic=True)
                )
            col.controls.append(field_col)

        elif field_type == FieldType.DATE:
            def make_date_picker(tf):
                def _on_change(e):
                    if e.control.value:
                        d = e.control.value.astimezone()
                        tf.value = f"{d.year}-{d.month:02d}-{d.day:02d}"
                        page.update()
                picker = ft.DatePicker(on_change=_on_change, locale=ft.Locale("en", "GB"))
                page.overlay.append(picker)
                def _open(e):
                    picker.open = True
                    page.update()
                return _open

            date_tf = ft.TextField(
                read_only=True,
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                text_size=13, border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                expand=True,
            )
            open_fn = make_date_picker(date_tf)
            date_tf.on_click = open_fn
            fields_dict[key] = date_tf
            col.controls.append(ft.Column([
                ft.Text(label, size=12, color=C_TEXT_DIM),
                ft.Row([
                    date_tf,
                    ft.IconButton(icon=ft.Icons.CALENDAR_MONTH, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=open_fn),
                ], spacing=4),
            ], spacing=4))

        else:  # TEXT (y NUMBER, actualmente sin usar)
            tf, c = styled_field(label)
            fields_dict[key] = tf
            tf.expand = True
            col.controls.append(c)
            if helper:
                c.controls.append(
                    ft.Text(helper, size=11, color=C_TEXT_DIM, italic=True)
                )

    return col
```

- [ ] **Step 2: Verificar que el fichero se puede importar sin errores**

Desde `bifrost-transfer/`:
```bash
# Activar el venv si no está activo
# .\.venv\Scripts\Activate.ps1  (Windows)
python -c "from meta_fields import FieldType, TAG_PROFILES, build_meta_fields; print('OK', list(TAG_PROFILES.keys()))"
```
Salida esperada:
```
OK ['IRB Standard', 'Histopathology']
```

- [ ] **Step 3: Commit**

```bash
git add bifrost-transfer/src/meta_fields.py
git commit -m "feat: add meta_fields module (FieldType, TAG_PROFILES, build_meta_fields)"
```

---

### Task 2: Actualizar `main.py` — imports y `_ws_save`

**Files:**
- Modify: `bifrost-transfer/src/main.py:92-133` (eliminar FieldType y TAG_PROFILES)
- Modify: `bifrost-transfer/src/main.py` (añadir import, actualizar _ws_save)

- [ ] **Step 1: Reemplazar la definición de `FieldType` y `TAG_PROFILES` por el import**

En `main.py`, las líneas 92–133 contienen la clase `FieldType` y el dict `TAG_PROFILES`.  
Eliminar ese bloque completo y sustituirlo por:

```python
from meta_fields import FieldType, TAG_PROFILES, build_meta_fields
```

La línea `class FieldType(Enum):` empieza en la línea 92. El bloque termina en la línea 133 (cierre del dict `TAG_PROFILES`). Dejar una línea en blanco después del import nuevo.

- [ ] **Step 2: Añadir `copy_tag_profile` a `_ws_save`**

En `_ws_save` (línea ~174), dentro del dict que se asigna a `_WEB_SESSIONS[usuario]`, hay un bloque de "copy state — always inherited". Añadir la clave `copy_tag_profile` a ese bloque:

Buscar este fragmento (líneas ~190–198):
```python
        # copy state — always inherited so a running copy survives reconnection
        "copy_log_buffer":    existing.get("copy_log_buffer", []),
        "copy_status":        existing.get("copy_status", "idle"),
        "copy_origen":        existing.get("copy_origen", ""),
        "copy_destino":       existing.get("copy_destino", ""),
        "copy_log_callbacks": existing.get("copy_log_callbacks", []),
```

Añadir al final de ese bloque:
```python
        "copy_tag_profile":   existing.get("copy_tag_profile", list(TAG_PROFILES.keys())[0]),
```

- [ ] **Step 3: Verificar que la app arranca sin errores de import**

```bash
python -c "import sys; sys.argv=['main']; import main" 2>&1 | head -5
```
No debe haber `ImportError` ni `NameError`. (Puede haber otros errores por falta de entorno Flet, lo que es normal.)

- [ ] **Step 4: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "refactor: move FieldType/TAG_PROFILES to meta_fields, persist copy_tag_profile in session"
```

---

### Task 3: Refactorizar la sección de metadatos en `_build_copy_content`

**Files:**
- Modify: `bifrost-transfer/src/main.py:1855-1866` (sección de metadatos)
- Modify: `bifrost-transfer/src/main.py:2418-2420` (layout — `card(meta_grid)`)

- [ ] **Step 1: Reemplazar la construcción estática de campos**

Localizar el bloque que empieza en línea ~1855:
```python
    # ── Metadatos ──────────────────────────────────────────────────────────
    meta_labels = TAG_PROFILES["IRB Standard"]
    meta_fields: dict[str, ft.TextField] = {}
    meta_controls = []
    for label, key, field_type, allow_custom, options_list, helper in TAG_PROFILES["IRB Standard"]:
        tf, col = styled_field(label)
        meta_fields[key] = tf
        meta_controls.append(col)

    meta_left  = ft.Column(meta_controls[:4], spacing=10, expand=True)
    meta_right = ft.Column(meta_controls[4:], spacing=10, expand=True)
    meta_grid  = ft.Row([meta_left, meta_right], spacing=16, expand=True)
```

Sustituirlo por:
```python
    # ── Metadatos ──────────────────────────────────────────────────────────
    _initial_profile = (
        web_session.get("copy_tag_profile") if (IS_WEB and web_session) else None
    ) or list(TAG_PROFILES.keys())[0]
    active_copy_profile = {"name": _initial_profile}

    meta_fields: dict = {}
    meta_container = ft.Container()

    def _rebuild_meta(profile_name: str):
        col = build_meta_fields(profile_name, page, meta_fields)
        meta_container.content = col

    _rebuild_meta(active_copy_profile["name"])

    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in TAG_PROFILES.keys()],
        value=active_copy_profile["name"],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        expand=True,
    )

    def _on_profile_change(e):
        new_profile = profile_dd.value
        if new_profile == active_copy_profile["name"]:
            return

        def _do_switch():
            _rebuild_meta(new_profile)
            active_copy_profile["name"] = new_profile
            if IS_WEB and web_session is not None:
                web_session["copy_tag_profile"] = new_profile
            page.update()

        def _cancel():
            profile_dd.value = active_copy_profile["name"]
            page.update()

        show_confirm(
            page,
            "Change profile",
            "Changing the profile will clear all metadata. Continue?",
            on_yes=_do_switch,
            on_no=_cancel,
        )

    profile_dd.on_change = _on_profile_change

    profile_row = ft.Row(
        [
            ft.Text("Metadata profile", size=12, color=C_TEXT_DIM, width=130),
            profile_dd,
        ],
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=8,
    )
```

- [ ] **Step 2: Actualizar el layout — reemplazar `card(meta_grid)` por profile_row + meta_container**

Localizar en el layout (línea ~2418–2420):
```python
                        section_title("METADATA"),
                        ft.Container(height=10),
                        card(meta_grid),
```

Sustituir por:
```python
                        section_title("METADATA"),
                        ft.Container(height=6),
                        profile_row,
                        ft.Container(height=10),
                        card(meta_container),
```

- [ ] **Step 3: Verificar manualmente — arrancar la app y probar**

```bash
cd bifrost-transfer
flet run
```

Verificar:
1. El formulario de copia muestra el selector "Metadata profile" con "IRB Standard" seleccionado por defecto.
2. Los 7 campos de texto de IRB Standard se renderizan correctamente.
3. Al cambiar a "Histopathology" aparece el diálogo de confirmación.
4. Si se pulsa "No", el dropdown vuelve a "IRB Standard" y los campos no cambian.
5. Si se pulsa "Yes", aparecen los 10 campos de Histopathology con sus controles propios (dropdown Owner, datepicker Date, multi-freetext Users, etc.).
6. Al rellenar campos y pulsar Copy, los metadatos aparecen en el log con los valores correctos.

- [ ] **Step 4: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: profile selector in copy form with confirmation dialog and session persistence"
```

---

### Task 4: Simplificar `_rebuild_tag_fields` en `_build_tag_manager_content`

**Files:**
- Modify: `bifrost-transfer/src/main.py:3057-3394`

- [ ] **Step 1: Reemplazar el cuerpo de `_rebuild_tag_fields`**

La función `_rebuild_tag_fields` (líneas 3057–3394) tiene ~337 líneas. Sustituir todo el cuerpo por:

```python
    def _rebuild_tag_fields(profile_name: str, target_container=None, target_fields=None) -> None:
        container = target_container if target_container is not None else card_container
        fields    = target_fields    if target_fields    is not None else tag_fields
        active_profile["name"] = profile_name
        col = build_meta_fields(profile_name, page, fields)
        container.content = card(col, padding=16)
        page.update()
```

Nota: `build_meta_fields` ya llama a `fields.clear()` internamente, así que no hace falta llamarlo aquí. La línea `active_profile["name"] = profile_name` se mantiene porque el Tag Manager la usa para saber el perfil activo al aplicar tags.

- [ ] **Step 2: Verificar manualmente — Tag Manager sigue funcionando**

```bash
cd bifrost-transfer
flet run
```

Verificar:
1. El Tag Manager abre con el primer perfil ("IRB Standard") por defecto.
2. El selector de perfil del Tag Manager cambia los campos correctamente (sin diálogo de confirmación — el Tag Manager no lo necesita).
3. Los campos de Histopathology en el Tag Manager siguen mostrando los controles ricos (dropdown, datepicker, etc.).
4. Aplicar tags desde el Tag Manager sigue funcionando.

- [ ] **Step 3: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "refactor: simplify _rebuild_tag_fields using build_meta_fields helper"
```

---

## Self-review del plan

**Cobertura del spec:**
- ✅ Nuevo módulo `meta_fields.py` con FieldType, TAG_PROFILES, build_meta_fields → Task 1
- ✅ Import en main.py → Task 2
- ✅ Selector de perfil con dropdown → Task 3
- ✅ Controles ricos (UNISELECT, DATE, MULTIFREETEXT) → Task 1 (build_meta_fields)
- ✅ Confirmación al cambiar perfil → Task 3
- ✅ Persistencia en sesión web (`copy_tag_profile`) → Tasks 2 y 3
- ✅ Simplificación de `_rebuild_tag_fields` → Task 4
- ✅ `do_copy()` sin cambios — `{k: tf.value ...}` funciona para todos los tipos → verificado en Task 3

**Sin placeholders ni TBDs.**

**Consistencia de tipos:** `build_meta_fields` devuelve `ft.Column`; `meta_container.content = col` lo asigna correctamente; `card(meta_container)` lo envuelve en el layout. `_rebuild_tag_fields` hace `container.content = card(col, padding=16)` — correcto, el Tag Manager envuelve en card con padding.
