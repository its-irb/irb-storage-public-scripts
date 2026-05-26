# Tag Manager — Editor freeform de tags por fichero

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cuando el usuario clica un fichero en el Tag Manager, el panel derecho muestra sus tags reales (clave/valor de S3) como filas editables con máximo 10 tags y 256 chars por campo, y un botón "Save tags" para guardar el fichero individual.

**Architecture:** Todo el cambio está en `bifrost-transfer/src/main.py` dentro de `_build_tag_manager_content`. Se añade `_file_editor_section` (editor freeform) y se envuelve el editor existente en `_profile_editor_section`; ambos son `ft.Container` con `visible` alternado según `sel["type"] == "file"`. No se toca el backend — se reutilizan `get_object_tags` y `apply_tags_to_object`.

**Tech Stack:** Python 3.11+, Flet 0.84, boto3 vía `bifrost_backend.backend`. Sin suite de tests automáticos — verificación manual con `flet run` desde `bifrost-transfer/`.

---

### Contexto de código clave

Antes de empezar, ten en cuenta:

- `_build_tag_manager_content` está en `bifrost-transfer/src/main.py` (~línea 2442).
- El bloque de estado comienza en ~línea 2449.
- `apply_btn.on_click = do_apply` está en ~línea 2861.
- El layout del panel derecho ("EDITAR TAGS") está en ~líneas 2908–2956.
- `_select_file` está en ~líneas 2733–2760.
- `_navigate` está en ~líneas 2636–2655.
- Helpers de UI disponibles: `btn_primary`, `btn_secondary`, `card`, `styled_field` (de `bifrost_frontend.frontend`).
- Constantes de color: `C_BG`, `C_SURFACE`, `C_SURFACE2`, `C_BORDER`, `C_PRIMARY`, `C_ACCENT`, `C_WARNING`, `C_ERROR`, `C_TEXT`, `C_TEXT_DIM`.
- Thread-safety: toda mutación de controles desde un hilo background debe ir en `backend.ui_call(page, fn)`. Los hilos se crean con `backend.safe_thread(page, fn).start()`.

---

### Task 1: Añadir variables de estado y todo el código nuevo del editor freeform

**Files:**
- Modify: `bifrost-transfer/src/main.py`

Inserta dos bloques: (A) 3 líneas al bloque de estado y (B) el bloque completo de nuevas funciones/widgets justo antes del comentario `# ── Layout`.

- [ ] **Step 1a: Añadir variables al bloque de estado**

Localiza el bloque de estado al inicio de `_build_tag_manager_content` (el que tiene `s3`, `nav`, `sel`, etc.) y añade estas 3 líneas **al final**, después de `_current_items`:

```python
    _file_tag_rows: list[dict] = []          # filas del editor freeform
    _file_editor_section  = None             # asignado en Task 2, antes del layout
    _profile_editor_section = None           # asignado en Task 2, antes del layout
```

- [ ] **Step 1b: Insertar bloque completo de funciones y widgets del editor freeform**

Localiza la línea `apply_btn.on_click = do_apply` e inserta **inmediatamente después** (antes del comentario `# ── Layout`):

```python
    # ── Editor freeform (fichero individual) ────────────────────────────
    _add_btn_ref  = {"btn": None}   # forward ref — asignado abajo
    _save_btn_ref = {"btn": None}   # forward ref — asignado abajo

    _file_name_label  = ft.Text("", size=12, color=C_TEXT_DIM, italic=True)
    _file_tags_col    = ft.Column(spacing=6, tight=True)
    _file_save_status = ft.Text("", size=12, visible=False)

    def _refresh_add_btn_state() -> None:
        if _add_btn_ref["btn"] is not None:
            _add_btn_ref["btn"].disabled = len(_file_tag_rows) >= 10

    def _build_file_editor_row(key: str = "", value: str = "") -> dict:
        key_tf = ft.TextField(
            value=key, hint_text="Clave",
            bgcolor=C_SURFACE2, border_color=C_BORDER,
            focused_border_color=C_PRIMARY, color=C_TEXT,
            hint_style=ft.TextStyle(color=C_TEXT_DIM),
            border_radius=6,
            content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            text_size=12, max_length=256, expand=1,
        )
        val_tf = ft.TextField(
            value=value, hint_text="Valor",
            bgcolor=C_SURFACE2, border_color=C_BORDER,
            focused_border_color=C_PRIMARY, color=C_TEXT,
            hint_style=ft.TextStyle(color=C_TEXT_DIM),
            border_radius=6,
            content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            text_size=12, max_length=256, expand=2,
        )
        row_dict: dict = {"key_tf": key_tf, "val_tf": val_tf, "row": None}

        def _delete(e, rd=row_dict):
            _file_tag_rows.remove(rd)
            _file_tags_col.controls.remove(rd["row"])
            _refresh_add_btn_state()
            page.update()

        row = ft.Row(
            [
                key_tf, val_tf,
                ft.IconButton(
                    icon=ft.Icons.CLOSE, icon_size=16, icon_color=C_TEXT_DIM,
                    tooltip="Eliminar", on_click=_delete,
                ),
            ],
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        row_dict["row"] = row
        return row_dict

    def _populate_file_editor(tags: dict[str, str]) -> None:
        _file_tag_rows.clear()
        _file_tags_col.controls.clear()
        _file_save_status.visible = False
        for k, v in tags.items():
            rd = _build_file_editor_row(k, v)
            _file_tag_rows.append(rd)
            _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()

    def _on_add_tag_row(e) -> None:
        if len(_file_tag_rows) >= 10:
            return
        rd = _build_file_editor_row()
        _file_tag_rows.append(rd)
        _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()

    def _on_prefill_from_profile(e) -> None:
        existing_keys = {rd["key_tf"].value for rd in _file_tag_rows if rd["key_tf"].value}
        for _lbl, pkey in TAG_PROFILES[active_profile["name"]]:
            if pkey not in existing_keys:
                if len(_file_tag_rows) >= 10:
                    break
                rd = _build_file_editor_row(pkey, "")
                _file_tag_rows.append(rd)
                _file_tags_col.controls.append(rd["row"])
        _refresh_add_btn_state()
        page.update()

    def _on_save_file_tags(e) -> None:
        tagset = {
            rd["key_tf"].value.strip(): rd["val_tf"].value.strip()
            for rd in _file_tag_rows
            if rd["key_tf"].value.strip()
        }
        if _save_btn_ref["btn"] is not None:
            _save_btn_ref["btn"].disabled = True
        _file_save_status.value   = "Guardando..."
        _file_save_status.color   = C_TEXT_DIM
        _file_save_status.visible = True
        page.update()

        def _do():
            client = _get_client()
            try:
                backend.apply_tags_to_object(client, nav["bucket"], sel["key"], tagset)
                def _ok():
                    if _save_btn_ref["btn"] is not None:
                        _save_btn_ref["btn"].disabled = False
                    _file_save_status.value = "✅ Tags guardados"
                    _file_save_status.color = C_ACCENT
                    page.update()
                backend.ui_call(page, _ok)
            except Exception as ex:
                err_str = str(ex)
                def _err():
                    if _save_btn_ref["btn"] is not None:
                        _save_btn_ref["btn"].disabled = False
                    _file_save_status.value = f"❌ Error: {err_str}"
                    _file_save_status.color = C_ERROR
                    page.update()
                backend.ui_call(page, _err)

        backend.safe_thread(page, _do).start()

    add_tag_btn = btn_secondary("+ Añadir tag", on_click=_on_add_tag_row)
    _add_btn_ref["btn"] = add_tag_btn

    prefill_profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=12,
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        width=175,
        on_change=lambda e: active_profile.update({"name": e.control.value}),
    )
    prefill_btn   = btn_secondary("Pre-fill", on_click=_on_prefill_from_profile)
    file_save_btn = btn_primary("Save tags")
    file_save_btn.on_click = _on_save_file_tags
    _save_btn_ref["btn"]   = file_save_btn
```

- [ ] **Step 1c: Verificar que el fichero parsea sin errores**

```powershell
cd C:\Users\operez\irb-storage-public-scripts\bifrost-transfer
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read()); print('OK')"
```

Resultado esperado: `OK`

---

### Task 2: Construir `_file_editor_section` y `_profile_editor_section`, actualizar layout

**Files:**
- Modify: `bifrost-transfer/src/main.py`

Justo después del bloque insertado en Task 1 (los `_save_btn_ref` / `file_save_btn`), todavía antes del comentario `# ── Layout`, añade los dos contenedores de sección y actualiza el layout.

- [ ] **Step 2a: Añadir `_file_editor_section` y `_profile_editor_section`**

Añade inmediatamente después de `_save_btn_ref["btn"] = file_save_btn`:

```python
    _file_editor_section = ft.Container(
        visible=False,
        expand=True,
        content=ft.Column(
            [
                ft.Text("TAGS DEL FICHERO", size=10, color=C_TEXT_DIM,
                        weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                _file_name_label,
                ft.Container(height=8),
                ft.Row(
                    [
                        ft.Text("Clave", size=11, color=C_TEXT_DIM, expand=1),
                        ft.Text("Valor", size=11, color=C_TEXT_DIM, expand=2),
                        ft.Container(width=40),
                    ],
                    spacing=6,
                ),
                ft.Container(height=4),
                _file_tags_col,
                ft.Container(height=8),
                add_tag_btn,
                ft.Container(height=12),
                ft.Divider(height=1, color=C_BORDER),
                ft.Container(height=8),
                ft.Row(
                    [prefill_profile_dd, prefill_btn],
                    spacing=8,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=12),
                ft.Row(
                    [file_save_btn, _file_save_status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=0,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        ),
    )

    _profile_editor_section = ft.Container(
        visible=True,
        expand=True,
        content=ft.Column(
            [
                ft.Text("EDITAR TAGS", size=10, color=C_TEXT_DIM,
                        weight=ft.FontWeight.W_600),
                ft.Container(height=8),
                card(
                    ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Text("Perfil:", size=13, color=C_TEXT),
                                    profile_dd,
                                ],
                                spacing=12,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Container(height=12),
                            tag_fields_col,
                        ],
                        spacing=0,
                    ),
                    padding=16,
                ),
                ft.Container(height=12),
                ft.Container(
                    content=ft.Column(
                        [target_label, obj_count_label],
                        spacing=2,
                    ),
                    bgcolor=C_SURFACE2,
                    border=ft.Border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                ),
                ft.Container(height=12),
                ft.Row(
                    [apply_btn, apply_status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            spacing=0,
            expand=True,
        ),
    )
```

- [ ] **Step 2b: Reemplazar el panel derecho en el layout**

Localiza este bloque en el layout (identifícalo por el comentario y el primer control):

```python
                        # Panel derecho: editor
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text("EDITAR TAGS", size=10, color=C_TEXT_DIM,
                                            weight=ft.FontWeight.W_600),
                                    ft.Container(height=8),
                                    card(
                                        ft.Column(
                                            [
                                                ft.Row(
                                                    [
                                                        ft.Text("Perfil:", size=13, color=C_TEXT),
                                                        profile_dd,
                                                    ],
                                                    spacing=12,
                                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                                ),
                                                ft.Container(height=12),
                                                tag_fields_col,
                                            ],
                                            spacing=0,
                                        ),
                                        padding=16,
                                    ),
                                    ft.Container(height=12),
                                    ft.Container(
                                        content=ft.Column(
                                            [target_label, obj_count_label],
                                            spacing=2,
                                        ),
                                        bgcolor=C_SURFACE2,
                                        border=ft.Border.all(1, C_BORDER),
                                        border_radius=6,
                                        padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                    ),
                                    ft.Container(height=12),
                                    ft.Row(
                                        [apply_btn, apply_status],
                                        spacing=12,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                ],
                                spacing=0,
                                expand=True,
                            ),
                            padding=ft.Padding.only(left=16),
                            expand=True,
                        ),
```

Reemplázalo por:

```python
                        # Panel derecho: editor (freeform para fichero / perfil para carpeta)
                        ft.Container(
                            content=ft.Column(
                                [_file_editor_section, _profile_editor_section],
                                spacing=0,
                                expand=True,
                            ),
                            padding=ft.Padding.only(left=16),
                            expand=True,
                        ),
```

- [ ] **Step 2c: Verificar parseo**

```powershell
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read()); print('OK')"
```

Resultado esperado: `OK`

---

### Task 3: Modificar `_select_file` y `_navigate` para alternar modos

**Files:**
- Modify: `bifrost-transfer/src/main.py`

- [ ] **Step 3a: Modificar `_select_file`**

Localiza la función interna `_upd` dentro de `_select_file` (la que hace `sel["type"] = "file"`). Actualmente:

```python
            def _upd():
                sel["type"]    = "file"
                sel["key"]     = key
                sel["count"]   = 1
                sel["display"] = display
                target_label.value    = display
                obj_count_label.value = ""
                apply_btn.disabled    = False
                _prefill_fields(tags_cp)
                _render_browser_contents()
            backend.ui_call(page, _upd)
```

Reemplázala por:

```python
            def _upd():
                sel["type"]    = "file"
                sel["key"]     = key
                sel["count"]   = 1
                sel["display"] = display
                target_label.value    = display
                obj_count_label.value = ""
                apply_btn.disabled    = False
                _prefill_fields(tags_cp)
                _file_name_label.value = key
                _populate_file_editor(tags_cp)
                if _file_editor_section is not None:
                    _file_editor_section.visible  = True
                    _profile_editor_section.visible = False
                _render_browser_contents()
            backend.ui_call(page, _upd)
```

- [ ] **Step 3b: Modificar `_navigate`**

Localiza la función interna `_reset_editor` dentro de `_navigate`. Actualmente:

```python
        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Selecciona una carpeta o fichero"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            _rebuild_breadcrumb()
        backend.ui_call(page, _reset_editor)
```

Reemplázala por:

```python
        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Selecciona una carpeta o fichero"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            if _file_editor_section is not None:
                _file_editor_section.visible  = False
                _profile_editor_section.visible = True
                _file_save_status.visible = False
            _rebuild_breadcrumb()
        backend.ui_call(page, _reset_editor)
```

- [ ] **Step 3c: Verificar parseo final**

```powershell
python -c "import ast; ast.parse(open('src/main.py', encoding='utf-8').read()); print('OK')"
```

Resultado esperado: `OK`

- [ ] **Step 3d: Commit**

```powershell
git -C "C:\Users\operez\irb-storage-public-scripts" add "bifrost-transfer/src/main.py"
git -C "C:\Users\operez\irb-storage-public-scripts" commit -m "feat(transfer): Tag Manager — freeform file tag editor

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Test manual

**Files:** ninguno

- [ ] **Step 4a: Lanzar la app**

```powershell
cd C:\Users\operez\irb-storage-public-scripts\bifrost-transfer
flet run
```

Haz login y navega al Tag Manager (botón "🏷️ Tags" en la vista de copia).

- [ ] **Step 4b: Verificar panel derecho inicial**

Al entrar al Tag Manager debe verse el editor de perfil ("EDITAR TAGS") en el panel derecho. El editor freeform no debe ser visible.

- [ ] **Step 4c: Verificar selección de carpeta**

Navega a un bucket y entra en una carpeta. El panel derecho debe seguir mostrando el editor de perfil con el conteo de objetos y el botón "Apply tags".

- [ ] **Step 4d: Verificar selección de fichero**

Activa "View files" en una carpeta con ficheros. Clica un fichero. El panel derecho debe:
- Cambiar a "TAGS DEL FICHERO"
- Mostrar el nombre del fichero
- Mostrar filas clave/valor con los tags reales del fichero (o vacío si no tiene tags)
- Mostrar botón "+ Añadir tag"
- Mostrar dropdown de perfil + botón "Pre-fill"
- Mostrar botón "Save tags"

- [ ] **Step 4e: Verificar límites**

Con el fichero seleccionado:
1. Intenta teclear más de 256 caracteres en un campo — debe truncarse.
2. Añade filas hasta llegar a 10 — el botón "+ Añadir tag" debe deshabilitarse.
3. Elimina una fila con [×] — el botón vuelve a habilitarse.

- [ ] **Step 4f: Verificar pre-fill**

Con un fichero seleccionado y 0 tags:
1. Selecciona "IRB Standard" en el dropdown y clica "Pre-fill".
2. Deben aparecer filas con las 7 claves del perfil (`project_name`, `compute_node`, etc.) con valores vacíos.
3. Clica "Pre-fill" de nuevo — no debe duplicar las claves ya existentes.

- [ ] **Step 4g: Verificar guardado**

Rellena algunos valores y clica "Save tags". Debe aparecer "✅ Tags guardados". Navega a otra carpeta y vuelve al mismo fichero — los tags guardados deben aparecer en el editor.

- [ ] **Step 4h: Verificar vuelta al modo perfil**

Con un fichero seleccionado, clica en una carpeta del browser. El panel derecho debe volver al editor de perfil ("EDITAR TAGS").

- [ ] **Step 4i: Commit final si hay correcciones**

Si se hizo alguna corrección durante el test:

```powershell
git -C "C:\Users\operez\irb-storage-public-scripts" add "bifrost-transfer/src/main.py"
git -C "C:\Users\operez\irb-storage-public-scripts" commit -m "fix(transfer): Tag Manager freeform editor corrections

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```
- [ ] **Step 5: Documentar**
Documentar el README, el CLAUDE.md y el CLAUDE_WIKI.md con los cambios aplicados. 