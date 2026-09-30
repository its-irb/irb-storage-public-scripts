# Lab Filter for Bucket Browser — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir un widget de filtro por laboratorio encima de la lista de buckets, en el browser de destino de la vista de copia y en el browser del Tag Manager.

**Architecture:** `build_lab_filter_widget` (nuevo en `meta_fields.py`) devuelve el widget de búsqueda con autocomplete y un callback `on_select(acronym|None)`. `build_rclone_browser` recibe dos parámetros opcionales nuevos (`lab_filter_enabled`, `endpoint`) e integra el widget; el Tag Manager lo integra de forma inline. Los tags S3 de cada bucket se leen en paralelo bajo demanda usando `ThreadPoolExecutor`, solo cuando el usuario activa el filtro.

**Tech Stack:** Flet, boto3 (`get_bucket_tagging`), `concurrent.futures.ThreadPoolExecutor`

---

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `bifrost-transfer/src/meta_fields.py` | Añadir `LAB_ACRONYMS` dict y `build_lab_filter_widget()` |
| `shared/bifrost_backend/backend.py` | Añadir `get_bucket_tags()` |
| `bifrost-transfer/src/main.py` | Nuevos imports, extender `build_rclone_browser`, integrar en Tag Manager |

---

## Task 1: `LAB_ACRONYMS` y `build_lab_filter_widget` en `meta_fields.py`

**Files:**
- Modify: `bifrost-transfer/src/meta_fields.py`

- [ ] **Step 1: Añadir import de `Callable`**

En `bifrost-transfer/src/meta_fields.py`, después de la línea `from __future__ import annotations`, añadir:

```python
from collections.abc import Callable
```

- [ ] **Step 2: Añadir `C_SURFACE` al import del frontend**

Línea actual (al inicio del archivo):
```python
from bifrost_frontend.frontend import (
    C_SURFACE2, C_BORDER, C_PRIMARY, C_TEXT, C_TEXT_DIM, C_ACCENT,
    styled_field,
)
```

Cambiar a:
```python
from bifrost_frontend.frontend import (
    C_SURFACE, C_SURFACE2, C_BORDER, C_PRIMARY, C_TEXT, C_TEXT_DIM, C_ACCENT,
    styled_field,
)
```

- [ ] **Step 3: Añadir `LAB_ACRONYMS` después de los imports, antes de `class FieldType`**

```python
LAB_ACRONYMS: dict[str, str] = {
    "adm":    "Administration",
    "sbnb":   "Nuria López-Bigas",
    "batlle": "Eduard Batlle",
    # RELLENAR: añadir aquí el resto de labs con sus acrónimos reales
    # Formato: "acronimo": "Nombre legible del PI / unidad"
    # El acrónimo debe coincidir exactamente con el tag S3 `acronym` del bucket
}
```

- [ ] **Step 4: Añadir `build_lab_filter_widget` al final del archivo, después de `build_meta_fields`**

```python
def build_lab_filter_widget(
    page: ft.Page,
    on_select: Callable[[str | None], None],
) -> tuple[ft.Control, Callable]:
    """Widget de filtro de laboratorio con búsqueda en tiempo real.

    Returns:
        (widget, clear_fn) — el widget Flet y una función para resetear el filtro.
    """
    state = {"acronym": None}

    suggestions_col = ft.Column(spacing=2, tight=True)
    suggestions_container = ft.Container(
        content=suggestions_col,
        bgcolor=C_SURFACE,
        border=ft.Border.all(1, C_BORDER),
        border_radius=6,
        padding=ft.Padding.all(4),
        visible=False,
        max_height=160,
    )

    def _matches(query: str) -> list[tuple[str, str]]:
        q = query.lower()
        return [
            (acr, name) for acr, name in LAB_ACRONYMS.items()
            if q in acr.lower() or q in name.lower()
        ]

    def _render_suggestions(matches: list[tuple[str, str]]) -> None:
        suggestions_col.controls.clear()
        if not matches:
            suggestions_col.controls.append(
                ft.Container(
                    content=ft.Text("No results", size=12, color=C_TEXT_DIM, italic=True),
                    padding=ft.Padding.symmetric(horizontal=8, vertical=6),
                )
            )
        else:
            for acr, name in matches:
                label = f"{name} ({acr})"
                suggestions_col.controls.append(
                    ft.Container(
                        content=ft.Text(label, size=12, color=C_TEXT),
                        bgcolor=C_SURFACE2,
                        border_radius=4,
                        padding=ft.Padding.symmetric(horizontal=8, vertical=6),
                        ink=True,
                        on_click=lambda e, a=acr, l=label: _select(a, l),
                    )
                )
        suggestions_container.visible = True
        page.update()

    def _select(acronym: str, label: str) -> None:
        state["acronym"] = acronym
        search_tf.value = label
        suggestions_container.visible = False
        clear_btn.visible = True
        page.update()
        on_select(acronym)

    def _on_change(e) -> None:
        query = (search_tf.value or "").strip()
        if not query:
            suggestions_container.visible = False
            page.update()
            return
        _render_suggestions(_matches(query))

    def _on_focus(e) -> None:
        query = (search_tf.value or "").strip()
        if query and state["acronym"] is None:
            _render_suggestions(_matches(query))

    def _clear(e=None) -> None:
        state["acronym"] = None
        search_tf.value = ""
        suggestions_col.controls.clear()
        suggestions_container.visible = False
        clear_btn.visible = False
        page.update()
        on_select(None)

    search_tf = ft.TextField(
        hint_text="Filter by lab…",
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        hint_style=ft.TextStyle(color=C_TEXT_DIM),
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
        text_size=12,
        expand=True,
        on_change=_on_change,
        on_focus=_on_focus,
    )

    clear_btn = ft.IconButton(
        icon=ft.Icons.CLOSE,
        icon_color=C_TEXT_DIM,
        icon_size=16,
        visible=False,
        on_click=_clear,
        tooltip="Clear filter",
    )

    widget = ft.Column(
        [
            ft.Row(
                [search_tf, clear_btn],
                spacing=4,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            suggestions_container,
        ],
        spacing=4,
        tight=True,
    )

    return widget, _clear
```

- [ ] **Step 5: Verificar que el módulo importa sin errores**

Desde `bifrost-transfer/` con el venv activo:
```
python -c "from meta_fields import LAB_ACRONYMS, build_lab_filter_widget; print('OK', list(LAB_ACRONYMS.items())[:2])"
```
Esperado: `OK [('adm', 'Administration'), ('sbnb', 'Nuria López-Bigas')]`

- [ ] **Step 6: Commit**

```bash
git add bifrost-transfer/src/meta_fields.py
git commit -m "feat: add LAB_ACRONYMS table and build_lab_filter_widget to meta_fields"
```

---

## Task 2: `get_bucket_tags` en `backend.py`

**Files:**
- Modify: `shared/bifrost_backend/backend.py`

- [ ] **Step 1: Añadir `get_bucket_tags` al final del archivo, junto al bloque de funciones boto3**

Busca la función `apply_tags_to_object` (última función boto3 del archivo) y añade después:

```python
def get_bucket_tags(s3_client, bucket: str) -> dict[str, str]:
    """Devuelve los tags del bucket como dict key→value. Vacío si no hay tags."""
    try:
        resp = s3_client.get_bucket_tagging(Bucket=bucket)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    except Exception:
        return {}
```

- [ ] **Step 2: Verificar que el módulo importa sin errores**

Desde `bifrost-transfer/` con el venv activo:
```
python -c "from bifrost_backend.backend import get_bucket_tags; print('OK')"
```
Esperado: `OK`

- [ ] **Step 3: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat: add get_bucket_tags to backend (reads bucket-level S3 tags)"
```

---

## Task 3: Extender `build_rclone_browser` con filtro de lab

**Files:**
- Modify: `bifrost-transfer/src/main.py`

- [ ] **Step 1: Añadir import de `concurrent.futures`**

Busca el bloque de imports al inicio de `main.py` (alrededor de la línea 53 donde está `import threading`) y añade justo debajo:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
```

- [ ] **Step 2: Actualizar el import de `meta_fields`**

Busca (línea ~86):
```python
from meta_fields import FieldType, TAG_PROFILES, build_meta_fields
```

Cambiar a:
```python
from meta_fields import FieldType, TAG_PROFILES, build_meta_fields, LAB_ACRONYMS, build_lab_filter_widget
```

- [ ] **Step 3: Añadir parámetros opcionales a `build_rclone_browser`**

Busca la firma de la función (línea ~960):
```python
def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str], None],
    initial_path: str = "",
) -> tuple[ft.Column, Callable]:
```

Cambiar a:
```python
def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str], None],
    initial_path: str = "",
    lab_filter_enabled: bool = False,
    endpoint: str | None = None,
) -> tuple[ft.Column, Callable]:
```

- [ ] **Step 4: Añadir estado del filtro y widget, justo después de la línea `nav_state = ...`**

Busca (línea ~975):
```python
    nav_state = {"current_path": "", "timeout": 15}
```

Añadir justo debajo:
```python
    filter_state = {"acronym": None}

    if lab_filter_enabled:
        def _on_lab_select(acronym: str | None) -> None:
            filter_state["acronym"] = acronym
            _navigate("")

        filter_widget, _filter_clear_fn = build_lab_filter_widget(page, _on_lab_select)
        filter_row = ft.Container(
            content=filter_widget,
            visible=True,
            padding=ft.Padding.only(bottom=4),
        )
    else:
        filter_row = ft.Container(visible=False)
```

- [ ] **Step 5: Gestionar visibilidad del filtro en `_navigate`**

Busca el inicio de `_navigate` dentro de `build_rclone_browser` (línea ~1046):
```python
    def _navigate(path: str):
        nav_state["current_path"] = path
        on_select(path)

        loading_row.visible  = True
        error_text.visible   = False
        folder_col.controls.clear()
        _rebuild_breadcrumb()
        page.update()
```

Cambiar a:
```python
    def _navigate(path: str):
        nav_state["current_path"] = path
        on_select(path)

        loading_row.visible  = True
        error_text.visible   = False
        folder_col.controls.clear()
        filter_row.visible   = lab_filter_enabled and not path
        _rebuild_breadcrumb()
        page.update()
```

- [ ] **Step 6: Añadir lógica de filtrado dentro de `_load()`**

Busca dentro de `_navigate → _load()` (línea ~1058):
```python
        def _load():
            try:
                folders = backend.rclone_lsd(perfil_rclone, path, timeout=nav_state["timeout"])
                print(f"[browser] path={path!r} folders={folders}")
```

Cambiar a:
```python
        def _load():
            try:
                folders = backend.rclone_lsd(perfil_rclone, path, timeout=nav_state["timeout"])
                print(f"[browser] path={path!r} folders={folders}")

                if lab_filter_enabled and filter_state["acronym"] and not path:
                    s3 = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        futs = {pool.submit(backend.get_bucket_tags, s3, b): b for b in folders}
                        bucket_acronyms: dict[str, str] = {}
                        for fut in as_completed(futs):
                            b = futs[fut]
                            try:
                                bucket_acronyms[b] = fut.result().get("acronym", "")
                            except Exception:
                                bucket_acronyms[b] = ""
                    active = filter_state["acronym"]
                    folders = [b for b in folders if bucket_acronyms.get(b) == active]
                    print(f"[browser] lab filter={active!r} → {len(folders)} buckets")
```

- [ ] **Step 7: Insertar `filter_row` en `browser_widget`**

Busca la construcción de `browser_widget` (línea ~1256):
```python
    browser_widget = ft.Column(
        [
            ft.Container(
                content=breadcrumb_row,
```

Cambiar a:
```python
    browser_widget = ft.Column(
        [
            filter_row,
            ft.Container(
                content=breadcrumb_row,
```

- [ ] **Step 8: Actualizar el call site en `_build_copy_content`**

Busca (línea ~2185):
```python
    dest_browser, dest_browser_refresh = build_rclone_browser(
        page, perfil_rclone, on_select=on_browser_select, initial_path=_initial_dest
    )
```

Cambiar a:
```python
    dest_browser, dest_browser_refresh = build_rclone_browser(
        page, perfil_rclone,
        on_select=on_browser_select,
        initial_path=_initial_dest,
        lab_filter_enabled=True,
        endpoint=endpoint,
    )
```

- [ ] **Step 9: Verificar en la app**

```
flet run
```

1. Hacer login y llegar a la vista de copia
2. Confirmar que el campo "Filter by lab…" aparece encima de la lista de buckets
3. Escribir "sbnb" → debe aparecer "Nuria López-Bigas (sbnb)" como sugerencia
4. Seleccionarlo → spinner → lista filtrada con solo los buckets del lab
5. Pulsar ✕ → vuelven todos los buckets
6. Navegar dentro de un bucket → el filtro desaparece; volver al root → vuelve el filtro

- [ ] **Step 10: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: add lab filter to copy view bucket browser"
```

---

## Task 4: Integrar filtro en el browser del Tag Manager

**Files:**
- Modify: `bifrost-transfer/src/main.py`

- [ ] **Step 1: Añadir estado del filtro y widget en `_build_tag_manager_content`**

Busca el inicio de la sección del browser del Tag Manager (línea ~2677):
```python
    # ── Browser ───────────────────────────────────────────────────────────
    breadcrumb_row = ft.Row(spacing=2, wrap=True)
    browser_col    = ft.Column(spacing=4, tight=True)
```

Añadir justo debajo de `browser_error = ft.Text(...)`:
```python
    tm_filter_state = {"acronym": None}

    def _on_tm_lab_select(acronym: str | None) -> None:
        tm_filter_state["acronym"] = acronym
        _navigate(None, "")

    tm_filter_widget, _tm_filter_clear_fn = build_lab_filter_widget(page, _on_tm_lab_select)
    tm_filter_row = ft.Container(
        content=tm_filter_widget,
        visible=True,
        padding=ft.Padding.only(bottom=4),
    )
```

- [ ] **Step 2: Modificar `_load_browser` para filtrar buckets cuando hay acrónimo activo**

Busca dentro de `_load_browser` (línea ~2972):
```python
            if nav["bucket"] is None:
                buckets = backend.rclone_lsd(perfil=perfil_rclone, path="")
                _current_items["folders"] = buckets
                _current_items["files"]   = []
```

Cambiar a:
```python
            if nav["bucket"] is None:
                buckets = backend.rclone_lsd(perfil=perfil_rclone, path="")
                if tm_filter_state["acronym"]:
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        futs = {pool.submit(backend.get_bucket_tags, client, b): b for b in buckets}
                        bucket_acronyms: dict[str, str] = {}
                        for fut in as_completed(futs):
                            b = futs[fut]
                            try:
                                bucket_acronyms[b] = fut.result().get("acronym", "")
                            except Exception:
                                bucket_acronyms[b] = ""
                    active = tm_filter_state["acronym"]
                    buckets = [b for b in buckets if bucket_acronyms.get(b) == active]
                    print(f"[tag-manager] lab filter={active!r} → {len(buckets)} buckets")
                _current_items["folders"] = buckets
                _current_items["files"]   = []
```

- [ ] **Step 3: Gestionar visibilidad del `tm_filter_row` en `_navigate` del Tag Manager**

Busca `_reset_editor` dentro de la función `_navigate` del Tag Manager (línea ~2941):
```python
        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Select a folder or a file"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            if _file_editor_section is not None:
                _file_editor_section.visible  = False
                _profile_editor_section.visible = True
                _file_save_status.visible = False
            _rebuild_breadcrumb()
```

Añadir al final de `_reset_editor`, antes del cierre:
```python
            tm_filter_row.visible = (bucket is None)
```

Quedando:
```python
        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Select a folder or a file"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            if _file_editor_section is not None:
                _file_editor_section.visible  = False
                _profile_editor_section.visible = True
                _file_save_status.visible = False
            _rebuild_breadcrumb()
            tm_filter_row.visible = (bucket is None)
```

Nota: `bucket` está disponible en `_reset_editor` porque es una clausura sobre el parámetro de `_navigate(bucket, prefix)`.

- [ ] **Step 4: Insertar `tm_filter_row` en el layout del Tag Manager**

Busca el panel izquierdo del Tag Manager (línea ~3485):
```python
                        ft.Container(height=6),
                        browser_loading,
                        browser_error,
```

Cambiar a:
```python
                        ft.Container(height=6),
                        tm_filter_row,
                        browser_loading,
                        browser_error,
```

- [ ] **Step 5: Verificar en la app**

```
flet run
```

1. Hacer login, ir a Tag Manager (botón "Tag Manager" en la vista de copia)
2. Confirmar que el campo "Filter by lab…" aparece encima de la lista de buckets
3. Escribir un acrónimo → seleccionar lab → lista filtrada
4. Navegar dentro de un bucket → filtro desaparece
5. Volver al root (clic en breadcrumb del perfil) → filtro vuelve con el lab aún seleccionado
6. Pulsar ✕ → vuelven todos los buckets

- [ ] **Step 6: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: add lab filter to Tag Manager bucket browser"
```

---

## Recordatorio post-implementación

Antes de hacer merge, rellenar `LAB_ACRONYMS` en `meta_fields.py` con todos los labs reales (acrónimos deben coincidir exactamente con el tag `acronym` de los buckets en MinIO).
