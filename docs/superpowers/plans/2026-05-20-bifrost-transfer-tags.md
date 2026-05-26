# Tag Manager — bifrost-transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir una pantalla "Tag Manager" en `bifrost-transfer` que permita al usuario navegar buckets/carpetas/ficheros S3 y aplicar tagsets (replace completo) sobre ellos, tanto en desktop como en web (Open OnDemand).

**Architecture:** Cinco funciones boto3 en `backend.py` (S3 tagging sin re-subida de datos). Constante `TAG_PROFILES` en `main.py` que centraliza los campos de metadatos (usada tanto por el formulario de copia existente como por el nuevo Tag Manager). Vista `_build_tag_manager_content` con dos paneles: browser de navegación (izquierda) + editor de tags (derecha), más área de log al fondo. Acceso vía botón "🏷️ Tags" en la toolbar de la vista de copia.

**Tech Stack:** Python 3, Flet (UI), boto3 (S3 API), `configparser` (leer credenciales de rclone.conf), `concurrent.futures.ThreadPoolExecutor` (paralelismo de tagging).

**Spec:** `docs/superpowers/specs/2026-05-20-bifrost-transfer-tags-design.md`

**Nota sobre tests:** El repo no tiene suite automatizada (ver `CLAUDE.md` §Tests). Cada tarea acaba con pasos de validación manual concretos.

---

## File Structure

- **Modificar** `shared/bifrost_backend/backend.py`:
  - 5 funciones nuevas (ya añadidas en esta sesión, pendiente de commit): `get_s3_client_from_profile`, `list_prefix_contents`, `get_object_tags`, `apply_tags_to_prefix`, `apply_tags_to_object`.
- **Modificar** `bifrost-transfer/src/main.py`:
  - Constante `TAG_PROFILES` (ya añadida, pendiente de commit).
  - Refactor `meta_labels` en `_build_copy_content` para usar `TAG_PROFILES["IRB Standard"]` (ya hecho, pendiente de commit).
  - Mejoras UX de servidor: doble-click + botón "← Back" (ya hechos, pendiente de commit).
  - Nueva función `_build_tag_manager_content` (pendiente).
  - Parámetro `on_tags` + botón "🏷️ Tags" en `_build_copy_content` (pendiente).
  - Función `go_tags()` y actualización de `go_copy()` en `main()` (pendiente).

---

## Task 1: Commit cambios ya realizados en esta sesión

Los cambios siguientes ya están en disco pero no commiteados.

**Files:**
- Modify: `shared/bifrost_backend/backend.py` (5 funciones S3)
- Modify: `bifrost-transfer/src/main.py` (TAG_PROFILES, meta_labels, doble-click, back-btn)

- [ ] **Verificar que los cambios del backend están presentes**

```bash
grep -n "def get_s3_client_from_profile\|def list_prefix_contents\|def get_object_tags\|def apply_tags_to_prefix\|def apply_tags_to_object" shared/bifrost_backend/backend.py
```

Resultado esperado: 5 líneas con las definiciones de función.

- [ ] **Verificar que TAG_PROFILES está en main.py**

```bash
grep -n "TAG_PROFILES" bifrost-transfer/src/main.py
```

Resultado esperado: al menos 2 líneas (definición + uso en meta_labels).

- [ ] **Verificar que meta_labels usa TAG_PROFILES**

```bash
grep -n "meta_labels" bifrost-transfer/src/main.py
```

Resultado esperado: `meta_labels = TAG_PROFILES["IRB Standard"]` (una sola línea, sin la lista inline antigua).

- [ ] **Verificar doble-click y back-btn en bifrost-transfer**

```bash
grep -n "on_double_tap\|on_back\|← Back" bifrost-transfer/src/main.py
```

Resultado esperado: líneas para `on_double_tap` en la selección de servidor, `back_btn` y `on_back=go_minio`.

- [ ] **Commit**

```bash
git add shared/bifrost_backend/backend.py bifrost-transfer/src/main.py docs/wiki/log.md docs/superpowers/specs/2026-05-20-bifrost-transfer-tags-design.md
git commit -m "feat(transfer): TAG_PROFILES, UX server selector, S3 tagging backend"
```

---

## Task 2: Parámetro on_tags y botón Tags en _build_copy_content

**Files:**
- Modify: `bifrost-transfer/src/main.py` — función `_build_copy_content` (~línea 1598)

- [ ] **Añadir parámetro `on_tags` a la firma de `_build_copy_content`**

Localizar la firma (busca `web_session: dict | None = None,`) y añadir el parámetro al final:

```python
    web_session: dict | None = None,
    on_back: Callable | None = None,
    on_tags: Callable | None = None,
) -> ft.Control:
```

- [ ] **Crear tags_btn justo después de back_btn y renew_btn**

Localizar la línea `back_btn  = btn_secondary(...)` y añadir debajo:

```python
    tags_btn  = btn_secondary("🏷️ Tags", on_click=lambda e: on_tags()) if on_tags else None
```

- [ ] **Añadir tags_btn al toolbar row**

Localizar la línea del toolbar:
```python
                    [c for c in [back_btn, expiry_badge, ft.Container(expand=True), renew_btn] if c is not None],
```

Cambiarla a:
```python
                    [c for c in [back_btn, tags_btn, expiry_badge, ft.Container(expand=True), renew_btn] if c is not None],
```

- [ ] **Validación manual rápida**

Ejecutar `flet run` en `bifrost-transfer/`. Hacer login, seleccionar servidor → ver que la vista de copia carga sin errores. (El botón Tags no aparecerá todavía porque `on_tags=None` por defecto.)

- [ ] **Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): add on_tags param and Tags button slot in copy view"
```

---

## Task 3: _build_tag_manager_content — estado, browser y navegación

**Files:**
- Modify: `bifrost-transfer/src/main.py` — insertar nueva función antes de la sección `# FUNCIÓN PRINCIPAL`

Busca el comentario `# ============================================================================` que precede a `# FUNCIÓN PRINCIPAL` (hay un bloque `main(page)` allí). Inserta la nueva función justo antes.

- [ ] **Insertar el bloque de estado, log y cliente S3**

```python
# ============================================================================
# VISTA: TAG MANAGER
# ============================================================================

def _build_tag_manager_content(
    page: ft.Page,
    perfil_rclone: str,
    endpoint: str,
    on_back: Callable,
) -> ft.Control:
    # ── Estado ────────────────────────────────────────────────────────────
    s3  = {"client": None}
    nav = {"bucket": None, "prefix": ""}
    sel = {"type": "none", "key": None, "count": 0, "display": ""}
    active_profile  = {"name": list(TAG_PROFILES.keys())[0]}
    tag_fields: dict[str, ft.TextField] = {}
    _log_buffer: list[str] = []
    _current_items = {"folders": [], "files": []}

    # ── Log ───────────────────────────────────────────────────────────────
    log_list = ft.ListView(
        expand=True, auto_scroll=True, spacing=0,
        padding=ft.padding.all(12),
    )
    log_section = ft.Container(
        content=ft.Column([
            ft.Text("LOG", size=10, color=C_TEXT_DIM, weight=ft.FontWeight.W_600,
                    letter_spacing=1.5),
            ft.Container(height=6),
            ft.Container(
                content=log_list,
                bgcolor=C_BG,
                border=ft.border.all(1, C_BORDER),
                border_radius=6,
                height=180,
            ),
        ], spacing=0),
        padding=ft.padding.symmetric(horizontal=24, vertical=8),
        visible=False,
    )

    def _log(msg: str, color: str = C_TEXT) -> None:
        _log_buffer.append(msg)
        def _add():
            log_list.controls.append(
                ft.Text(msg.rstrip("\n"), size=11, color=color,
                        font_family=FONT_MONO, selectable=True)
            )
        backend.ui_call(page, _add)

    def _autosave_tag_log() -> None:
        content = "".join(_log_buffer)
        if not content.strip():
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = pathlib.Path.home() / "bifrost-logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fpath = log_dir / f"bifrost-tags-{ts}.log"
            fpath.write_text(content, encoding="utf-8")
            _log(f"\n📄 Log guardado en: {fpath}", C_TEXT_DIM)
        except Exception as ex:
            _log(f"\n⚠️  No se pudo guardar el log: {ex}", C_WARNING)

    def _get_client():
        if s3["client"] is None:
            s3["client"] = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
        return s3["client"]
```

- [ ] **Insertar los componentes del browser**

Continuación de la función:

```python
    # ── Browser ───────────────────────────────────────────────────────────
    breadcrumb_row = ft.Row(spacing=2, wrap=True)
    browser_col    = ft.Column(spacing=4, tight=True)
    browser_loading = ft.Row(
        [
            ft.ProgressRing(width=14, height=14, stroke_width=2, color=C_PRIMARY),
            ft.Text("Cargando...", size=11, color=C_TEXT_DIM),
        ],
        spacing=8, visible=False,
    )
    browser_error = ft.Text("", color=C_ERROR, size=11, visible=False)
```

- [ ] **Insertar la función _rebuild_breadcrumb**

```python
    def _rebuild_breadcrumb() -> None:
        breadcrumb_row.controls.clear()

        def _crumb(label: str, on_click_fn):
            return ft.TextButton(
                label,
                on_click=on_click_fn,
                style=ft.ButtonStyle(
                    color=C_PRIMARY,
                    padding=ft.padding.symmetric(horizontal=4, vertical=0),
                ),
            )

        breadcrumb_row.controls.append(
            _crumb("buckets", lambda e: _navigate(None, ""))
        )
        if nav["bucket"]:
            breadcrumb_row.controls.append(ft.Text("/", color=C_TEXT_DIM, size=12))
            bname = nav["bucket"]
            breadcrumb_row.controls.append(
                _crumb(bname, lambda e, b=bname: _navigate(b, ""))
            )
            accumulated = ""
            for part in nav["prefix"].split("/"):
                if not part:
                    continue
                accumulated += part + "/"
                acc_copy = accumulated
                breadcrumb_row.controls.append(ft.Text("/", color=C_TEXT_DIM, size=12))
                breadcrumb_row.controls.append(
                    _crumb(part, lambda e, p=acc_copy: _navigate(nav["bucket"], p))
                )
        page.update()
```

- [ ] **Insertar los row builders (bucket, folder, file)**

```python
    def _render_browser_contents() -> None:
        browser_col.controls.clear()
        if nav["bucket"] is None:
            for bname in _current_items["folders"]:
                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.STORAGE_OUTLINED, color=C_PRIMARY, size=16),
                        ft.Text(bname, size=13, color=C_TEXT, expand=True),
                        ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=16),
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=C_SURFACE2, border=ft.border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.padding.symmetric(horizontal=12, vertical=8), ink=True,
                )
                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_tap=lambda e, b=bname: _navigate(b, ""),
                    )
                )
        else:
            for prefix in _current_items["folders"]:
                name = prefix.rstrip("/").split("/")[-1] + "/"
                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
                        ft.Text(name, size=13, color=C_TEXT, expand=True),
                        ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=16),
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=C_SURFACE, border=ft.border.all(1, C_BORDER),
                    border_radius=6,
                    padding=ft.padding.symmetric(horizontal=12, vertical=8), ink=True,
                )
                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_tap=lambda e, p=prefix: _navigate(nav["bucket"], p),
                    )
                )
            for key in _current_items["files"]:
                name    = key.split("/")[-1]
                is_sel  = sel["type"] == "file" and sel["key"] == key
                c = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                color=C_ACCENT if is_sel else C_TEXT_DIM, size=16),
                        ft.Text(name, size=12, color=C_TEXT, expand=True),
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=f"{C_ACCENT}18" if is_sel else C_SURFACE,
                    border=ft.border.all(2 if is_sel else 1, C_ACCENT if is_sel else C_BORDER),
                    border_radius=6,
                    padding=ft.padding.symmetric(horizontal=12, vertical=6), ink=True,
                )
                browser_col.controls.append(
                    ft.GestureDetector(
                        content=c,
                        on_tap=lambda e, k=key: _select_file(k),
                    )
                )

        if not _current_items["folders"] and not _current_items["files"]:
            browser_col.controls.append(
                ft.Text("(sin contenido)", size=11, color=C_TEXT_DIM, italic=True)
            )
        page.update()
```

- [ ] **Insertar la función _navigate y _load_browser**

```python
    def _navigate(bucket: str | None, prefix: str) -> None:
        nav["bucket"] = bucket
        nav["prefix"] = prefix
        sel["type"]   = "none"
        sel["key"]    = None
        sel["count"]  = 0
        sel["display"] = ""
        _current_items["folders"] = []
        _current_items["files"]   = []

        def _reset_editor():
            apply_btn.disabled = True
            target_label.value = "Selecciona una carpeta o fichero"
            obj_count_label.value = ""
            apply_status.value = ""
            apply_status.visible = False
            _rebuild_breadcrumb()
        backend.ui_call(page, _reset_editor)
        backend.safe_thread(page, _load_browser).start()

    def _load_browser() -> None:
        def _set_loading():
            browser_loading.visible = True
            browser_error.visible   = False
            browser_col.controls.clear()
            page.update()
        backend.ui_call(page, _set_loading)

        try:
            client = _get_client()
            if nav["bucket"] is None:
                resp    = client.list_buckets()
                buckets = [b["Name"] for b in resp.get("Buckets", [])]
                _current_items["folders"] = buckets
                _current_items["files"]   = []
            else:
                folders, files = backend.list_prefix_contents(
                    client, nav["bucket"], nav["prefix"]
                )
                _current_items["folders"] = folders
                _current_items["files"]   = files
                # Auto-select current prefix for bulk edit
                _update_prefix_selection()

            def _show():
                browser_loading.visible = False
                _render_browser_contents()
            backend.ui_call(page, _show)

        except Exception as ex:
            def _err():
                browser_loading.visible = False
                browser_error.value     = f"Error: {ex}"
                browser_error.visible   = True
                page.update()
            backend.ui_call(page, _err)
```

- [ ] **Insertar _update_prefix_selection y _select_file**

```python
    def _update_prefix_selection() -> None:
        """Cuenta objetos bajo el prefijo actual y samplea tags del primero."""
        bucket = nav["bucket"]
        prefix = nav["prefix"]
        if not bucket:
            return
        client    = _get_client()
        paginator = client.get_paginator("list_objects_v2")
        count     = 0
        first_key = None
        for pg in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in pg.get("Contents") or []:
                if first_key is None:
                    first_key = obj["Key"]
                count += 1

        tags = {}
        if first_key:
            try:
                tags = backend.get_object_tags(client, bucket, first_key)
            except Exception:
                pass

        label   = f"📁 {prefix or (bucket + '/')} — {count} objeto{'s' if count != 1 else ''}"
        note    = "(tags del primer objeto)" if first_key else "(sin objetos)"
        tags_cp = dict(tags)
        cnt_cp  = count

        def _upd():
            sel["type"]    = "prefix"
            sel["key"]     = None
            sel["count"]   = cnt_cp
            sel["display"] = label
            target_label.value    = label
            obj_count_label.value = note
            apply_btn.disabled    = (cnt_cp == 0)
            _prefill_fields(tags_cp)
        backend.ui_call(page, _upd)

    def _select_file(key: str) -> None:
        def _do():
            client = _get_client()
            try:
                tags = backend.get_object_tags(client, nav["bucket"], key)
            except Exception as ex:
                tags = {}
                def _err():
                    browser_error.value   = f"Error al leer tags: {ex}"
                    browser_error.visible = True
                    page.update()
                backend.ui_call(page, _err)

            display = f"📄 {key}"
            tags_cp = dict(tags)

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
        backend.safe_thread(page, _do).start()
```

- [ ] **Commit parcial**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): tag manager — browser + navigation + S3 client wiring"
```

---

## Task 4: _build_tag_manager_content — editor, apply y layout

**Files:**
- Modify: `bifrost-transfer/src/main.py` — continuación de `_build_tag_manager_content`

- [ ] **Insertar componentes del editor de tags**

Continuación dentro de la función (después de `_select_file`):

```python
    # ── Editor ────────────────────────────────────────────────────────────
    profile_names = list(TAG_PROFILES.keys())
    profile_dd = ft.Dropdown(
        options=[ft.dropdown.Option(p) for p in profile_names],
        value=profile_names[0],
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        text_size=13,
        border_radius=6,
        content_padding=ft.padding.symmetric(horizontal=12, vertical=8),
        width=220,
    )
    tag_fields_col  = ft.Column(spacing=10)
    target_label    = ft.Text("Selecciona una carpeta o fichero",
                               size=12, color=C_TEXT_DIM, italic=True)
    obj_count_label = ft.Text("", size=11, color=C_TEXT_DIM)
    apply_btn       = btn_primary("Apply tags →")
    apply_btn.disabled = True
    apply_status    = ft.Text("", size=12, color=C_TEXT_DIM, visible=False)

    def _rebuild_tag_fields(profile_name: str) -> None:
        active_profile["name"] = profile_name
        tag_fields.clear()
        tag_fields_col.controls.clear()
        for label, key in TAG_PROFILES[profile_name]:
            tf, col = styled_field(label)
            tag_fields[key] = tf
            tag_fields_col.controls.append(col)
        page.update()

    def _prefill_fields(tags: dict[str, str]) -> None:
        for key, tf in tag_fields.items():
            tf.value = tags.get(key, "")
        page.update()

    profile_dd.on_change = lambda e: backend.ui_call(
        page, lambda: _rebuild_tag_fields(e.control.value)
    )
    _rebuild_tag_fields(profile_names[0])
```

- [ ] **Insertar la función do_apply**

```python
    def do_apply(e) -> None:
        tagset = {k: (tf.value or "").strip() for k, tf in tag_fields.items()}
        apply_btn.disabled  = True
        apply_status.value  = "Aplicando tags..."
        apply_status.color  = C_TEXT_DIM
        apply_status.visible = True
        log_section.visible  = True
        page.update()

        def _do():
            client = _get_client()
            bucket = nav["bucket"]
            ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _log(f"### Tags aplicados — {ts} ###\n")
            _log(f"Perfil : {active_profile['name']}\n", C_TEXT_DIM)
            for k, v in tagset.items():
                if v:
                    _log(f"  {k}: {v}\n", C_TEXT_DIM)
            _log("\n")

            try:
                if sel["type"] == "file":
                    _log(f"📄 Fichero: {sel['key']}\n")
                    backend.apply_tags_to_object(client, bucket, sel["key"], tagset)
                    _log(f"  ✓ {sel['key']}\n", C_ACCENT)
                    n_ok = 1
                else:
                    prefix = nav["prefix"]
                    _log(f"📁 Prefijo: {bucket}/{prefix} — {sel['count']} objeto(s)\n")
                    n_ok = backend.apply_tags_to_prefix(
                        client, bucket, prefix, tagset,
                        log_fn=lambda msg: _log(msg),
                    )

                _log(f"\n✅ {n_ok} objeto(s) tagueado(s) correctamente.\n", C_ACCENT)

                def _ok():
                    apply_btn.disabled   = False
                    apply_status.value   = f"✅ {n_ok} objeto(s) actualizados"
                    apply_status.color   = C_ACCENT
                    page.update()
                backend.ui_call(page, _ok)

            except Exception as ex:
                err_str = str(ex)
                _log(f"\n❌ Error: {err_str}\n", C_ERROR)
                def _err():
                    apply_btn.disabled   = False
                    apply_status.value   = "❌ Error al aplicar tags"
                    apply_status.color   = C_ERROR
                    page.update()
                backend.ui_call(page, _err)

            _autosave_tag_log()

        backend.safe_thread(page, _do).start()

    apply_btn.on_click = do_apply
```

- [ ] **Insertar el layout final y el return**

```python
    # ── Layout ────────────────────────────────────────────────────────────
    back_btn = btn_secondary("← Back", on_click=lambda e: on_back())

    content = ft.Column(
        [
            build_header(subtitle="Tag Manager", IS_WEB=IS_WEB),
            ft.Container(
                content=ft.Row(
                    [back_btn, ft.Container(expand=True)],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
            ),
            ft.Container(
                content=ft.Row(
                    [
                        # Panel izquierdo: browser
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text("NAVEGAR", size=10, color=C_TEXT_DIM,
                                            weight=ft.FontWeight.W_600, letter_spacing=1.5),
                                    ft.Container(height=8),
                                    breadcrumb_row,
                                    ft.Container(height=6),
                                    browser_loading,
                                    browser_error,
                                    ft.Container(
                                        content=ft.Column(
                                            [browser_col],
                                            scroll=ft.ScrollMode.AUTO,
                                            spacing=0,
                                        ),
                                        bgcolor=C_SURFACE,
                                        border=ft.border.all(1, C_BORDER),
                                        border_radius=6,
                                        height=400,
                                        padding=ft.padding.all(8),
                                    ),
                                ],
                                spacing=0,
                                width=380,
                            ),
                        ),
                        ft.VerticalDivider(width=1, color=C_BORDER),
                        # Panel derecho: editor
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text("EDITAR TAGS", size=10, color=C_TEXT_DIM,
                                            weight=ft.FontWeight.W_600, letter_spacing=1.5),
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
                                        border=ft.border.all(1, C_BORDER),
                                        border_radius=6,
                                        padding=ft.padding.symmetric(horizontal=12, vertical=8),
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
                            padding=ft.padding.only(left=16),
                            expand=True,
                        ),
                    ],
                    spacing=0,
                    expand=True,
                    vertical_alignment=ft.CrossAxisAlignment.START,
                ),
                padding=ft.padding.symmetric(horizontal=24, vertical=8),
                expand=True,
            ),
            log_section,
        ],
        expand=True,
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )

    backend.safe_thread(page, _load_browser).start()
    return content
```

- [ ] **Verificar que la función cierra bien**

```bash
python -c "import ast; ast.parse(open('bifrost-transfer/src/main.py').read()); print('OK')"
```

Resultado esperado: `OK` (sin errores de sintaxis).

- [ ] **Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): tag manager — editor, apply, log area, layout"
```

---

## Task 5: Conectar go_tags y actualizar go_copy en main()

**Files:**
- Modify: `bifrost-transfer/src/main.py` — función `main(page)`, subfunciones `go_copy` y nueva `go_tags`

- [ ] **Añadir go_tags() dentro de main()**

Localizar `def go_copy():` y añadir justo antes:

```python
    def go_tags():
        show_screen(_build_tag_manager_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            endpoint=state["endpoint"],
            on_back=go_copy,
        ))

```

- [ ] **Actualizar go_copy para pasar on_tags=go_tags**

Dentro de `go_copy()`, en la llamada a `_build_copy_content`, añadir el argumento:

```python
        show_screen(_build_copy_content(
            page,
            perfil_rclone=state["perfil_rclone"],
            mounts_activos=state["mounts_activos"],
            on_close=do_close,
            endpoint=state["endpoint"],
            credenciales_ldap=state["credenciales_ldap"],
            extra_config=extra_config,
            on_renew_complete=go_copy,
            show_screen=show_screen,
            web_session=session,
            on_back=go_minio,
            on_tags=go_tags,          # <-- añadir esta línea
        ))
```

- [ ] **Verificar sintaxis**

```bash
python -c "import ast; ast.parse(open('bifrost-transfer/src/main.py').read()); print('OK')"
```

Resultado esperado: `OK`.

- [ ] **Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(transfer): wire go_tags → Tag Manager accessible from copy view"
```

---

## Task 6: Validación manual

No hay suite automatizada; ejecutar estos pasos con `flet run` en `bifrost-transfer/`.

- [ ] **Verificar que el botón "🏷️ Tags" aparece en la toolbar de la vista de copia**

Hacer login → seleccionar servidor → ver la vista de copia. El botón "🏷️ Tags" debe aparecer entre "← Back" y el badge de expiración de credenciales.

- [ ] **Navegar a la pantalla Tag Manager**

Pulsar "🏷️ Tags" → debe aparecer la nueva pantalla con el encabezado "Tag Manager", un panel izquierdo cargando buckets y un panel derecho con el formulario vacío. El botón "Apply tags →" debe estar deshabilitado.

- [ ] **Navegar buckets y carpetas**

Hacer click en un bucket → ver subcarpetas y ficheros listados. El breadcrumb debe actualizarse. Los campos de tags deben auto-rellenarse con los tags del primer objeto. El contador "N objetos" debe aparecer bajo el formulario.

- [ ] **Seleccionar un fichero**

Hacer click en un fichero de la lista → los campos del editor deben rellenarse con los tags del fichero. El indicador debe cambiar a "📄 path/fichero". El botón "Apply tags →" debe habilitarse.

- [ ] **Aplicar tags a un fichero**

Rellenar al menos un campo → pulsar "Apply tags →" → el área de log debe aparecer y mostrar `✓ path/fichero`. Al terminar debe aparecer `✅ 1 objeto(s) tagueado(s)` y una línea `📄 Log guardado en: ~/bifrost-logs/bifrost-tags-....log`.

Verificar con el cliente S3 o MinIO Console que los tags se han aplicado.

- [ ] **Aplicar tags masivamente a una carpeta**

Navegar a una subcarpeta con varios ficheros (sin seleccionar fichero individual) → rellenar campos → pulsar "Apply tags →" → verificar que el log muestra un `✓` por cada fichero y el resumen final es correcto.

- [ ] **Navegar con el breadcrumb**

Desde dentro de una subcarpeta, hacer click en el bucket en el breadcrumb → debe volver al nivel del bucket. Click en "buckets" → debe mostrar la lista de buckets de nuevo.

- [ ] **Botón "← Back"**

Pulsar "← Back" desde Tag Manager → debe volver a la vista de copia con todos los campos intactos.

- [ ] **Modo web (si es posible probar)**

Ejecutar `BIFROST_DEV=1 flet run` (o `python src/main.py --web`) → verificar que el Tag Manager se carga sin errores en modo web.

- [ ] **Actualizar docs/wiki/log.md**

Añadir la entrada de cierre de tarea:

```markdown
## [2026-05-20] task | Tag Manager en bifrost-transfer

Implementada la pantalla "Tag Manager" en `bifrost-transfer`: navegación de buckets/carpetas/ficheros S3 vía boto3, visualización y edición de tags (replace completo), operación masiva sobre todos los objetos de un prefijo con `ThreadPoolExecutor`, log en pantalla y auto-guardado en `~/bifrost-logs/`. Acceso desde botón "🏷️ Tags" en la toolbar de la vista de copia. Sistema `TAG_PROFILES` centraliza los campos de metadatos para copia y tagging. Disponible en desktop y web (Open OnDemand).
```

- [ ] **Commit final**

```bash
git add docs/wiki/log.md
git commit -m "docs: log entry — Tag Manager feature complete"
```

---

## Self-Review

**Spec coverage:**
- ✅ boto3 directo (Task 3: `_get_client`)
- ✅ Credenciales de rclone.conf (`get_s3_client_from_profile`)
- ✅ Replace completo (`apply_tags_to_prefix` + `apply_tags_to_object`)
- ✅ TAG_PROFILES + selector de perfil (Task 4)
- ✅ Vista dedicada con dos paneles (Task 4, layout)
- ✅ Log en pantalla + auto-save a fichero (Task 4, `_autosave_tag_log`)
- ✅ Navegación con breadcrumb (Task 3)
- ✅ Click en fichero = edición individual (Task 3, `_select_file`)
- ✅ Click en carpeta = navegar + selección masiva (Task 3, `_navigate`)
- ✅ Prefill automático desde el primer objeto (Task 3, `_update_prefix_selection`)
- ✅ `meta_labels` refactorizado para usar `TAG_PROFILES` (Task 1)
- ✅ Web mode: `IS_WEB` pasado a `build_header`, log a `~/bifrost-logs/` (mismo que copy view)
- ✅ Botón "← Back" en Tag Manager → `go_copy` (Task 5)
- ✅ Botón "🏷️ Tags" en toolbar de copia (Task 2)

**Sin TBDs ni placeholders.**

**Consistencia de firmas:**
- `_navigate(bucket, prefix)` referenciada en breadcrumb y row builders: ✅ consistente.
- `_prefill_fields(tags: dict)` definida en Task 4, referenciada en Task 3 (`_update_prefix_selection`, `_select_file`): el compilador lo resolverá porque Python es late-binding en closures. ✅ OK en tiempo de ejecución.
- `apply_btn`, `target_label`, `obj_count_label`, `apply_status`, `log_section` definidos en Task 4 pero referenciados en Task 3 (`_navigate`, `_update_prefix_selection`): misma razón — closures de Python resuelven en tiempo de llamada, no de definición. ✅ OK siempre que el código completo se inserte en el orden correcto (estado/log primero, browser segundo, editor tercero, layout cuarto).

**Nota de orden de inserción:** El código de la función se inserta en 4 bloques dentro de la misma función. El orden correcto en el archivo final es: estado+log+cliente → browser components → row builders+navigate+load → editor+apply+layout+return. Las tareas 3 y 4 lo respetan.
