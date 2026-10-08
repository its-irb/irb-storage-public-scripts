# Copy Form Bucket Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hide METADATA/buttons/log sections in the copy form until the user selects a bucket, and use a distinct icon for buckets vs subfolders in the rclone browser.

**Architecture:** Two small, isolated edits to `bifrost-transfer/src/main.py` — (1) wrap the bottom layout sections in a toggled `ft.Column`, (2) pick icon based on whether the current browser path is root-level. Then update docs.

**Tech Stack:** Python, Flet (UI framework). No automated tests — validation is manual (`flet run`).

---

## Files

- Modify: `bifrost-transfer/src/main.py`
  - `_build_copy_content` (~line 2155): `on_browser_select` — add visibility toggle
  - `_build_copy_content` (~line 2395): layout assembly — wrap bottom items in `bottom_col`
  - `build_rclone_browser` (~line 1070): `_show()` — pick icon per level
- Modify: `README.md` — note that bottom sections appear after bucket selection
- Modify: `CLAUDE.md` — add gotcha about bucket-gated visibility

---

### Task 1: Wrap bottom layout sections in a hidden `ft.Column`

**Files:**
- Modify: `bifrost-transfer/src/main.py` lines ~2428–2445 (layout assembly inside `_build_copy_content`)

- [ ] **Step 1: Locate the layout block**

Open `bifrost-transfer/src/main.py`. Find the `# ── Layout` comment (~line 2395). Inside the inner `ft.Column`, the current sequence after the PATHS card is:

```python
                        ft.Container(height=16),
                        section_title("METADATA"),
                        ft.Container(height=6),
                        profile_row,
                        ft.Container(height=10),
                        card(meta_container),
                        ft.Container(height=16),
                        ft.Row(
                            [copy_btn, check_btn, cancel_btn, mount_btn, save_btn, close_btn],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            wrap=True,
                        ),
                        ft.Container(height=12),
                        section_title("LOG OUTPUT"),
                        ft.Container(height=8),
                        log_container,
                        ft.Container(height=16),
```

- [ ] **Step 2: Replace those lines with a `bottom_col` reference**

In the layout `ft.Column`, replace everything from `ft.Container(height=16),` (the one before `section_title("METADATA")`) through the final `ft.Container(height=16),` with a single reference to `bottom_col`:

```python
                        bottom_col,
```

So the inner `ft.Column` ends like:

```python
                    ft.Column(
                        [
                            section_title("PATHS"),
                            ft.Container(height=10),
                            card(
                                ft.Column([...paths content...]),
                            ),
                            bottom_col,
                        ],
                        spacing=0,
                    ),
```

- [ ] **Step 3: Define `bottom_col` just before the layout block**

Immediately before the `# ── Layout` comment (~line 2395), insert:

```python
    bottom_col = ft.Column(
        [
            ft.Container(height=16),
            section_title("METADATA"),
            ft.Container(height=6),
            profile_row,
            ft.Container(height=10),
            card(meta_container),
            ft.Container(height=16),
            ft.Row(
                [copy_btn, check_btn, cancel_btn, mount_btn, save_btn, close_btn],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                wrap=True,
            ),
            ft.Container(height=12),
            section_title("LOG OUTPUT"),
            ft.Container(height=8),
            log_container,
            ft.Container(height=16),
        ],
        spacing=0,
        visible=False,
    )
```

- [ ] **Step 4: Verify the file parses**

```bash
cd bifrost-transfer
python -c "import ast; ast.parse(open('src/main.py').read()); print('OK')"
```

Expected output: `OK`

- [ ] **Step 5: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: wrap copy form bottom sections in hidden bottom_col"
```

---

### Task 2: Toggle `bottom_col` visibility in `on_browser_select`

**Files:**
- Modify: `bifrost-transfer/src/main.py` — `on_browser_select` (~line 2155) inside `_build_copy_content`

- [ ] **Step 1: Locate `on_browser_select`**

Find the function `on_browser_select` inside `_build_copy_content`. It currently ends like:

```python
    def on_browser_select(path: str):
        _dest_path["value"] = path
        if IS_WEB and web_session is not None and path:
            web_session["copy_destino"] = path
        if path:
            display = f"{perfil_rclone}:{path}"
            ruta_label.value = f"→ All files from source will be copied into: {display}"
            ruta_label.color = C_ACCENT
        else:
            ruta_label.value = f"→ {perfil_rclone}: (root — select a folder above)"
            ruta_label.color = C_WARNING
        # NO llamamos ruta_label.update() aquí ...
```

- [ ] **Step 2: Add visibility toggle at the end of `on_browser_select`**

Append these lines inside the function, after the `ruta_label` block and before the closing comment:

```python
        should_be_visible = bool(path)
        if bottom_col.visible != should_be_visible:
            bottom_col.visible = should_be_visible
            # page.update() is called by _navigate() right after on_select()
```

`bottom_col` is a local variable defined later in the same function body. Python closures are late-binding — it resolves at call time, which is always after `bottom_col` is defined.

- [ ] **Step 3: Verify the file parses**

```bash
cd bifrost-transfer
python -c "import ast; ast.parse(open('src/main.py').read()); print('OK')"
```

Expected output: `OK`

- [ ] **Step 4: Manual smoke test**

```bash
flet run
```

1. Navigate past login/server/credentials to the copy form.
2. Confirm only the PATHS card is visible; METADATA, buttons, and log are absent.
3. Click a bucket in the destination browser.
4. Confirm METADATA, buttons, and LOG OUTPUT appear.
5. Click `perfil_rclone:` in the breadcrumb to go back to root.
6. Confirm the sections hide again.

- [ ] **Step 5: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: show copy form bottom sections only after bucket is selected"
```

---

### Task 3: Distinct icon for buckets vs subfolders

**Files:**
- Modify: `bifrost-transfer/src/main.py` — `_show()` inside `build_rclone_browser` (~line 1070)

- [ ] **Step 1: Locate the folder row render loop**

Inside `build_rclone_browser`, find `_show()`. The loop that renders each item looks like:

```python
                    for fname in folders:
                        full_path = f"{path}/{fname}" if path else fname
                        fp_snap   = full_path

                        row = ft.Container(
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
                                    ft.Text(fname, size=12, color=C_TEXT, expand=True),
                                    ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=14),
                                ],
```

- [ ] **Step 2: Replace the hardcoded icon with a level-aware one**

Replace the line:

```python
                                    ft.Icon(ft.Icons.FOLDER_OUTLINED, color=C_WARNING, size=16),
```

with:

```python
                                    ft.Icon(
                                        ft.Icons.STORAGE if not path else ft.Icons.FOLDER_OUTLINED,
                                        color=C_PRIMARY if not path else C_WARNING,
                                        size=16,
                                    ),
```

`path` is the variable captured by the enclosing `_navigate` / `_load` scope that tells us the current level. When `path == ""` we are listing buckets; otherwise subfolders.

- [ ] **Step 3: Verify the file parses**

```bash
cd bifrost-transfer
python -c "import ast; ast.parse(open('src/main.py').read()); print('OK')"
```

Expected output: `OK`

- [ ] **Step 4: Manual smoke test**

```bash
flet run
```

1. Navigate to the copy form.
2. Confirm bucket rows show a cylinder/storage icon in blue (`C_PRIMARY`).
3. Click a bucket. Confirm subfolder rows show a folder icon in orange (`C_WARNING`).

- [ ] **Step 5: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat: use STORAGE icon for buckets and FOLDER_OUTLINED for subfolders in rclone browser"
```

---

### Task 4: Update README.md and CLAUDE.md

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update README.md**

Find the section that describes the copy form / destination browser. Add a note that the METADATA, copy/check buttons, and log panel are only shown after a destination bucket has been selected in the browser.

Look for text like "Destination path" or "formulario de copia" and add after it:

> Los campos de metadatos, los botones de copia/verificación y el panel de log solo aparecen una vez que se ha seleccionado un bucket destino en el navegador.

- [ ] **Step 2: Update CLAUDE.md**

In the "Convenciones y gotchas críticas" section, add a new item:

```markdown
10. **Visibilidad condicional en el formulario de copia**: las secciones METADATA, botones de acción y LOG OUTPUT de `_build_copy_content` están ocultas (`bottom_col.visible=False`) hasta que el usuario selecciona un bucket en el browser de destino. El toggle se gestiona en `on_browser_select`: si `path` es no-vacío → visible; si vuelve a vacío (root) → oculto.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: note copy form bucket-gated visibility in README and CLAUDE.md"
```
