# SFTP Source UX Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SFTP source password optional, remove the "create folder" affordance from the SFTP browser (it only makes sense for the S3 destination), and let the user select either a whole folder or a single file as the SFTP copy source.

**Architecture:** Extend the existing shared `build_rclone_browser` component (used by both the S3 destination browser and the SFTP source browser) with two new parameters — `allow_mkdir` and `show_files` — instead of forking a second browser component. A new backend function `rclone_lsjson` lists folders **and** files in one call (SFTP only; the S3 destination browser keeps using `rclone_lsd`, unchanged, because MinIO's HDD-backed listing stays slow).

**Tech Stack:** Python 3, Flet (desktop/web UI), rclone (subprocess), no automated test suite in this repo — verification is manual (`flet run`), per `CLAUDE.md` → "Tests".

## Global Constraints

- **No automated test suite** — this repo has none (`CLAUDE.md` → "Tests"). Each task below substitutes `python -m py_compile` (syntax/import sanity) for the automated-test step, plus a manual `flet run` verification. The final task runs the full manual QA checklist from the spec.
- **All UI text and error messages introduced or touched must be in English** — matches the existing convention in `bifrost-transfer/src/main.py` (`CLAUDE.md` reserves Spanish for comments/docstrings/README, not UI strings).
- **Do not add a "(optional)" hint to the Password field** — the user removed it manually; leave the hint text as-is.
- Source spec: `docs/superpowers/specs/2026-07-31-sftp-source-ux-refinement-design.md`.

---

## File Structure

| File | Responsibility in this change |
|---|---|
| `shared/bifrost_backend/backend.py` | New `rclone_lsjson()` function (folders + files, one rclone call) |
| `bifrost-transfer/src/main.py` | `build_rclone_browser()` gains `allow_mkdir`/`show_files`; SFTP connect dialog password validation; SFTP browser modal wiring |
| `CLAUDE.md` | Gotcha #12 updated to mention file/folder selection and optional password |
| `README.md` | `bifrost-transfer` description updated to mention file/folder selection and optional password |

No new files are created — this is a refinement of existing code from the 2026-07-30 SFTP source feature.

---

### Task 1: Backend — `rclone_lsjson`

**Files:**
- Modify: `shared/bifrost_backend/backend.py` (insert after `rclone_lsd`, which ends at line 1796, right before the `# LÓGICA DE INICIALIZACIÓN` section header at line 1799)

**Interfaces:**
- Consumes: `get_rclone_executable()`, `_subprocess_kwargs()` (already defined earlier in the file, already used by `rclone_lsd`)
- Produces: `rclone_lsjson(perfil: str, path: str = "", timeout: int = 15) -> list[dict]` where each dict is `{"name": str, "is_dir": bool}`, directories first then files, alphabetical case-insensitive within each group. Raises `RuntimeError` on non-zero rclone exit, propagates `subprocess.TimeoutExpired` on timeout — same error contract as `rclone_lsd`.

- [ ] **Step 1: Add the function**

Insert immediately after the `return sorted(folders)` line that ends `rclone_lsd` (line 1796), before the `# LÓGICA DE INICIALIZACIÓN` section comment block:

```python
def rclone_lsjson(perfil: str, path: str = "", timeout: int = 15) -> list[dict]:
    """
    Lista carpetas y ficheros (un nivel) de un path en un perfil rclone, vía JSON.

    Args:
        perfil: nombre del perfil rclone (ej. "sftp-src-abc123")
        path:   path dentro del perfil. "" = raíz

    Returns:
        Lista de dicts {"name": str, "is_dir": bool}, carpetas primero,
        luego alfabético case-insensitive dentro de cada grupo.

    Raises:
        RuntimeError: si rclone lsjson falla.
    """
    rclone = get_rclone_executable()
    target = f"{perfil}:{path}" if path else f"{perfil}:"

    result = subprocess.run(
        [rclone, "lsjson", target],
        capture_output=True,
        text=True,
        timeout=timeout,
        **_subprocess_kwargs(),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"rclone lsjson failed (code {result.returncode})")

    entradas = json.loads(result.stdout or "[]")
    items = [{"name": e["Name"], "is_dir": bool(e.get("IsDir"))} for e in entradas]
    return sorted(items, key=lambda i: (not i["is_dir"], i["name"].lower()))
```

`json` is already imported at the top of `backend.py` (line 25) — no new import needed.

- [ ] **Step 2: Verify syntax**

Run: `python -m py_compile shared/bifrost_backend/backend.py`
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add shared/bifrost_backend/backend.py
git commit -m "feat(backend): add rclone_lsjson to list folders and files in one call"
```

---

### Task 2: Frontend — SFTP password optional

**Files:**
- Modify: `bifrost-transfer/src/main.py` (inside `_open_sftp_dialog`, function `connect`, around line 2356)

**Interfaces:**
- Consumes: nothing new
- Produces: nothing new — this is a validation-only change, `backend.crear_perfil_rclone_sftp` already accepts an empty-string password unchanged

- [ ] **Step 1: Relax the validation**

Find in `connect(ev)`:

```python
            if not host or not user or not pwd:
                err.value   = "Host, username and password are required."
                err.visible = True
                page.update()
                return
```

Replace with:

```python
            if not host or not user:
                err.value   = "Host and username are required."
                err.visible = True
                page.update()
                return
```

- [ ] **Step 2: Verify syntax**

Run: `python -m py_compile bifrost-transfer/src/main.py`
Expected: no output, exit code 0.

- [ ] **Step 3: Manual verification**

From `bifrost-transfer/`: `flet run`. Log in, go to the copy view, click "🌐 SFTP", leave Password empty, fill Host/Username with a test SFTP account that accepts a blank password, click Connect.
Expected: connects successfully (no "password required" error blocks it). If you don't have a passwordless test account handy, at minimum confirm that submitting the dialog with Host+Username filled and Password empty no longer shows "Host, username and password are required." — the request should reach `crear_perfil_rclone_sftp`/`validar_conexion_sftp` instead of being blocked client-side.

- [ ] **Step 4: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "fix(frontend): make SFTP password optional in connect dialog"
```

---

### Task 3: Frontend — `build_rclone_browser` gains `allow_mkdir` and 2-arg `on_select`

**Files:**
- Modify: `bifrost-transfer/src/main.py`
  - `build_rclone_browser` signature (line 1041)
  - `nav_state` init (line 1058)
  - `_navigate` (lines 1150-1161)
  - manual-path-confirm branch inside the timeout handler (`confirm_manual`, around line 1254-1263)
  - `_do_mkdir` (around line 1379)
  - destination browser call site: `on_browser_select` (line 2516) and `build_rclone_browser(...)` call (line 2544)
  - SFTP call site: `_on_sftp_select` (line 2302) and `build_rclone_browser(...)` call (line 2305)

**Interfaces:**
- Consumes: nothing new
- Produces: `build_rclone_browser(page, perfil_rclone, on_select: Callable[[str, bool], None], initial_path="", lab_filter_enabled=False, endpoint=None, allow_mkdir: bool = True, show_files: bool = False) -> tuple[ft.Column, Callable]`. `on_select` is now called with `(path, is_file)` everywhere; `is_file` is always `False` until Task 4 adds real file selection. `allow_mkdir=False` hides the "Add subfolder" section entirely, regardless of path.

This task does **not** yet add file listing/selection (that's Task 4) — it only changes the signature, wires `allow_mkdir`, and updates both call sites so the app keeps working end-to-end after this task.

- [ ] **Step 1: Update the function signature**

Find:

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

Replace with:

```python
def build_rclone_browser(
    page: ft.Page,
    perfil_rclone: str,
    on_select: Callable[[str, bool], None],
    initial_path: str = "",
    lab_filter_enabled: bool = False,
    endpoint: str | None = None,
    allow_mkdir: bool = True,
    show_files: bool = False,
) -> tuple[ft.Column, Callable]:
```

- [ ] **Step 2: Extend `nav_state`**

Find:

```python
    nav_state = {"current_path": "", "timeout": 15}
```

Replace with:

```python
    nav_state = {"current_path": "", "timeout": 15, "selected_file": None}
```

- [ ] **Step 3: Update `_navigate`**

Find:

```python
    def _navigate(path: str):
        print(f"[browser] navigate → perfil={perfil_rclone!r} path={path!r}")
        nav_state["current_path"] = path
        on_select(path)

        loading_row.visible    = True
        error_text.visible     = False
        folder_col.controls.clear()
        filter_row.visible     = lab_filter_enabled and not path
        mkdir_section.visible  = bool(path)
        _rebuild_breadcrumb()
        page.update()
```

Replace with:

```python
    def _navigate(path: str):
        print(f"[browser] navigate → perfil={perfil_rclone!r} path={path!r}")
        nav_state["current_path"]  = path
        nav_state["selected_file"] = None
        on_select(path, False)

        loading_row.visible    = True
        error_text.visible     = False
        folder_col.controls.clear()
        filter_row.visible     = lab_filter_enabled and not path
        mkdir_section.visible  = allow_mkdir and bool(path)
        _rebuild_breadcrumb()
        page.update()
```

- [ ] **Step 4: Update the manual-path-confirm branch**

Find (inside the `subprocess.TimeoutExpired` handler's `_timeout_ui`):

```python
                    def confirm_manual(e):
                        new_path = manual_tf.value.strip()
                        print(f"[browser] manual path confirmed → {new_path!r}")
                        nav_state["current_path"] = new_path
                        on_select(new_path)
                        _rebuild_breadcrumb()
```

Replace with:

```python
                    def confirm_manual(e):
                        new_path = manual_tf.value.strip()
                        print(f"[browser] manual path confirmed → {new_path!r}")
                        nav_state["current_path"]  = new_path
                        nav_state["selected_file"] = None
                        on_select(new_path, False)
                        _rebuild_breadcrumb()
```

- [ ] **Step 5: Update `_do_mkdir`**

Find (inside `_do_mkdir`):

```python
        # Actualizar estado y breadcrumb sin llamar a rclone
        nav_state["current_path"] = new_path
        on_select(new_path)
        _rebuild_breadcrumb()
```

Replace with:

```python
        # Actualizar estado y breadcrumb sin llamar a rclone
        nav_state["current_path"] = new_path
        on_select(new_path, False)
        _rebuild_breadcrumb()
```

- [ ] **Step 6: Update the destination (S3) call site**

Find:

```python
    def on_browser_select(path: str):
        print(f"[copy] destination selected → {perfil_rclone}:{path}" if path
              else "[copy] destination cleared (root)")
        _dest_path["value"] = path
```

Replace with:

```python
    def on_browser_select(path: str, is_file: bool = False):
        print(f"[copy] destination selected → {perfil_rclone}:{path}" if path
              else "[copy] destination cleared (root)")
        _dest_path["value"] = path
```

(The destination browser never sets `show_files=True`, so `is_file` is always `False` here — the parameter exists only to match the new `on_select` contract. No other line in `on_browser_select` changes.)

The `build_rclone_browser(...)` call for the destination browser (line 2544) does not need any argument changes — `allow_mkdir` defaults to `True` and `show_files` defaults to `False`, which is the current behavior.

- [ ] **Step 7: Update the SFTP call site**

Find:

```python
        def _on_sftp_select(path: str) -> None:
            _sftp_dest_path["value"] = path

        browser_widget, browser_refresh = build_rclone_browser(
            page, sftp_state["perfil"], on_select=_on_sftp_select, lab_filter_enabled=False,
        )
```

Replace with:

```python
        def _on_sftp_select(path: str, is_file: bool = False) -> None:
            _sftp_dest_path["value"] = path

        browser_widget, browser_refresh = build_rclone_browser(
            page, sftp_state["perfil"], on_select=_on_sftp_select, lab_filter_enabled=False,
            allow_mkdir=False,
        )
```

- [ ] **Step 8: Verify syntax**

Run: `python -m py_compile bifrost-transfer/src/main.py`
Expected: no output, exit code 0.

- [ ] **Step 9: Manual verification**

`flet run` from `bifrost-transfer/`. Log in, go to copy view:
- Destination browser (S3): navigate into a bucket → "Add subfolder to destination" section still appears, works as before.
- SFTP browser: connect, navigate into a folder → "Add subfolder" section never appears (was showing before this task).
- Both browsers still navigate folders and populate the destination/origin fields correctly.

- [ ] **Step 10: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "refactor(frontend): add allow_mkdir param to build_rclone_browser, hide mkdir in SFTP source"
```

---

### Task 4: Frontend — file listing, selection, and dynamic confirm button in the SFTP browser

**Files:**
- Modify: `bifrost-transfer/src/main.py`
  - `nav_state`/new `file_row_refs` (near line 1058, right after Task 3's edit)
  - new helper functions `_style_file_row` / `_toggle_file_selection` (add near `_navigate`, before its first use)
  - `_load` (folder/file fetch, lines ~1163-1193)
  - `_show` (row rendering, lines ~1195-1231)
  - `_open_sftp_browser_modal` (lines 2299-2334): `_on_sftp_select`, `build_rclone_browser(...)` call, `confirm_btn`

**Interfaces:**
- Consumes: `backend.rclone_lsjson` (Task 1), `allow_mkdir`/2-arg `on_select` (Task 3)
- Produces: when `show_files=True`, `build_rclone_browser` renders both folders and files per level; clicking a file toggles a highlighted selection (single selection at a time) and calls `on_select(file_path, True)`; clicking a folder navigates as before and calls `on_select(folder_path, False)`. The SFTP modal's confirm button reads `_sftp_dest_path["is_file"]` to switch its label between "Select this folder" and "Select this file".

- [ ] **Step 1: Add `file_row_refs` next to `nav_state`**

Find (this is the result of Task 3 Step 2):

```python
    nav_state = {"current_path": "", "timeout": 15, "selected_file": None}
```

Replace with:

```python
    nav_state = {"current_path": "", "timeout": 15, "selected_file": None}
    file_row_refs: dict[str, ft.Container] = {}
```

- [ ] **Step 2: Add selection-toggle helpers**

Insert directly after the `file_row_refs` line from Step 1 (before `_rebuild_breadcrumb`):

```python
    def _style_file_row(container: ft.Container, selected: bool) -> None:
        if selected:
            container.bgcolor = f"{C_PRIMARY}22"
            container.border  = ft.Border.all(2, C_PRIMARY)
        else:
            container.bgcolor = C_SURFACE2
            container.border  = ft.Border.all(1, C_BORDER)

    def _toggle_file_selection(path: str) -> None:
        previous = nav_state["selected_file"]
        if previous is not None and previous in file_row_refs:
            _style_file_row(file_row_refs[previous], False)

        if previous == path:
            nav_state["selected_file"] = None
            on_select(nav_state["current_path"], False)
        else:
            nav_state["selected_file"] = path
            if path in file_row_refs:
                _style_file_row(file_row_refs[path], True)
            on_select(path, True)

        page.update()
```

- [ ] **Step 3: Clear `file_row_refs` on navigation**

Find (this is the result of Task 3 Step 3):

```python
    def _navigate(path: str):
        print(f"[browser] navigate → perfil={perfil_rclone!r} path={path!r}")
        nav_state["current_path"]  = path
        nav_state["selected_file"] = None
        on_select(path, False)

        loading_row.visible    = True
        error_text.visible     = False
        folder_col.controls.clear()
        filter_row.visible     = lab_filter_enabled and not path
        mkdir_section.visible  = allow_mkdir and bool(path)
        _rebuild_breadcrumb()
        page.update()
```

Replace with:

```python
    def _navigate(path: str):
        print(f"[browser] navigate → perfil={perfil_rclone!r} path={path!r}")
        nav_state["current_path"]  = path
        nav_state["selected_file"] = None
        file_row_refs.clear()
        on_select(path, False)

        loading_row.visible    = True
        error_text.visible     = False
        folder_col.controls.clear()
        filter_row.visible     = lab_filter_enabled and not path
        mkdir_section.visible  = allow_mkdir and bool(path)
        _rebuild_breadcrumb()
        page.update()
```

- [ ] **Step 4: Fetch folders+files via `rclone_lsjson` when `show_files=True`**

Find:

```python
        def _load():
            try:
                if not path and bucket_cache["list"] is not None:
                    folders = list(bucket_cache["list"])
                else:
                    folders = backend.rclone_lsd(perfil_rclone, path, timeout=nav_state["timeout"])
                    print(f"[browser] rclone lsd path={path!r} → {len(folders)} folders: {folders}")
                    if not path:
                        bucket_cache["list"] = list(folders)
                        bucket_cache["tags"] = None

                if lab_filter_enabled and filter_state["acronym"] and not path:
                    active = filter_state["acronym"]
                    total = len(bucket_cache["list"])
                    if bucket_cache["tags"] is None:
                        print(f"[browser] lab filter {active!r}: scanning S3 'acronym' tag for {total} buckets (one-time per session)...")
                        s3 = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            futs = {pool.submit(backend.get_bucket_tags, s3, b): b for b in bucket_cache["list"]}
                            tag_map: dict[str, str] = {}
                            for fut in as_completed(futs):
                                b = futs[fut]
                                try:
                                    tag_map[b] = fut.result().get("acronym", "")
                                except Exception:
                                    tag_map[b] = ""
                        bucket_cache["tags"] = tag_map
                        n_tagged = sum(1 for v in tag_map.values() if v)
                        print(f"[browser] lab filter: tag scan done → {n_tagged}/{total} buckets have an 'acronym' tag (cached for this session)")
                    folders = [b for b in folders if bucket_cache["tags"].get(b) == active]
                    print(f"[browser] lab filter {active!r} → {len(folders)}/{total} buckets match: {folders}")
```

Replace with:

```python
        def _load():
            try:
                if not path and bucket_cache["list"] is not None:
                    entries = list(bucket_cache["list"])
                else:
                    if show_files:
                        entries = backend.rclone_lsjson(perfil_rclone, path, timeout=nav_state["timeout"])
                        print(f"[browser] rclone lsjson path={path!r} → {len(entries)} entries: {entries}")
                    else:
                        folders = backend.rclone_lsd(perfil_rclone, path, timeout=nav_state["timeout"])
                        print(f"[browser] rclone lsd path={path!r} → {len(folders)} folders: {folders}")
                        entries = [{"name": f, "is_dir": True} for f in folders]
                    if not path:
                        bucket_cache["list"] = list(entries)
                        bucket_cache["tags"] = None

                if lab_filter_enabled and filter_state["acronym"] and not path:
                    active = filter_state["acronym"]
                    bucket_names = [e["name"] for e in bucket_cache["list"]]
                    total = len(bucket_names)
                    if bucket_cache["tags"] is None:
                        print(f"[browser] lab filter {active!r}: scanning S3 'acronym' tag for {total} buckets (one-time per session)...")
                        s3 = backend.get_s3_client_from_profile(perfil_rclone, endpoint)
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            futs = {pool.submit(backend.get_bucket_tags, s3, b): b for b in bucket_names}
                            tag_map: dict[str, str] = {}
                            for fut in as_completed(futs):
                                b = futs[fut]
                                try:
                                    tag_map[b] = fut.result().get("acronym", "")
                                except Exception:
                                    tag_map[b] = ""
                        bucket_cache["tags"] = tag_map
                        n_tagged = sum(1 for v in tag_map.values() if v)
                        print(f"[browser] lab filter: tag scan done → {n_tagged}/{total} buckets have an 'acronym' tag (cached for this session)")
                    entries = [e for e in entries if bucket_cache["tags"].get(e["name"]) == active]
                    print(f"[browser] lab filter {active!r} → {len(entries)}/{total} buckets match: {[e['name'] for e in entries]}")
```

`lab_filter_enabled` is only ever `True` for the destination browser, which never sets `show_files=True`, so this branch only ever sees `entries` built from `rclone_lsd` folder names (all `is_dir=True`) — behavior for the destination browser is unchanged.

- [ ] **Step 5: Render folder and file rows**

Find:

```python
                def _show():
                    loading_row.visible = False
                    folder_col.controls.clear()

                    if not folders:
                        folder_col.controls.append(
                            ft.Text("(empty — no subfolders)", size=11, color=C_TEXT_DIM, italic=True)
                        )
                    else:
                        for fname in folders:
                            full_path = f"{path}/{fname}" if path else fname
                            fp_snap   = full_path

                            row = ft.Container(
                                content=ft.Row(
                                    [
                                        ft.Icon(
                                        ft.Icons.STORAGE if not path else ft.Icons.FOLDER_OUTLINED,
                                        color=C_PRIMARY if not path else C_WARNING,
                                        size=16,
                                    ),
                                        ft.Text(fname, size=12, color=C_TEXT, expand=True),
                                        ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=14),
                                    ],
                                    spacing=8,
                                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                ),
                                bgcolor=C_SURFACE2,
                                border=ft.Border.all(1, C_BORDER),
                                border_radius=6,
                                padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                on_click=lambda e, p=fp_snap: _navigate(p),
                                ink=True,
                            )
                            folder_col.controls.append(row)

                    page.update()

                backend.ui_call(page, _show)
```

Replace with:

```python
                def _show():
                    loading_row.visible = False
                    folder_col.controls.clear()
                    file_row_refs.clear()

                    if not entries:
                        empty_msg = "(empty)" if show_files else "(empty — no subfolders)"
                        folder_col.controls.append(
                            ft.Text(empty_msg, size=11, color=C_TEXT_DIM, italic=True)
                        )
                    else:
                        for entry in entries:
                            name      = entry["name"]
                            is_dir    = entry["is_dir"]
                            full_path = f"{path}/{name}" if path else name
                            fp_snap   = full_path

                            if is_dir:
                                row = ft.Container(
                                    content=ft.Row(
                                        [
                                            ft.Icon(
                                                ft.Icons.STORAGE if not path else ft.Icons.FOLDER_OUTLINED,
                                                color=C_PRIMARY if not path else C_WARNING,
                                                size=16,
                                            ),
                                            ft.Text(name, size=12, color=C_TEXT, expand=True),
                                            ft.Icon(ft.Icons.CHEVRON_RIGHT, color=C_TEXT_DIM, size=14),
                                        ],
                                        spacing=8,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                    bgcolor=C_SURFACE2,
                                    border=ft.Border.all(1, C_BORDER),
                                    border_radius=6,
                                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                    on_click=lambda e, p=fp_snap: _navigate(p),
                                    ink=True,
                                )
                            else:
                                row = ft.Container(
                                    content=ft.Row(
                                        [
                                            ft.Icon(ft.Icons.INSERT_DRIVE_FILE_OUTLINED,
                                                    color=C_TEXT_DIM, size=16),
                                            ft.Text(name, size=12, color=C_TEXT, expand=True),
                                        ],
                                        spacing=8,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                    bgcolor=C_SURFACE2,
                                    border=ft.Border.all(1, C_BORDER),
                                    border_radius=6,
                                    padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                                    on_click=lambda e, p=fp_snap: _toggle_file_selection(p),
                                    ink=True,
                                )
                                file_row_refs[fp_snap] = row

                            folder_col.controls.append(row)

                    page.update()

                backend.ui_call(page, _show)
```

- [ ] **Step 6: Wire the SFTP modal to `show_files=True` and a dynamic confirm button**

Find:

```python
    def _open_sftp_browser_modal() -> None:
        _sftp_dest_path = {"value": ""}

        def _on_sftp_select(path: str, is_file: bool = False) -> None:
            _sftp_dest_path["value"] = path

        browser_widget, browser_refresh = build_rclone_browser(
            page, sftp_state["perfil"], on_select=_on_sftp_select, lab_filter_enabled=False,
            allow_mkdir=False,
        )

        def confirm(e):
            path = _sftp_dest_path["value"]
            origen_tf.value = f"{sftp_state['perfil']}:{path}"
            page.pop_dialog()
            page.update()

        def cancel(e):
            page.pop_dialog()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text(
                f"SFTP — {sftp_state['user']}@{sftp_state['host']}",
                color=C_TEXT, size=15, weight=ft.FontWeight.W_600,
            ),
            content=ft.Column([browser_widget], spacing=6, tight=True, width=520),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                btn_primary("Select this folder", on_click=confirm),
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()
        threading.Timer(0.1, lambda: backend.ui_call(page, browser_refresh)).start()
```

Replace with:

```python
    def _open_sftp_browser_modal() -> None:
        _sftp_dest_path = {"value": "", "is_file": False}

        def _on_sftp_select(path: str, is_file: bool = False) -> None:
            _sftp_dest_path["value"]   = path
            _sftp_dest_path["is_file"] = is_file
            confirm_btn.content.value = "Select this file" if is_file else "Select this folder"
            page.update()

        browser_widget, browser_refresh = build_rclone_browser(
            page, sftp_state["perfil"], on_select=_on_sftp_select, lab_filter_enabled=False,
            allow_mkdir=False, show_files=True,
        )

        def confirm(e):
            path = _sftp_dest_path["value"]
            origen_tf.value = f"{sftp_state['perfil']}:{path}"
            page.pop_dialog()
            page.update()

        def cancel(e):
            page.pop_dialog()

        confirm_btn = btn_primary("Select this folder", on_click=confirm)

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text(
                f"SFTP — {sftp_state['user']}@{sftp_state['host']}",
                color=C_TEXT, size=15, weight=ft.FontWeight.W_600,
            ),
            content=ft.Column([browser_widget], spacing=6, tight=True, width=520),
            actions=[
                btn_secondary("Cancel", on_click=cancel),
                confirm_btn,
            ],
            bgcolor=C_OVERLAY,
            shape=ft.RoundedRectangleBorder(radius=10),
        )
        page.show_dialog(dlg)
        page.update()
        threading.Timer(0.1, lambda: backend.ui_call(page, browser_refresh)).start()
```

Note: `confirm_btn` is referenced inside `_on_sftp_select`, which is defined textually *before* `confirm_btn` is assigned. This is safe in Python — `_on_sftp_select` is only ever *called* later (after user interaction, by which point `confirm_btn` already exists in the enclosing scope), the same pattern already used elsewhere in this file for dialog callbacks referencing later-defined controls.

- [ ] **Step 7: Verify syntax**

Run: `python -m py_compile bifrost-transfer/src/main.py`
Expected: no output, exit code 0.

- [ ] **Step 8: Manual verification**

`flet run` from `bifrost-transfer/`. Log in, go to copy view, connect to a real SFTP test account with a folder that has both subfolders and files:
- Navigate into that folder → both subfolders and files are listed; files show a file icon and no chevron; subfolders behave as before (chevron, navigate on click).
- Click a file → it highlights (colored border/background), confirm button label changes to "Select this file".
- Click the same file again → it un-highlights, confirm button reverts to "Select this folder".
- Click a file, then click a subfolder → navigates into the subfolder, no file stays selected, confirm button is back to "Select this folder".
- Click a file, click "Select this file" → modal closes, `origen` field shows `perfil:path/to/file` → run a copy → the single file is copied correctly.
- Click "Select this folder" without picking a file → `origen` field shows `perfil:path` (the folder) → run a copy → the whole folder is copied correctly.
- Confirm the destination (S3) browser still shows no file listing and still allows "Add subfolder" as before (no regression from `show_files`/`allow_mkdir` defaults).

- [ ] **Step 9: Commit**

```bash
git add bifrost-transfer/src/main.py
git commit -m "feat(frontend): list files alongside folders in SFTP browser, allow selecting either as source"
```

---

### Task 5: Documentation — `CLAUDE.md` and `README.md`

**Files:**
- Modify: `CLAUDE.md` (gotcha #12 in "Convenciones y gotchas críticas")
- Modify: `README.md` (the `bifrost-transfer` SFTP description added by the 2026-07-30 spec)

**Interfaces:**
- Consumes: nothing (documentation only)
- Produces: nothing (documentation only)

- [ ] **Step 1: Update `CLAUDE.md` gotcha #12**

Read the current gotcha #12 text in `CLAUDE.md` (under "Convenciones y gotchas críticas") — it currently describes the ephemeral rclone profile lifecycle for SFTP. Extend it (do not replace the existing lifecycle explanation) with a short addition covering:
- The password field is optional (some SFTP accounts have none); the connect dialog only requires host and username.
- The SFTP browser (`build_rclone_browser(..., allow_mkdir=False, show_files=True)`) does not offer "create folder" (only meaningful for the S3 destination, where the folder is virtual until copy) and lists files alongside folders via `backend.rclone_lsjson` — unlike the S3 destination browser, which only lists folders via `backend.rclone_lsd` because MinIO's HDD-backed listing is slow.
- The user can select either a folder or a single file as the SFTP source — same `perfil:path` format either way, no backend distinction between the two.

- [ ] **Step 2: Update `README.md`**

Find the `bifrost-transfer` SFTP description added by the previous spec (search for "SFTP" in the `bifrost-transfer` section). Update it to mention:
- The password is optional.
- The user can browse and select either a folder or an individual file as the source.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: document optional SFTP password and file/folder source selection"
```

---

### Task 6: End-to-end manual QA

**Files:** none (verification only, no code changes)

**Interfaces:** none

- [ ] **Step 1: Run the full spec checklist**

From `bifrost-transfer/`, run `flet run` (desktop) and separately `flet run --web` (web mode), and for each mode walk through the checklist from `docs/superpowers/specs/2026-07-31-sftp-source-ux-refinement-design.md` → "Restricciones y gotchas":

1. Connect without a password to an SFTP account that accepts a blank one.
2. Navigate a folder with mixed subfolders and files → both are listed, files have no navigation arrow.
3. Select a file → button changes to "Select this file" → confirm → `origen` = `perfil:path/file` → copy works.
4. Deselect the file (click again) → button reverts to "Select this folder" → confirm selects the current folder.
5. Navigate to another folder after selecting a file → selection clears automatically.
6. Confirm "Add subfolder" never appears anywhere in the SFTP browser.
7. Confirm the S3 destination browser is unchanged (no file listing, "Add subfolder" still available).

- [ ] **Step 2: Confirm cleanup still works**

Disconnect (✕) after a file-selection SFTP session, and separately navigate back out of the copy view without disconnecting — in both cases confirm the ephemeral `sftp-src-*` profile is removed from `rclone.conf` (this logic is untouched by this plan, but worth re-confirming since the browser wiring changed around it).

No commit for this task — it is a verification pass. If any step fails, open a new task (or amend the relevant earlier task) to fix it before considering this plan complete.
