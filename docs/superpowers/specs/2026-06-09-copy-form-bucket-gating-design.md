# Design: Copy Form Bucket Gating + Browser Icons

**Date:** 2026-06-09
**Branch:** feature/profiles-copy
**Scope:** `bifrost-transfer` only

---

## Problem

The copy form (`_build_copy_content`) shows all sections (METADATA, action buttons, LOG OUTPUT) immediately on load, before the user has selected a destination bucket. This is confusing — the user should pick a bucket first.

Additionally, buckets and subfolders look identical in the rclone browser (both use `FOLDER_OUTLINED`), making it hard to distinguish the two levels visually.

---

## Changes

### 1. Conditional visibility of bottom sections

**File:** `bifrost-transfer/src/main.py` — `_build_copy_content`

Extract the following elements from the layout into a dedicated `ft.Column` named `bottom_col` with `visible=False`:

- `section_title("METADATA")` + spacer
- `profile_row` + spacer
- `card(meta_container)` + spacer
- Action buttons row (`copy_btn`, `check_btn`, `cancel_btn`, `mount_btn`, `save_btn`, `close_btn`)
- `section_title("LOG OUTPUT")` + spacer
- `log_container` + spacer

In `on_browser_select(path)`, toggle visibility:

```python
should_be_visible = bool(path)
if bottom_col.visible != should_be_visible:
    bottom_col.visible = should_be_visible
    # page.update() is called by _navigate() right after on_select()
```

`bottom_col` is a local variable in `_build_copy_content`; Python's late-binding closures ensure it is resolved at call time, after the layout is built. The initial `on_browser_select("")` call (fired via Timer after `show_screen()`) leaves `bottom_col` hidden.

If the user navigates back to the bucket root (path becomes `""`), the sections hide again.

### 2. Different icon for buckets vs folders

**File:** `bifrost-transfer/src/main.py` — `build_rclone_browser` → `_show()`

At root level (`path == ""`), listed items are S3 buckets. At any deeper level they are subfolders. Use this to pick the icon when rendering each row:

```python
is_bucket = not path
icon       = ft.Icons.STORAGE        if is_bucket else ft.Icons.FOLDER_OUTLINED
icon_color = C_PRIMARY               if is_bucket else C_WARNING
```

No other changes to `build_rclone_browser`.

### 3. Documentation

**Files:** `README.md`, `CLAUDE.md`

Update to mention that the copy form only reveals the METADATA / action buttons / log sections after a destination bucket has been selected in the browser. Icon change does not need documenting.

---

## What is NOT changing

- The rclone browser navigation logic (`_navigate`, breadcrumb, mkdir).
- Web session state (`copy_destino`, `copy_log_callbacks`, etc.).
- Tag Manager view.
- `bifrost-mount`.

---

## Acceptance criteria

1. On load of the copy form, only the PATHS card is visible; METADATA, buttons and log are hidden.
2. Clicking a bucket in the browser reveals all three sections.
3. Navigating back to bucket root (clicking `perfil_rclone:` in the breadcrumb) hides them again.
4. Bucket rows show `STORAGE` icon (blue); subfolder rows show `FOLDER_OUTLINED` (orange).
5. README and CLAUDE.md reflect point 1.
