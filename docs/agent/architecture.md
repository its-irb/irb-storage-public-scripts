# Architecture

## Components

| Component | Folder | Role |
|---|---|---|
| **bifrost-transfer** | `bifrost-transfer/` | Copies data from network shares (SMB/CIFS), SFTP servers or local paths to MinIO S3 buckets, with integrity checks and tagging by metadata profile. Includes **Tag Manager** (bulk tagging without re-upload) and **web mode** (Open OnDemand). |
| **bifrost-mount** | `bifrost-mount/` | Mounts MinIO S3 folders as a local drive (Windows/macOS/Linux). Desktop mode only. |
| **bifrost-shared** | `shared/` | Common wheel package: `bifrost_backend` (all non-UI logic, split into `common/`, `mount/` and `transfer/`; the `backend.py` facade re-exports it as `backend.X`) and `bifrost_frontend` (theme, components and the views shared by both apps; the `frontend.py` facade re-exports them). |

Both apps are Flet apps with entry point `src/main.py` and one `pyproject.toml`
per app.

## Repository layout

```text
bifrost-mount/            # Mount app (desktop)
  src/
    main.py               # Flet entry point: startup, exit cleanup (signals/atexit), view navigation
    session_log.py        # Persistent session log (~/bifrost-mount-logs/)
    views/mount.py        # Bucket selector + mount/unmount view
    config.py             # APP_INFO = {"flavour": "mount", ...}
    version.py            # __version__ (written by CI/build)
    assets/bin/           # bundled rclone
  frameworks/             # fuse_t.framework (macOS)
  pyproject-template.toml # Template; pyproject.toml is generated locally (not versioned)
  installer.iss           # Inno Setup (Windows installer)
  build-macos.sh

bifrost-transfer/         # Transfer app (desktop + web)
  src/
    main.py               # Flet entry point: IS_WEB, console log, view navigation, cluster ASGI app
    web_session.py        # Web-mode sessions (_WEB_SESSIONS, _ws_save/_ws_load/_ws_clear)
    views/                # shares.py, rclone_browser.py, local_fs.py, copy.py, tag_manager.py
    meta_fields.py        # Profiles, metadata fields, lab filter
    config.py             # APP_INFO = {"flavour": "transfer", ...}
    version.py
    assets/bin/
    storage/              # Temporary transfer data
  pyproject-template.toml
  installer.iss
  build-macos.sh

shared/                   # bifrost-shared package (local wheel)
  bifrost_backend/
    backend.py            # Facade: re-exports the public API (backend.X)
    common/               # auth, constants, rclone, ui_helpers, updates
    mount/                # preflight (WinFsp/FUSE checks), s3_mount
    transfer/             # copy_check, ldap_groups, rclone_ops, s3_tags, sftp, smb
  bifrost_frontend/
    frontend.py           # Facade: re-exports theme, components and views
    theme.py              # Palette (C_*), fonts, apply_theme
    components.py         # Buttons, fields, show_dialog, show_confirm, build_header
    views/                # update.py, login.py, minio.py, credentials.py
  pyproject.toml          # Defines the "bifrost-shared" package
  *-assets-downloader.sh  # Download rclone/fuse-t (also used by CI)

old/                      # Legacy scripts (do not use)
build-windows.ps1         # Local Windows build (pyproject from template + rclone + flet build)
.github/workflows/main.yml  # CI: macOS/Windows build + release
AGENTS.md                 # Entry point for any agent -> docs/agent/
docs/agent/               # Agent layer (English)
docs/development/         # Developer layer (Spanish)
docs/user/                # User layer (English)
docs/superpowers/         # Historical feature specs and plans
.agentic/                 # Documentation framework (skills, instructions)
```

## Shared vs app-specific

**Shared (`shared/`)**:
- `bifrost_backend` — LDAP, rclone (exec, profiles, copy/check, listing), STS
  and the STS session token (`get_session_info`), SMB/CIFS, boto3 tagging,
  `ui_call()`, `safe_thread()`, autoupdate. Shared constants live in
  `bifrost_backend.common.constants` (`MINIO_SERVERS`, LDAP URL/base DN,
  `STS_RENEWAL_THRESHOLD_DAYS`, `STS_AUTO_RENEWAL_DAYS`, `NO_LDAP`). See
  [backend.md](backend.md).
- `bifrost_frontend` — theme (`C_BG`, `C_PRIMARY`, …), components
  (`btn_primary`, `btn_secondary`, `styled_field`, `show_dialog`,
  `show_confirm`, `build_header`) and the views shared by both apps
  (`build_update_content`, `build_login_content`, `build_minio_content`,
  `build_credentials_content`). Each app does
  `from bifrost_frontend.frontend import *`. See [frontend.md](frontend.md).

**App-specific**:
- `src/main.py` — entry point: startup, view navigation (login → minio →
  credentials → mount/copy) and exit cleanup. In `bifrost-transfer` it also
  computes `IS_WEB`, sets up the console log and builds the cluster ASGI app.
- `src/views/` — the app's own views (`mount.py` in mount; `shares.py`,
  `rclone_browser.py`, `local_fs.py`, `copy.py`, `tag_manager.py` in transfer).
- `src/session_log.py` (**mount only**) — persistent session log.
- `src/web_session.py` (**transfer only**) — web-mode session store.
- `src/meta_fields.py` — **`bifrost-transfer` only**: `FieldType`, `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS`, `build_lab_filter_widget`, `detect_profile`. Canonical source of profiles and fields.
- `src/config.py` — only `APP_INFO`. The backend reads `APP_INFO["flavour"]` to resolve asset paths in dev.
- `src/version.py` — written by CI/build (`__version__ = "1.0.<run_number>"`).
- `installer.iss`, `build-macos.sh`, `pyproject-template.toml` (frozen deps per app).

## Coupling and invariants

- Apps import the backend with `from bifrost_backend import backend` and the
  frontend with `from bifrost_frontend.frontend import *`. Shared code imports
  `config` as a top-level module (`common/rclone.py`, `common/updates.py` and
  the frontend modules): **`config.py` must be importable as a top-level module
  in each app** (that is why each app has its own, even though it only contains
  `APP_INFO`). `version` is also imported as a top-level module
  (`common/constants.py`, `common/rclone.py`), but inside `try/except` with a
  fallback (`"1.0.1"` / `"dev"`), so a missing `version.py` does not break the
  import.
- Each app's `pyproject.toml` references
  `bifrost-shared @ file:///__BUILDPATH__/shared`; the build script (CI,
  `build-windows.ps1` or `build-macos.sh`) replaces `__BUILDPATH__` with the
  real path of the shared package. `pyproject.toml` is not versioned: it is
  generated from `pyproject-template.toml`.
- The backend imports from the frontend only in one place:
  `common/ui_helpers.safe_thread` imports `show_dialog` and `C_ERROR` lazily
  (inside the function) to show unhandled exceptions. Keep that import lazy:
  a top-level import would create a circular import.
- **Views never import `main`**: `main.py` imports the views, so the reverse
  import would be circular. Anything a view and `main.py` both need lives in
  `shared/` or in an app module (`session_log.py`, `web_session.py`).
- **`IS_WEB` (transfer)**: computed only in `src/main.py`, because it depends on
  `__name__ != "__main__"`; `main()` also sets `IS_WEB = IS_WEB or page.web`.
  Modules moved out of `main.py` that read it (`web_session`, `views.shares`,
  `views.copy`, `views.tag_manager`) declare `IS_WEB = False`, and
  `_propagar_is_web()` in `main.py` copies the real value into them at import
  and whenever `main()` updates it. A new module that reads `IS_WEB` must be
  added to `_propagar_is_web()`.
- **Thread-safety rule**: any mutation of `control.controls` or call to
  `page.update()` from a background thread must be wrapped in
  `backend.ui_call(page, fn)`. Using `page.run_thread()` directly causes
  `IndexError` in `_compare_lists`. To create threads, use
  `backend.safe_thread(page, target)`. See [backend.md](backend.md) and
  [frontend.md](frontend.md).
- `TAG_PROFILES` and `LAB_ACRONYMS` are defined only in
  `bifrost-transfer/src/meta_fields.py`; the copy form and Tag Manager consume
  them from there. Do not duplicate definitions in the views or `main.py`.

## High-level flows

- Desktop: login (LDAP) → MinIO server selection → automatic temporary STS
  credentials → action view (mount or copy).
- Web (transfer only, Open OnDemand): same, with a persistent session in
  `_WEB_SESSIONS` (`web_session.py`) and tab reconnection. See
  [frontend.md](frontend.md).

## Legacy zone

`old/` contains legacy scripts (`backend-old.py`,
`minio-sts-credentials-request.py`): do not use or modify.
