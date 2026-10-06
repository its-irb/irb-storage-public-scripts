# Architecture

## Components

| Component | Folder | Role |
|---|---|---|
| **bifrost-transfer** | `bifrost-transfer/` | Copies data from network shares (SMB/CIFS), SFTP servers or local paths to MinIO S3 buckets, with integrity checks and tagging by metadata profile. Includes **Tag Manager** (bulk tagging without re-upload) and **web mode** (Open OnDemand). |
| **bifrost-mount** | `bifrost-mount/` | Mounts MinIO S3 folders as a local drive (Windows/macOS/Linux). Desktop mode only. |
| **bifrost-shared** | `shared/` | Common wheel package: `bifrost_backend.backend` (all business logic) and `bifrost_frontend.frontend` (palette + Flet components). |

Both apps are Flet apps with entry point `src/main.py` and one `pyproject.toml`
per app.

## Repository layout

```text
bifrost-mount/            # Mount app (desktop)
  src/
    main.py               # Flet GUI — entry point
    config.py             # APP_INFO = {"flavour": "mount", ...}
    version.py            # __version__ (written by CI/build)
    assets/bin/           # bundled rclone
    frameworks/           # fuse_t.framework (macOS)
  pyproject-template.toml # Template; pyproject.toml is generated locally (not versioned)
  installer.iss           # Inno Setup (Windows installer)
  build-macos.sh

bifrost-transfer/         # Transfer app (desktop + web)
  src/
    main.py               # Flet GUI
    meta_fields.py        # Profiles, metadata fields, lab filter
    config.py             # APP_INFO = {"flavour": "transfer", ...}
    version.py
    assets/bin/
    storage/              # Temporary transfer data
  pyproject-template.toml
  installer.iss
  build-macos.sh

shared/                   # bifrost-shared package (local wheel)
  bifrost_backend/backend.py
  bifrost_frontend/frontend.py
  pyproject.toml          # Defines the "bifrost-shared" package
  requirements.txt        # Common dev deps
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
- `bifrost_backend.backend` — LDAP, rclone (exec, profiles, copy/check, listing), STS, SMB/CIFS, boto3 tagging, `ui_call()`, `safe_thread()`, autoupdate.
- `bifrost_frontend.frontend` — palette (`C_BG`, `C_PRIMARY`, …), buttons (`btn_primary`, `btn_secondary`), `show_dialog`. Each app does `from bifrost_frontend.frontend import *`.

**App-specific**:
- `src/main.py` — Flet view flow (login → minio → credentials → mount/copy) and all app UI. In `bifrost-transfer` it also holds Tag Manager and web mode.
- `src/meta_fields.py` — **`bifrost-transfer` only**: `FieldType`, `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS`, `build_lab_filter_widget`, `detect_profile`. Canonical source of profiles and fields.
- `src/config.py` — only `APP_INFO`. The backend reads `APP_INFO["flavour"]` to resolve asset paths in dev.
- `src/version.py` — written by CI/build (`__version__ = "1.0.<run_number>"`).
- `installer.iss`, `build-macos.sh`, `pyproject-template.toml` (frozen deps per app).

## Coupling and invariants

- Apps import the backend with `from bifrost_backend import backend` and
  `from config import APP_INFO`. **`config.py` must be importable as a
  top-level module in each app** (that is why each app has its own, even though
  it only contains `APP_INFO`).
- Each app's `pyproject.toml` references
  `bifrost-shared @ file:///__BUILDPATH__/shared`; the build script (CI,
  `build-windows.ps1` or `build-macos.sh`) replaces `__BUILDPATH__` with the
  real path of the shared package. `pyproject.toml` is not versioned: it is
  generated from `pyproject-template.toml`.
- The backend imports from the frontend (`show_dialog`, `C_ERROR` from
  `bifrost_frontend.frontend`): it is not a decoupled backend. Do not introduce
  new circular imports.
- **Thread-safety rule**: any mutation of `control.controls` or call to
  `page.update()` from a background thread must be wrapped in
  `backend.ui_call(page, fn)`. Using `page.run_thread()` directly causes
  `IndexError` in `_compare_lists`. To create threads, use
  `backend.safe_thread(page, target)`. See [backend.md](backend.md) and
  [frontend.md](frontend.md).
- `TAG_PROFILES` and `LAB_ACRONYMS` are defined only in
  `bifrost-transfer/src/meta_fields.py`; the copy form and Tag Manager consume
  them from there. Do not duplicate definitions in `main.py`.

## High-level flows

- Desktop: login (LDAP) → MinIO server selection → automatic temporary STS
  credentials → action view (mount or copy).
- Web (transfer only, Open OnDemand): same, with a persistent session in
  `_WEB_SESSIONS` and tab reconnection. See [frontend.md](frontend.md).

## Legacy zone

`old/` contains legacy scripts (`backend-old.py`,
`minio-sts-credentials-request.py`): do not use or modify.
