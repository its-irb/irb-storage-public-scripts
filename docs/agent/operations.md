# Operation: running, packaging, CI and environment variables

## Development

**Prerequisites**: Python **≥ 3.11** (CI uses 3.12), **uv** (environment
manager), Nexica VPN (Forticlient) to **run** the apps (LDAP/MinIO). `flet`
(0.84.0) and the other deps are frozen in each app's `pyproject.toml`; `uv sync`
installs them.

```bash
pip install uv
```

**Important**: the `rclone` and `fuse-t` binaries are **not versioned**
(`src/assets/bin/` and `frameworks/` are gitignored, only the `.keep` files
remain): download them with the `shared/*-assets-downloader.sh` scripts.

From the app folder (`bifrost-mount/` or `bifrost-transfer/`):

```bash
# First time: generate pyproject.toml from the template and point __BUILDPATH__ to shared/
cp pyproject-template.toml pyproject.toml
sed -i '' "s|__BUILDPATH__|${PWD}/..|g" ./pyproject.toml   # macOS (no '' on Linux)

# Virtual environment
uv sync
```

Binary download (mandatory; the scripts use relative paths, so run them from
the `src/` of **each app** — each one downloads its own copy even though the
command is the same; repeat the step in the other app):

```bash
cd src   # inside the app you are in (bifrost-mount/ or bifrost-transfer/)
# Only the script for your platform:
bash ../../shared/macos-assets-downloader.sh      # mount macOS: rclone + fuse_t.framework
bash ../../shared/macos-rclone-downloader.sh      # transfer macOS: rclone
bash ../../shared/windows-assets-downloader.sh    # Windows: rclone.exe
bash ../../shared/linux-assets-downloader.sh      # Linux (cluster): rclone
cd ..   # back to the app folder
```

```bash
# Activate
source .venv/bin/activate            # macOS/Linux
# Windows: .\.venv\Scripts\Activate.ps1 (PowerShell) | .\.venv\Scripts\activate.bat (CMD)

# Run
flet run
```

Useful flags:

```bash
flet run --customuser     # Sign in with a user different from the system one
flet run --update         # Force autoupdate
flet run --web            # (transfer only) web mode for local development
BIFROST_CLUSTER=1 python src/main.py --web  # (transfer only) simulate OOD production
```

After changing code in `shared/`, reinstall the shared package:

```bash
uv sync --reinstall-package bifrost-shared
```

## Packaging

Common prerequisite: local `pyproject.toml` generated from the template with
`__BUILDPATH__` replaced, synced venv and downloaded assets.

| Environment | Notes |
|---|---|
| Local Windows | Regenerates `pyproject.toml`, downloads rclone, reinstalls `bifrost-shared` and runs `flet build windows`. The installer (Inno Setup) is packaged separately. |
| Local macOS | From the app folder; requires Xcode. Local version `2.0.0.dev`; in mount it copies `fuse_t.framework` into the bundle. |
| CI | `.github/workflows/main.yml` — macOS (`.app` → DMG) and Windows (build + Inno Setup + installer signing) for both apps. **There is no Linux job.** |
| Linux (cluster) | No packaging: `bifrost-transfer` runs from source in web mode (Open OnDemand, `BIFROST_CLUSTER=1`). |

Local builds:

```bash
# macOS (from the app folder)
./build-macos.sh
```

```powershell
# Windows (from the repo root)
.\build-windows.ps1 -app bifrost-mount    # or -app bifrost-transfer
```

Windows installer (Inno Setup, separate from the build):

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DAppVersion=<version> /DAppName=<app> /DBranchSuffix=<suffix> <app>\installer.iss
```

`<version>` is the version number, `<app>` the app folder name and `<suffix>`
the branch suffix of the installer file name.

When adding/updating Python dependencies (frozen per app):

```bash
uv add <package>
```

## CI and releases

- Triggers: push to `main`, `release`, `develop`, `feature/**` (only with
  changes in the apps, `shared/` or the workflow) + `workflow_dispatch`.
- CI toolchain: Python 3.12, `uv` via pip, **Node 24** (needed for
  `flet build windows`), `PYTHONUTF8=1` on Windows.
- The version is injected as `1.0.<run_number>` in `src/version.py` and in each
  app's `pyproject.toml` before the build (the template version is `2.0.0`).
- `release` job (only on `main` and `release`): publishes the release with tag
  `v1.0.<run_number>` and the artifacts (macOS: `bifrost-<flavour>-macos.dmg`;
  Windows: installer `.exe` **signed** with `signtool`, PFX from the secrets
  `IRBCODESIGNING`/`IRBCODESIGNING_PASSWORD`). The apps' autoupdate downloads
  from those releases.

## Tests

**There is no automated test suite.** Changes are validated by running the apps
manually (`flet run`).

## Environment variables

| Variable | Applies to | Effect |
|---|---|---|
| `BIFROST_CLUSTER=1` | transfer | Enables `IS_WEB` (full web mode; OOD production signal) |
| `BIFROST_NO_LDAP=1` | both | Skips LDAP validation at login (machines without LDAP but with MinIO access, for example IVIS). The user still types username+password (needed for STS). Header badge: `DESKTOP (NO LDAP)`. On Windows define it as a system variable (see below). |
| `FLET_ASSETS_DIR` | both | Set by Flet at runtime; the backend uses it to locate the bundled `rclone` |
| `FLET_APP_STORAGE_TEMP` | both | Set by Flet; used to debug binary location |

```powershell
# BIFROST_NO_LDAP as a Windows system variable (applies to all users)
setx BIFROST_NO_LDAP 1 /M
```

## Commit hygiene

Do not commit `.venv/`, `dist/`, `build/`, generated `src/version.py`, the
downloaded binaries (`src/assets/**/*`, `frameworks/*`) or the local
`pyproject.toml` of the apps (only the `pyproject-template.toml` templates). See
`.gitignore`.

## Documentation

Documentation is updated with the `docs-update` skill (invoke `/docs-update`).
It reviews changes since the last documented commit
(`documentation.last_reviewed_commit` in `.agentic.lock.json`), proposes the
changes and applies them only after human confirmation. Layers: `docs/agent/`
(English), `docs/development/` (Spanish), `docs/user/` (English), plus
`README.md` and `AGENTS.md`.
