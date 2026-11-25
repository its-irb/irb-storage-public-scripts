# AGENTS.md — BIFROST

Entry point for any coding agent. BIFROST is a pair of Flet/Python desktop apps
for IRB Barcelona's MinIO storage: **bifrost-transfer** (copy data to MinIO,
Tag Manager, web mode on Open OnDemand) and **bifrost-mount** (mount MinIO
folders as a local drive). Both share the `shared/` package (`bifrost-shared`).

## Where the knowledge lives

Start with `docs/agent/README.md` and load only the module you need:

| Task | Read |
|---|---|
| Anything | `docs/agent/architecture.md` |
| Backend (`shared/bifrost_backend/`) | `docs/agent/backend.md` |
| Apps / UI (`bifrost-*/src/`, `shared/bifrost_frontend/`) | `docs/agent/frontend.md` |
| Run, package, CI, environment variables | `docs/agent/operations.md` |
| Before changing code | `docs/agent/conventions-gotchas.md` |

Other layers: `docs/development/` (developers, Spanish) and `docs/user/` (users,
English). Documentation methodology: `docs/documentation-methodology.md`.

## Rules that always apply

- Any UI mutation from a background thread goes through `backend.ui_call(page, fn)`;
  create threads with `backend.safe_thread(page, target)`.
- The macOS asset downloaders pick the rclone architecture from `uname -m`
  (`arm64` Apple Silicon / `amd64` Intel); override with the `RCLONE_ARCH` env var.
- Profiles and lab acronyms are defined only in `bifrost-transfer/src/meta_fields.py`.
- In `bifrost-transfer`, `IS_WEB` is computed only in `src/main.py`; a module that
  reads it declares `IS_WEB = False` and must be added to `_propagar_is_web()`.
- Automated tests (pytest) cover pure logic only (`tests/`, `bifrost-transfer/tests/`); validate UI changes by running the app (`flet run`).
- Commit types decide the release version when they reach `main` (`.github/scripts/next_version.py`):
  `feat` → minor, `fix`/`perf`/`revert`/`build` → patch, `!` or `BREAKING CHANGE:` → major,
  `Release-As: X.Y.Z` in a commit body forces it; `docs`/`style`/`refactor`/`test`/`ci`/`chore` release nothing.
- Never commit `.venv/`, `dist/`, `build/` or local `pyproject.toml` files. `src/version.py` is tracked with the
  development version `0.0.0.dev` (CI writes the real one): never commit another value.

## Keeping the documentation up to date

Run the `docs-update` skill (`/docs-update`). It reviews the changes since the
last documented commit, proposes the documentation updates for every layer
(including `README.md` and this file) and applies them only after human
confirmation.

## Known false positives for secrets

None registered.
