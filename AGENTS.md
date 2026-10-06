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
| Apps / UI (`bifrost-*/src/`) | `docs/agent/frontend.md` |
| Run, package, CI, environment variables | `docs/agent/operations.md` |
| Before changing code | `docs/agent/conventions-gotchas.md` |

Other layers: `docs/development/` (developers, Spanish) and `docs/user/` (users,
English). Documentation methodology: `docs/documentation-methodology.md`.

## Rules that always apply

- Any UI mutation from a background thread goes through `backend.ui_call(page, fn)`;
  create threads with `backend.safe_thread(page, target)`.
- Profiles and lab acronyms are defined only in `bifrost-transfer/src/meta_fields.py`.
- There is no automated test suite: validate by running the app (`flet run`).
- Never commit `.venv/`, `dist/`, `build/`, generated `src/version.py` or local `pyproject.toml` files.

## Keeping the documentation up to date

Run the `docs-update` skill (`/docs-update`). It reviews the changes since the
last documented commit, proposes the documentation updates for every layer
(including `README.md` and this file) and applies them only after human
confirmation.

## Known false positives for secrets

None registered.
