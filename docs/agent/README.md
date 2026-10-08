# Agent documentation — BIFROST

BIFROST is a pair of desktop apps (Flet/Python) for IRB Barcelona's MinIO S3
server: **bifrost-transfer** (copy data to buckets with integrity checks and
tagging; includes Tag Manager and web mode) and **bifrost-mount** (mount
buckets as a local drive). Both share the `bifrost-shared` package (`shared/`).

Read only the module you need for the task. Index:

| Module | When to read it |
|---|---|
| [architecture.md](architecture.md) | Any task: what each component is, repo layout, coupling and invariants. |
| [backend.md](backend.md) | Changes in `shared/bifrost_backend/` (rclone, STS, LDAP, SMB, S3, tagging, autoupdate). |
| [frontend.md](frontend.md) | Changes in `bifrost-*/src/` (Flet views, web mode, `meta_fields.py`, UI conventions). |
| [operations.md](operations.md) | Running, packaging, CI, releases, environment variables. |
| [conventions-gotchas.md](conventions-gotchas.md) | Before modifying code: critical rules and known pitfalls. |

## Context notes

- **Language of the documentation**: `docs/agent/` and `docs/user/` are written
  in **English**; `docs/development/` is written in **Spanish**.
- **Language of the code**: follow the surrounding code. Backend function names,
  many comments and docstrings are in Spanish; UI strings in the apps are mostly
  English (for example "Source path", "Connect"). The WinFsp flow of
  `bifrost-mount` is in English.
- **There is no automated test suite**: validation is manual with `flet run`.
- `docs/agent/` should be enough for routine work; consult `docs/development/`
  only to go deeper when updating that layer.
- **Entry point for any agent**: `AGENTS.md` at the repo root points here.
  `CLAUDE.md`, `CLAUDE_BACKEND.md` and `CLAUDE_FRONTEND.md` only redirect to this
  documentation. Do not add content to them.
- `docs/superpowers/` holds historical design specs and plans for individual
  features (for example the SFTP source). They are background, not the source
  of truth; the current state of the repository prevails.

## Documentation style conventions

- Commands presented as **instructions** always go in fenced code blocks
  (`bash` for bash, `powershell` for Windows commands); inline formatting is
  used only for nominal references in prose (tool, script, file or flag names).
- User documentation (`docs/user/`) follows `.agentic/instructions/docs-local.md`:
  always "MinIO" (never "S3"), "copy" (never "transfer" or "move"), and every
  technical term explained in plain words.
