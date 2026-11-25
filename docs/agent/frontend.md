# Frontend — Flet apps (`bifrost-mount` / `bifrost-transfer`) and `shared/bifrost_frontend`

## Per-app layout

```text
<app>/
  pyproject-template.toml  # Template; pyproject.toml is generated locally
  installer.iss            # Inno Setup (Windows)
  build-macos.sh
  frameworks/              # fuse_t.framework (mount, macOS) — downloaded (not versioned)
  src/
    main.py                # Flet entry point
    config.py              # APP_INFO = {"flavour": ..., "name": ..., "description": ...}
    version.py             # __version__ — 0.0.0.dev in the repo; CI writes the real one
    assets/bin/            # rclone(.exe) — downloaded with the downloaders (not versioned)
    views/                 # the app's own views
    storage/               # (transfer only) temporary data
```

| App | Modules in `src/` besides `main.py` |
|---|---|
| `bifrost-mount` | `views/servers.py` (`build_servers_content`: one card per MinIO server; mounts, opens or unmounts it in a thread and reads its state from the backend, `active_mount_point`, instead of keeping it), `views/server_card.py` (`ServerCard`: name, endpoint, credentials expiry, mount point, Mount/Open, Unmount, Renew credentials; double-click = Mount; never calls the backend), `views/winfsp_dialog.py` (`prompt_install_winfsp`). The Renew dialog is shared (`show_renew_dialog`, see below). |
| `bifrost-transfer` | `web_session.py`, `meta_fields.py`, `views/shares.py` (`_build_shares_content`), `views/rclone_browser.py` (`build_rclone_browser` folder navigator), `views/local_fs.py` (`build_local_fs_browser`, `show_local_fs_modal`), `views/copy.py` (`_build_copy_content`), `views/tag_manager.py` (`_build_tag_manager_content`). |

`build_rclone_browser` only exists in transfer (folder navigator).

## `shared/bifrost_frontend`

`frontend.py` is a facade: it re-exports `theme.py` (palette `C_*`, fonts,
`apply_theme`, `tint`), `components.py` and the shared views. Components:

| Component | What it is |
|---|---|
| `btn_primary(text, on_click=None, width=None, disabled=False, icon=None)`, `btn_secondary(text, on_click=None, width=None, icon=None)` | Buttons; `icon` is a Material icon (`ft.Icons.*`). |
| `btn_nav(text, on_click=None, icon=ft.Icons.ARROW_BACK)` | Discreet navigation button ("Back to login"). |
| `nav_bar(back_text=None, on_back=None, *, usuario=None)` | Top row of a screen: back button on the left (only with `on_back`), "Signed in as <usuario>" on the right. |
| `icon_tile(icon, color, size=44)` | Icon on a rounded square tinted with its colour (card and dialog headers). |
| `expiry_label(session) -> (text, color)`, `expiry_chip(session)` | Credentials expiry text/colour (red under 1 day, amber up to 3) and its chip with a key icon. |
| `card`, `section_title`, `field_label`, `styled_field`, `status_badge`, `build_header`, `log_text` | As before. |
| `open_dialog(page, *, title, color, icon, body, actions, subtitle="")` | Modal with the common look: icon tile, title, optional subtitle, body, buttons on the right. |
| `show_dialog`, `show_issue`, `show_confirm` | Notices, program errors and Yes/No (see "UI conventions"). |
| `tip_box(text)`, `error_code_row(page, ref)` | "What you can do" box and the error code row with a copy button. |
| `ErrorBanner(value="", visible=…)` | Error inside a screen or dialog (red box with icon). Drop-in for the red `ft.Text` it replaced: change `value` and `visible`; a leading "⚠️"/"❌" is stripped. |

Shared views:

| View | Signature | Notes |
|---|---|---|
| `views/update.py` | `build_update_content(page, on_continue)` | First screen; checks GitHub releases and installs updates. |
| `views/login.py` | `build_login_content(page, on_success, prefill_user="", *, no_ldap, is_web=False)` | Locks button and fields while validating (`_set_busy`), so Enter/click cannot start a second LDAP check. Message per `validar_credenciales_ldap` reason (`_LDAP_ERROR_MESSAGES`); "Username is required." / "Password is required." for empty fields; the password is not stripped. Writes `LOGIN attempt/bypass LDAP/success — user: <user>` and `LOGIN failed — user: <user> — reason: <reason>` to the technical log (logger `bifrost.login`), the same in both apps. `prefill_user` shows the "Resuming previous session" banner (transfer web). |
| `views/minio.py` | `build_minio_content(page, on_continue, *, no_ldap, is_web=False, on_back=None, usuario=None)` | MinIO server selection (transfer): one card per server with its credentials expiry; click selects, double-click or "Continue" goes on. `on_back` → login; `usuario` is shown top right. |
| `views/credentials.py` | `build_credentials_content(page, perfil_rclone, endpoint, credenciales_ldap, on_continue, extra_config=None, duracion_dias=None, on_back=None, *, no_ldap, is_web=False, done_message, on_cancel=None, cancel_label="Back")` | STS renewal: a state card (renewing / error / renewed) and the on-screen log. On failure it shows what to do (`tip_box`), the code (`error_code_row`) and "Try again", except for a wrong password without LDAP (`on_back` set: "Back to login" instead, retrying would repeat the same password). An unexpected exception in the renewal also ends in the error state (never stuck). With `on_cancel`, a `nav_bar` button (`cancel_label`) leaves at any time; after that the thread neither touches the screen nor navigates. The technical log (logger `bifrost.auth`) gets one line per step (`credentials: renewing …`, `credentials: renewed …`, `credentials: retrying …`, request failures), not the on-screen text; `done_message` is the last line ("Loading servers…" / "Continuing to copy interface…"). |
| `views/renew_dialog.py` | `show_renew_dialog(page, *, perfil, usuario, on_renew)` | "Renew MinIO credentials" dialog (1–30 days, default 7; Enter confirms); calls `on_renew(days)`. Used by mount's server cards and transfer's copy view. |

Differences between the apps are parameters; do not copy these views back into
an app.

## Initialisation of each `main.py`

```python
from bifrost_backend import backend
from bifrost_backend.common.constants import NO_LDAP, STS_RENEWAL_THRESHOLD_DAYS
from bifrost_frontend.frontend import *      # theme + components + shared views
```

Then: 1) (transfer) computes the run mode (`IS_WEB`) and calls
`_propagar_is_web()`; 2) re-wraps `sys.stdout`/`sys.stderr` in UTF-8 (Windows
console) — **do not touch**; 3) technical log with `backend.setup_logging(...)` and shutdown cleanup with
`backend.register_shutdown(...)` (see `docs/development/operations.md#logs`); `main()` calls
`install_window_close(page)` (window close → `backend.request_shutdown("window")`, destroy the window, exit);
4) defines `main(page: ft.Page)` and starts with `ft.run(main)` (in cluster
mode transfer also builds the ASGI `app` with `ft.app(main, export_asgi_app=True)`).

## View flow

```text
bifrost-mount (pure desktop):
  view_update → view_login ⇄ view_servers ⇄ view_credentials
  (view_servers: one card per server; each server is mounted whole, with its
  buckets as folders. view_credentials comes up when mounting needs a renewal,
  then goes back to view_servers and mounts; or from "Renew credentials".)

bifrost-transfer (desktop and web; web skips view_update and starts at view_login):
  view_update → view_login ⇄ view_minio ⇄ view_credentials (auto) → view_copy
  view_copy ⇄ view_credentials (manual), view_copy ⇄ Tag Manager, view_copy ⇄ NetApp shares (web)
```

Every screen has a `nav_bar` at the top: a back button (top left) and "Signed
in as <user>" (top right). Back targets: servers/minio → login; renewal →
servers (automatic) or copy (manual, transfer); copy → minio; Tag Manager and
NetApp → copy. In mount, going back to the login does not unmount anything
(view_servers reads the mount state from the backend when it is built).

`view_copy` contains the rclone folder browser for the destination
(`build_rclone_browser`), the source selector (SMB/local/SFTP), copy options
and the live log panel (`ft.ListView` with `auto_scroll=True`).

## STS credentials — auto-renewal and manual renewal

Constants in `bifrost_backend.common.constants`:
`STS_RENEWAL_THRESHOLD_DAYS = 3`, `STS_AUTO_RENEWAL_DAYS = 7`. After choosing
the server (transfer) or when mounting one (mount, `views/servers.py`), the app calls `backend.hay_que_renovar_credenciales(profile, user)`
(it logs the decision in one line); if there is no token or
`needs_renewal(user, STS_RENEWAL_THRESHOLD_DAYS)` is true (token of another user,
unreadable, or 3 days or less left), it shows
`build_credentials_content` and renews for 7 days, showing progress; otherwise
it goes straight to the action view (in mount: mounts the server).

Each server card in mount, each card of transfer's server selection and the
server card of the copy view show a chip (`expiry_chip`: key icon + "Credentials
expire in 6d 23h", red under 1 day, amber up to 3 days). Mount's cards and the
copy view have a **"Renew credentials"** button that opens `show_renew_dialog`
to renew manually for 1–30 days (default 7).

## `meta_fields.py` (bifrost-transfer only)

- `TAG_PROFILES` — metadata profiles (`IRB Standard`, `Histopathology IRB Core
  Facility`, `Advanced Genomic Technologies IRB Core Facility`); canonical
  source used by the copy form and Tag Manager. Field tuple:
  `(label, key, FieldType, allow_custom, options, helper[, required])`; when
  `required` is true the label is shown with ` *`. **The profile name is the
  value of the `provider` tag**; `provider` is not declared in `TAG_PROFILES`.
- `profile_fields(name)` — fields of a profile with the locked Provider first
  (its only option is the profile name).
- `apply_provider(name, values)` — copy of `values` with `provider` forced to
  the profile name (used on prefill).
- `missing_required(name, values)` — labels of empty required fields (internal).
- `validate_profile_tagset(name, tags)` — the **only** validation the views call
  on Copy/Apply/Save: characters and length (`validate_tagset`) plus
  `Missing required fields: ...`. Returns a list of errors.
- `check_tag_value(text, max_len=TAG_VALUE_MAX)`, `validate_tagset`,
  `TAG_KEY_MAX` (128) and `TAG_VALUE_MAX` (256) — S3 tag limits and allowed
  characters.
- `LAB_ACRONYMS` — exact acronyms that appear in the `acronym` tag of MinIO
  buckets.
- `build_meta_fields(..., prefill_values: dict[str, str] | None)` — builds the
  form controls; `prefill_values` pre-fills them with existing tags.
- `build_lab_filter_widget(...)` — the "Filter by lab…" widget of the browsers.
- `detect_profile(tags: dict[str, str])` — detects the profile that fits a tag
  dict: first by `provider` (== profile name) when all the tag keys belong to
  that profile (otherwise `None`: the file opens in raw mode, so saving in
  profile mode never drops foreign tags); then, for objects without a known
  provider, by key subset.

## Web mode (`bifrost-transfer`, Open OnDemand) — essentials

```python
IS_CLUSTER = os.environ.get("BIFROST_CLUSTER") == "1"
IS_WEB = ("--web" in sys.argv) or (__name__ != "__main__") or IS_CLUSTER
```

**Why two variables.** `IS_WEB` answers "is there a browser?"; `IS_CLUSTER`
answers "is Hypercorn serving this under OOD?". They are not the same:

| How it starts | `IS_WEB` | `IS_CLUSTER` |
|---|---|---|
| Desktop (`python main.py`) | False | False |
| Local web dev (`flet run --web`, `python main.py --web`) | True | False |
| Cluster OOD (Hypercorn, `script.sh.erb` exports `BIFROST_CLUSTER=1`) | True | True |

`IS_CLUSTER` gates what must only happen on the cluster:

- The `if IS_CLUSTER:` block at the end of `main.py` that builds the `FastAPI`
  app, mounts Flet and defines the authenticated WebSocket endpoint (the `app`
  Hypercorn loads as `main:app`). With `IS_WEB` it would also run in local web
  dev, where Flet starts its own server, and the two would clash.
- `register_shutdown(..., server_managed=IS_CLUSTER)`: on the cluster the
  server manages shutdown; in local dev the process does.

`IS_WEB` cannot replace it: under Hypercorn it is already true (`__name__ !=
"__main__"`), but so it is under `flet run`, so it does not tell the cluster
apart. Do not remove `export BIFROST_CLUSTER=1` from
`ood-app-bifrost/template/script.sh.erb`: without it `main:app` does not exist
and Hypercorn fails at startup. History: this was tried in the June 2026
simplification (single `IS_WEB`, spec in `docs/superpowers/specs/`) and
reverted the next day (`5e6246b`).

- `main(page)` also sets `IS_WEB = IS_WEB or page.web`. `IS_WEB` lives only in
  `main.py`; `_propagar_is_web()` copies it to `web_session`, `views.shares`,
  `views.copy`, `views.tag_manager` and `views.rclone_browser` (see `architecture.md`).
- ASGI server: **Hypercorn** (a single asyncio event loop). Each tab opens its
  own WebSocket with its own `page` object.
- Sessions in `_WEB_SESSIONS` (`web_session.py`; global dict by `username`;
  TTL = life of the Hypercorn process). **The LDAP password is never stored.**
  `_ws_clear` runs when a different username signs in (on restore or on a
  normal login); there is no logout.
- Reconnection: when the tab is reopened the user only re-enters the password;
  `_replay` restores state, replays the last 200 buffer lines and re-attaches
  the rclone process if it is still alive. `go_login(resume=True)` (default)
  is what restores; "Back to login" of view_minio calls `go_login(resume=False)`:
  a normal login that goes to view_minio. The session is kept for the same
  user, so a running copy stays attached when that server is chosen again.
- Log dispatcher `_dispatch_log` with a **150 ms throttle** (buffer cap 5000
  lines, several callbacks per user, `_dispatch_lock` lock). Without the
  throttle Hypercorn saturates and reconnections hang.
- Per-operation report: each copy/check keeps its own lines (`op_log`); when it
  ends, `on_finish(summary)` writes the report with `_write_report` to
  `backend.report_path("copy"|"check")` (desktop: `<log dir>/reports/`; web:
  `$BIFROST_SESSION_DIR/reports/`). rclone output is parsed by
  `common/rclone_output.RunSummary` (panel: progress + summary; raw output to the
  technical log). Do not rebuild reports from the web buffer or the UI controls.
- The `Mount NetApp` button (web mode only) opens the CIFS shares view
  (`go_cifs`).

Full detail in [../development/frontend.md](../development/frontend.md).

## Absolute thread-safety rule

> Any mutation of `control.controls` or call to `page.update()` from outside
> the Flet event loop must be wrapped in `backend.ui_call(page, fn)`.

Only Flet event handlers (buttons, dialogs) may call `page.update()` directly.
With `threading.Timer`, wrap the callback:
`threading.Timer(0.1, lambda: ui_call(page, fn)).start()`.

## UI conventions

- **Language**: follow the surrounding code; UI strings in the apps are mostly
  English (for example "Source path", "Connect", "Back to login"). The WinFsp
  installation flow messages in `bifrost-mount` are in English.
- **Colours**: only constants from `bifrost_frontend.frontend` (`C_PRIMARY`,
  `C_ERROR`, …). Do not hardcode hex values. Translucent backgrounds and
  borders: `tint(color, opacity)`, never `f"{C_X}22"` (Flet reads `#RRGGBBAA`
  as `#AARRGGBB`, so the colour changes: amber looked red).
- **Buttons**: prefer `btn_primary` / `btn_secondary` over raw `ft.Button`. Put
  the icon in `icon=` (Material icon), not an emoji in the label (emojis render
  as boxes on some systems).
- **Navigation**: every screen starts with `nav_bar(back_text, on_back,
  usuario=…)`; no screen should be a dead end.
- **Error dialogs**: notices about what the user typed: `show_dialog(page, title, msg, color=C_ERROR)`. Program
  errors (`UserIssue`): `show_issue(page, issue, *, is_web, title=None, context="", screen=…, buttons=[(label,
  action), …], ref=None) -> str` — header with icon and title, and under it `context` (the bucket, one file or a
  count; never lists or log paths); then what happened, the "What you can do" box (`tip_box`) and the error code
  ("MNT101-1103-141526") in its own row with a copy button (`error_code_row`); each button closes the dialog,
  then runs its action. `screen` (`mount`, `netapp`, `copy`, `check`, `tags`, `app`) sets the code prefix and
  the hint; `ref` reuses a code (an operation's, or the one shown the first time); it returns the code. An
  error shown instead of a list: `issue_line(issue, *, is_web, screen)`, shown in an `ErrorBanner`. Both log
  `issue shown: ref=… code=… screen=…` through `issue_reference(issue, screen, ref=None)`, which the
  credentials screen (`CRD`) and the login (`LGN`) call directly; the login only logs it and does not show the
  code (noise there). New dialogs use `open_dialog` for the same look.
- **Errors inside a screen or dialog**: `ErrorBanner`, not a red `ft.Text`. Field validation under a single
  field (metadata, tag rows) stays a small red text.
- **Header**: `build_header(subtitle, IS_WEB, no_ldap, page=None)`; with `page`, on desktop, the "Export logs…"
  button (confirmation, then `backend.export_logs_zip()`). Every screen passes `page`.
- **Log panel lines**: `log_text(line)` (colour from the leading emoji; used by copy and Tag Manager).
- **Confirmations**: `show_confirm(page, title, message, on_yes, on_no=None)` (same header, question icon).
- **Copy logs** (transfer/web): always go through `_dispatch_log`; never
  `log_list.controls.append(...)` directly from a thread.
