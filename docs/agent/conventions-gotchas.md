# Critical rules and gotchas

Cross-cutting knowledge that constrains any change. Technical details in
[backend.md](backend.md) and [frontend.md](frontend.md).

## Threading and Flet

1. **`ui_call` is mandatory**: any mutation of `control.controls` or
   `page.update()` from a background thread must be wrapped in
   `backend.ui_call(page, fn)`. Using `page.run_thread()` directly causes
   `IndexError` in `_compare_lists` of Flet's diff walker. To create threads,
   use `backend.safe_thread(page, target)` — it catches exceptions and shows
   them in a dialog.
2. **`threading.Timer`**: wrap the callback (`lambda: ui_call(page, fn)`);
   never pass the navigation function directly.
3. **Windows console encoding**: `main.py` re-wraps `sys.stdout`/`sys.stderr`
   in UTF-8 at startup (`TextIOWrapper` block). Do not touch it.

## Structure and coupling

4. **The backend imports from the frontend**: `backend.py` uses `show_dialog`
   and `C_ERROR` from `bifrost_frontend.frontend`. It is coupled (not a "pure"
   backend).
5. **`config.py` must be importable as a top-level module** in each app — the
   backend does `from config import APP_INFO`.
6. **`TAG_PROFILES` and `LAB_ACRONYMS` are canonical in
   `bifrost-transfer/src/meta_fields.py`**: the copy form and Tag Manager use
   `TAG_PROFILES`, `build_meta_fields`, `LAB_ACRONYMS`,
   `build_lab_filter_widget` and `detect_profile` from there. To add, rename or
   reorder a field, profile or lab, change it **only** in `meta_fields.py`.
   `LAB_ACRONYMS` must contain the exact acronyms of the `acronym` tag of the
   MinIO buckets. `detect_profile(tags)` finds which profile fits a
   `dict[str, str]` of tags; `build_meta_fields` accepts the optional
   `prefill_values: dict[str, str]` to pre-fill controls.

## Visible behaviour to preserve

7. **STS credentials**: if more than 3 days remain they are reused; with less
   than 3 days they are renewed automatically for 7 days
   (`STS_RENEWAL_THRESHOLD_DAYS` / `STS_AUTO_RENEWAL_DAYS` in `main.py`).
8. **WinFsp auto-install (`bifrost-mount` only, Windows)**: if WinFsp is
   missing when mounting, the backend raises `WinFspMissingError` (subclass of
   `EnvironmentError`) and the UI offers to download the latest official
   release (`github.com/winfsp/winfsp`) through
   `backend.install_winfsp_windows()`. It needs UAC; the MSI is cached in
   `%TEMP%`. The messages of this flow are in **English**. `bifrost-transfer`
   has no such flow.
9. **Language of the code**: follow the surrounding code (backend names,
   comments and docstrings are mostly Spanish; UI strings in the apps are
   mostly English).
10. **Conditional visibility in the copy form**: the METADATA section, action
    buttons and LOG OUTPUT (`bottom_col.visible=False`) stay hidden until a
    destination bucket is selected. The toggle lives in `on_browser_select`:
    non-empty `path` → visible; back to root → hidden.
11. **Lab filter in bucket browsers**: the destination browser of the copy view
    and the Tag Manager browser include "Filter by lab…"
    (`build_lab_filter_widget`), which reads the `acronym` tag of each bucket
    with `backend.get_bucket_tags` in parallel (`ThreadPoolExecutor`). It hides
    when navigating into a bucket and reappears at the root. It only filters at
    bucket level (root).
12. **Ephemeral SFTP source (`bifrost-transfer`)**: the "🌐 SFTP" button creates
    a temporary rclone profile (`sftp-src-<random>`, type `sftp`, password
    obscured with `rclone obscure`) in `rclone.conf`. For security it **must not
    outlive the session**: it is deleted on Disconnect (✕) and on leaving the
    copy view (`on_back`), and any orphan `sftp-src-*` is swept after every
    login (`backend.limpiar_perfiles_rclone_con_prefijo`). The connection
    dialog only requires host and username (password optional; port defaults
    to 22). The SFTP browser (`allow_mkdir=False, show_files=True`) does not
    offer creating folders and lists files through `backend.rclone_lsjson`;
    the S3 destination browser only lists folders through `backend.rclone_lsd`
    because MinIO listing over HDD is slow. A folder or a single file can be
    chosen as the source (same `profile:path` format). Background in
    `docs/superpowers/specs/2026-07-30-sftp-source-design.md`.
13. **"Mount NetApp" button (`bifrost-transfer`, web mode only)**: the copy
    view shows `⊞  Mount NetApp` only when `IS_WEB` is true and the `on_cifs`
    callback exists; it opens the CIFS shares view (`go_cifs`).
14. **Known cluster limitation (from the maintainers)**: Bifrost mount in a DCV
    session fails straight away on node `ccn01`; use other nodes (for example
    `sphr`). This is not enforced in the repository code.

## Repository hygiene

15. **Do not commit** `.venv/`, `dist/`, `build/`, generated `src/version.py` or
    the local `pyproject.toml` of the apps. See `.gitignore`.

## Documentation hygiene

16. `docs/wiki/` is referenced by old documentation but **does not exist**.
    Do not create new references to it.
17. Documentation is updated with the `docs-update` skill; the agent entry
    point is `AGENTS.md`.
