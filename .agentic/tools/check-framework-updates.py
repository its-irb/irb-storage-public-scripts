#!/usr/bin/env python3
"""Check whether a target repository is in sync with the Agentic Framework.

Read-only tool: it never modifies any file in the repository. It reads the
traceability recorded in ``.agentic.lock.json`` by the last successful
``agentic-sync.py --apply`` and compares the installed commit with the current
remote HEAD of the recorded framework branch, using only ``git ls-remote`` for
the remote query (no ``urllib``/``requests``/``curl``/``certifi`` — Git is
already a framework dependency).

The repository that contains ``.agentic-framework.json`` is the framework
source itself: the check is skipped (no warning) so the source repo never
warns about itself.

Exit codes are stable and documented; stdout carries a single JSON object so
harness integrations can interpret the result deterministically. Use
``--human`` for a readable summary when debugging manually.

When the lock contains a non-empty ``source`` string (the local framework
clone path used by the last apply), it is surfaced as ``framework_source``
in the JSON output as an informational hint. It is not a canonical or
trusted origin.

Candidate model: the remote probe is attempted against the candidates
``[framework_access_url, framework_remote_url]`` (deduplicated, access first).
``framework_access_url`` is OPTIONAL — old locks and all locks from HTTPS
origins lack it, in which case the single candidate is the canonical URL and
the behavior is exactly the pre-change one. The access URL is a local access
hint (the verified SSH origin of the last apply, alias included): it can be
stale or meaningless on other machines, so it is only ever TRIED, never
trusted. A candidate is authoritative ONLY when it returns the ref of the
requested branch with a valid SHA — a bare rc=0 is not enough (rc!=0 ->
"inaccessible"; rc=0 without the branch -> "branch_missing"; rc=0 with an
invalid SHA -> "malformed"; each is recorded and the next candidate is tried).
The final diagnosis is emitted only after all candidates are exhausted, with
documented precedence malformed (7) > branch_missing (6) > inaccessible (7),
and the optional ``attempted`` key (present in states 0-1 only when an earlier
candidate failed, and in states 6-7) records each non-authoritative candidate
as ``{"url": ..., "failure": ...}``.

States / exit codes:

  0  UP_TO_DATE            — installed commit == remote HEAD of the branch
  1  UPDATE_AVAILABLE      — remote HEAD differs from the installed commit
  2  SOURCE_REPO_SKIPPED   — .agentic-framework.json present (framework source)
  3  LOCK_MISSING          — .agentic.lock.json does not exist
  4  LOCK_INCOMPLETE       — lock lacks a required field (url/branch/commit)
  5  LOCK_INVALID          — lock is invalid JSON / not an object / bad commit
                             / invalid optional framework_access_url
  6  REMOTE_BRANCH_MISSING — no candidate returned the branch ref
  7  GIT_OR_NETWORK_ERROR  — no candidate accessible (network/auth/exec/timeout)
                             or a candidate returned a malformed SHA
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LOCK_FILE = ".agentic.lock.json"
MANIFEST_FILE = ".agentic-framework.json"
REQUIRED_FIELDS = ("framework_remote_url", "framework_branch", "framework_commit")
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Short timeout: a network failure must not delay the OpenCode session.
_LSREMOTE_TIMEOUT_SECONDS = 10


def find_repo_root(start: Path) -> Path:
    """Walk up from ``start`` until a ``.git`` entry is found.

    Returns the first ancestor containing ``.git``. If none is found, returns
    ``start`` resolved, so the lockfile/manifest lookup still has a best-effort
    root to probe (``git ls-remote`` works without a local git repo anyway).
    """
    start = start.resolve()
    current = start
    while True:
        if (current / ".git").exists():
            return current
        if current.parent == current:
            return start
        current = current.parent


def is_source_repo(root: Path) -> bool:
    """True when ``root`` contains the framework manifest (the source repo)."""
    return (root / MANIFEST_FILE).exists()


def load_lock(root: Path) -> dict | None:
    """Load and validate ``.agentic.lock.json`` at ``root``.

    Returns ``None`` when the file does not exist (so the caller can
    distinguish a missing lock from an empty-but-present one). Raises
    ``ValueError`` if the file exists but is not valid JSON or its root is not
    a JSON object. An existing file whose content is ``{}`` is returned as an
    empty dict — it is a present-but-incomplete lock, not a missing one.
    """
    lock_path = root / LOCK_FILE
    if not lock_path.exists():
        return None
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{lock_path} is not valid JSON ({exc.msg} at line {exc.lineno} "
            f"column {exc.colno})."
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"{lock_path} root is not a JSON object (got {type(data).__name__})."
        )
    return data


def run_lsremote(url: str, branch: str) -> tuple[int, str, str]:
    """Run ``git ls-remote <url> refs/heads/<branch>`` in a controlled env.

    Returns ``(returncode, stdout, stderr)``. The environment forces
    ``LC_ALL=C`` (stable English messages) and ``GIT_TERMINAL_PROMPT=0`` (never
    block on interactive credentials). A short timeout bounds network failures
    so a hung connection cannot delay the session.

    Failures to start or execute the git process — most notably
    ``FileNotFoundError`` when git is not installed or not on ``PATH``, but
    also any other ``OSError`` — are converted to a non-zero return code with
    a clear ``reason`` message in stderr. They never propagate as exceptions
    to the caller, so the tool produces a deterministic ``GIT_OR_NETWORK_ERROR``
    result instead of a traceback.
    """
    env = {**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"}
    refspec = f"refs/heads/{branch}"
    try:
        result = subprocess.run(
            ["git", "ls-remote", url, refspec],
            capture_output=True,
            text=True,
            env=env,
            timeout=_LSREMOTE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return 128, "", f"git ls-remote timed out after {_LSREMOTE_TIMEOUT_SECONDS}s"
    except FileNotFoundError:
        return 128, "", "git executable not found in PATH; cannot run git ls-remote"
    except OSError as exc:
        return 128, "", f"could not execute git ls-remote ({type(exc).__name__}: {exc})"
    return result.returncode, result.stdout, result.stderr


def _result(status: str, code: int, message: str, **extra) -> dict:
    """Build a stable result object. Extra fields are included only if set."""
    out = {"status": status, "code": code, "message": message}
    for key, value in extra.items():
        if value is not None:
            out[key] = value
    return out


def check(root: Path) -> dict:
    """Run the full check against ``root`` and return a result dict.

    Pure orchestration: delegates to ``load_lock`` and ``run_lsremote`` so the
    remote step can be monkeypatched in tests. Never writes anything.
    """
    if is_source_repo(root):
        return _result(
            "SOURCE_REPO_SKIPPED", 2,
            "Framework source repository detected via .agentic-framework.json; "
            "check skipped.",
        )

    try:
        lock = load_lock(root)
    except ValueError as exc:
        return _result("LOCK_INVALID", 5, str(exc))

    # A missing lockfile is distinct from a present-but-incomplete one.
    if lock is None:
        return _result(
            "LOCK_MISSING", 3,
            f"{LOCK_FILE} does not exist. The framework installation is "
            f"incomplete; update the local framework clone and run "
            f"agentic-sync.py --apply.",
        )

    # The lockfile exists. Surface the local source path as an informational
    # aid (the framework clone used by the last apply), if it is a non-empty
    # string (ignoring whitespace-only values). It is NOT a canonical or
    # trusted origin — just a hint to help the user locate the clone to
    # update. The original value is preserved verbatim so legitimate paths
    # containing spaces (e.g. "/home/david/my projects/fw") are not altered.
    source = lock.get("source")
    framework_source = (
        source if isinstance(source, str) and source.strip() else None
    )

    # An existing lock without the required traceability fields is incomplete
    # (this includes an empty {} lock). This is NOT the same as missing.
    missing = [f for f in REQUIRED_FIELDS if f not in lock]
    if missing:
        return _result(
            "LOCK_INCOMPLETE", 4,
            f"{LOCK_FILE} exists but lacks required field(s): "
            f"{', '.join(missing)}. Update the local framework clone and run "
            f"agentic-sync.py --apply to record the framework origin.",
            missing_fields=missing,
            framework_source=framework_source,
        )

    url = lock["framework_remote_url"]
    branch = lock["framework_branch"]
    installed = lock["framework_commit"]

    # Validate types before any regex/remote call. A non-string, empty, or
    # whitespace-only value is a corrupt lock (LOCK_INVALID), not a network or
    # branch error.
    def _type_error(name: str, value) -> str | None:
        if not isinstance(value, str):
            return (
                f"{LOCK_FILE} {name} must be a string "
                f"(got {type(value).__name__})."
            )
        if not value.strip():
            return f"{LOCK_FILE} {name} is empty or whitespace-only."
        return None

    for name, value in (("framework_remote_url", url),
                        ("framework_branch", branch),
                        ("framework_commit", installed)):
        err = _type_error(name, value)
        if err is not None:
            return _result("LOCK_INVALID", 5, err, framework_source=framework_source)

    if not _FULL_SHA_RE.match(installed):
        return _result(
            "LOCK_INVALID", 5,
            f"{LOCK_FILE} framework_commit is not a full 40-char SHA "
            f"(got {installed!r}).",
            framework_source=framework_source,
        )

    # framework_access_url is OPTIONAL: old locks (pre-2-URL model) and all
    # locks from HTTPS origins lack it. When present it must be a non-empty
    # string like the other traceability fields (LOCK_INVALID, before any
    # remote call). In production it is always an SSH URL (or a local path in
    # tests); the tool treats it as an opaque ls-remote target, exactly like
    # the canonical URL.
    access: str | None = None
    if "framework_access_url" in lock:
        access_value = lock["framework_access_url"]
        err = _type_error("framework_access_url", access_value)
        if err is not None:
            return _result("LOCK_INVALID", 5, err, framework_source=framework_source)
        access = access_value

    # Candidates: the verified access URL first (a local hint — it can be
    # stale or point elsewhere on other machines), then the canonical
    # identity. Deduplicated; with a single candidate (no access key) the
    # classification, messages and fields are identical to the pre-change
    # behavior.
    candidates: list[str] = [access] if access is not None else []
    if url not in candidates:
        candidates.append(url)

    failures: list[dict] = []
    first_malformed: tuple[str, str, str] | None = None  # (url, sha, stdout)
    last_rc: int | None = None
    last_stderr = ""

    for candidate in candidates:
        rc, stdout, stderr = run_lsremote(candidate, branch)
        if rc != 0:
            failures.append({"url": candidate, "failure": "inaccessible"})
            last_rc = rc
            last_stderr = stderr
            continue
        stripped = stdout.strip()
        first_line = stripped.splitlines()[0] if stripped else ""
        if not first_line:
            failures.append({"url": candidate, "failure": "branch_missing"})
            continue
        sha = first_line.split("\t", 1)[0].strip()
        if not _FULL_SHA_RE.match(sha):
            failures.append({"url": candidate, "failure": "malformed"})
            if first_malformed is None:
                first_malformed = (candidate, sha, stripped)
            continue

        # Authoritative: the branch ref with a valid full SHA.
        if sha == installed:
            result = _result(
                "UP_TO_DATE", 0,
                "Repository is in sync with the framework branch.",
                installed_commit=installed, remote_commit=sha,
                branch=branch, url=candidate, framework_source=framework_source,
            )
        else:
            result = _result(
                "UPDATE_AVAILABLE", 1,
                "A framework update is available.",
                installed_commit=installed, remote_commit=sha,
                branch=branch, url=candidate, framework_source=framework_source,
            )
        if failures:
            result["attempted"] = failures
        return result

    # All candidates exhausted: the final diagnosis is emitted here, with the
    # documented precedence malformed (7) > branch_missing (6) >
    # inaccessible (7).
    if first_malformed is not None:
        _m_url, malformed_sha, malformed_stdout = first_malformed
        return _result(
            "GIT_OR_NETWORK_ERROR", 7,
            f"git ls-remote returned a malformed SHA: {malformed_sha!r}.",
            reason=malformed_stdout,
            url=url,
            attempted=failures,
            framework_source=framework_source,
        )
    if any(f["failure"] == "branch_missing" for f in failures):
        return _result(
            "REMOTE_BRANCH_MISSING", 6,
            f"Remote branch {branch!r} does not exist at {url}.",
            branch=branch, url=url,
            attempted=failures,
            framework_source=framework_source,
        )
    detail = last_stderr.strip()
    if len(detail) > 400:
        detail = detail[:400] + "..."
    return _result(
        "GIT_OR_NETWORK_ERROR", 7,
        f"git ls-remote failed (exit {last_rc}). The framework status could "
        f"not be checked.",
        reason=detail,
        url=url,
        attempted=failures,
        framework_source=framework_source,
    )


def _print_human(result: dict) -> None:
    """Print a readable summary for manual debugging."""
    print(f"[{result['code']}] {result['status']}")
    print(result["message"])
    for key in ("installed_commit", "remote_commit", "branch", "url",
                "framework_source", "reason"):
        if key in result:
            print(f"  {key}: {result[key]}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check if a repo is in sync with the Agentic Framework "
                    "(read-only). Prints JSON to stdout.",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Repository root to check. Defaults to walking up from the cwd.",
    )
    parser.add_argument(
        "--human",
        action="store_true",
        help="Print a human-readable summary instead of JSON (for debugging).",
    )
    args = parser.parse_args()

    root = find_repo_root(Path(args.root)) if args.root else find_repo_root(Path.cwd())
    result = check(root)

    if args.human:
        _print_human(result)
    else:
        print(json.dumps(result, indent=2))
    return result["code"]


if __name__ == "__main__":
    raise SystemExit(main())
