#!/usr/bin/env python3
"""Versión de BIFROST para el workflow de build y release (.github/workflows/main.yml).

Una sola versión para las dos apps, SemVer (MAYOR.MENOR.PARCHE), calculada a partir de los commits
convencionales desde la última release (el tag vX.Y.Z más alto):

  · `feat!:` / `fix(x)!:` o un `BREAKING CHANGE:` en el cuerpo  → sube MAYOR
  · algún `feat`                                                 → sube MENOR
  · solo `fix`, `perf`, `revert` o `build`                       → sube PARCHE
  · solo `docs`, `style`, `refactor`, `test`, `ci`, `chore`      → no hay release
  · una línea `Release-As: X.Y.Z` en el cuerpo de un commit fija la versión (tiene que ser mayor que la
    última release: si no, el autoupdate no la vería como nueva)

Solo `main` publica. En cualquier otra rama, o en `main` sin commits que saquen versión, la versión es
la de la última release + el número de ejecución (X.Y.Z.N): el autoupdate la ve más nueva que su release
y más antigua que la siguiente.

Uso en el workflow:
  next_version.py version --ref "$GITHUB_REF" --run-number N   # escribe version/base/is_release en $GITHUB_OUTPUT
  next_version.py notes                                         # notas de la release (Markdown) por stdout
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
HEADER_RE = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?:\s*(?P<desc>.+)$")
BREAKING_RE = re.compile(r"^BREAKING[ -]CHANGE:", re.MULTILINE)
RELEASE_AS_RE = re.compile(r"^Release-As:\s*v?(\d+)\.(\d+)\.(\d+)\s*$", re.MULTILINE | re.IGNORECASE)

MINOR_TYPES = {"feat"}
PATCH_TYPES = {"fix", "perf", "revert", "build"}

Version = tuple[int, int, int]


def fmt(v: Version) -> str:
    return ".".join(str(n) for n in v)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def latest_release(tags: list[str]) -> Version | None:
    """La versión del tag vX.Y.Z más alto (los que no tienen esa forma se ignoran)."""
    versions = [tuple(int(n) for n in m.groups()) for t in tags if (m := TAG_RE.match(t.strip()))]
    return max(versions) if versions else None


def commit_messages(since_tag: str | None) -> list[str]:
    """Mensajes completos de los commits desde `since_tag` hasta HEAD, del más nuevo al más antiguo. Sin los
    "Merge pull request": cuentan los commits que traen dentro."""
    rango = f"{since_tag}..HEAD" if since_tag else "HEAD"
    out = git("log", rango, "--no-merges", "--format=%B%x1e")
    return [m.strip() for m in out.split("\x1e") if m.strip()]


def parse_header(message: str) -> tuple[str, str, bool] | None:
    """(tipo, descripción, incompatible) de la primera línea, o None si no es un commit convencional."""
    m = HEADER_RE.match(message.splitlines()[0].strip())
    if not m:
        return None
    breaking = bool(m.group("bang")) or bool(BREAKING_RE.search(message))
    return m.group("type"), m.group("desc").strip(), breaking


def bump_level(messages: list[str]) -> str | None:
    """'major', 'minor', 'patch' o None (nada que saque versión). Manda el más fuerte."""
    level = None
    for msg in messages:
        parsed = parse_header(msg)
        if parsed is None:
            continue
        type_, _, breaking = parsed
        if breaking:
            return "major"
        if type_ in MINOR_TYPES:
            level = "minor"
        elif type_ in PATCH_TYPES and level is None:
            level = "patch"
    return level


def next_version(last: Version | None, messages: list[str]) -> Version | None:
    """La versión de la próxima release, o None si estos commits no sacan versión.

    Raises:
        ValueError: si un `Release-As` no es mayor que la última release.
    """
    for msg in messages:                      # del más nuevo al más antiguo: manda el último Release-As
        if m := RELEASE_AS_RE.search(msg):
            forced = tuple(int(n) for n in m.groups())
            if last is not None and forced <= last:
                raise ValueError(f"Release-As: {fmt(forced)} no es mayor que la última release ({fmt(last)}): "
                                 "el autoupdate no la vería como una versión nueva")
            return forced
    level = bump_level(messages)
    if level is None:
        return None
    major, minor, patch = last or (0, 0, 0)
    if level == "major":
        return (major + 1, 0, 0)
    if level == "minor":
        return (major, minor + 1, 0)
    return (major, minor, patch + 1)


def compute(ref: str, run_number: str, last: Version | None, messages: list[str]) -> dict[str, str]:
    """Salidas del job `version`: version (la de version.py y el instalador), base (X.Y.Z del bundle) e
    is_release."""
    base_last = fmt(last) if last else "0.0.0"
    if ref == "refs/heads/main":
        nueva = next_version(last, messages)
        if nueva is not None:
            v = fmt(nueva)
            return {"version": v, "base": v, "is_release": "true"}
    return {"version": f"{base_last}.{run_number}", "base": base_last, "is_release": "false"}


SECTIONS = [
    ("breaking", "⚠️ Cambios incompatibles"),
    ("feat", "Nuevas funciones"),
    ("fix", "Arreglos"),
    ("other", "Otros cambios en la app (rendimiento, dependencias, reversiones)"),
]


def release_notes(messages: list[str]) -> str:
    """Notas de la release en Markdown: los commits que sacan versión, agrupados por tipo."""
    groups: dict[str, list[str]] = {key: [] for key, _ in SECTIONS}
    for msg in reversed(messages):            # del más antiguo al más nuevo
        parsed = parse_header(msg)
        if parsed is None:
            continue
        type_, desc, breaking = parsed
        if breaking:
            groups["breaking"].append(desc)
        if type_ in MINOR_TYPES:
            groups["feat"].append(desc)
        elif type_ == "fix":
            groups["fix"].append(desc)
        elif type_ in PATCH_TYPES:
            groups["other"].append(f"{type_}: {desc}")
    parts = [f"### {title}\n\n" + "\n".join(f"- {line}" for line in groups[key])
             for key, title in SECTIONS if groups[key]]
    return "\n\n".join(parts) + "\n" if parts else "Sin cambios destacados.\n"


def _last_and_messages() -> tuple[Version | None, list[str]]:
    last = latest_release(git("tag", "--list", "v*").split())
    return last, commit_messages(f"v{fmt(last)}" if last else None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_version = sub.add_parser("version", help="calcula la versión de este build")
    p_version.add_argument("--ref", required=True, help="github.ref (refs/heads/<rama>)")
    p_version.add_argument("--run-number", required=True, help="github.run_number")
    sub.add_parser("notes", help="notas de la release (Markdown) por stdout")
    args = parser.parse_args(argv)

    last, messages = _last_and_messages()
    if args.cmd == "notes":
        sys.stdout.write(release_notes(messages))
        return 0

    try:
        out = compute(args.ref, args.run_number, last, messages)
    except ValueError as ex:
        print(f"::error::{ex}")
        return 1
    print(f"Última release: {fmt(last) if last else 'ninguna'} · versión de este build: {out['version']} "
          f"(release: {out['is_release']})")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            for key, value in out.items():
                f.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
