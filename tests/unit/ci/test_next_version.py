"""Versión de cada build y notas de la release (.github/scripts/next_version.py)."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / ".github" / "scripts" / "next_version.py"
_spec = importlib.util.spec_from_file_location("next_version", _SCRIPT)
nv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nv)

MAIN = "refs/heads/main"


def test_latest_release_ignora_tags_que_no_son_xyz():
    assert nv.latest_release(["v1.0.9", "v1.0.338", "v1.0.10", "v2.0.0-rc1", "otro", "v1.2"]) == (1, 0, 338)
    assert nv.latest_release([]) is None


@pytest.mark.parametrize("messages, expected", [
    (["fix(mount): algo", "docs: algo"], "patch"),
    (["perf: más rápido"], "patch"),
    (["build(deps): sube flet"], "patch"),
    (["revert: quita X"], "patch"),
    (["fix: a", "feat(ui): b", "docs: c"], "minor"),
    (["feat(ui)!: cambia todo"], "major"),
    (["fix: a", "refactor: b\n\nBREAKING CHANGE: ya no existe X"], "major"),
    (["docs: a", "refactor: b", "ci: c", "style: d", "test: e", "chore: f"], None),
    (["Merge branch 'develop'", "texto libre"], None),
])
def test_bump_level(messages, expected):
    assert nv.bump_level(messages) == expected


@pytest.mark.parametrize("messages, expected", [
    (["fix: a"], (1, 0, 339)),
    (["feat: a", "fix: b"], (1, 1, 0)),
    (["feat!: a"], (2, 0, 0)),
    (["docs: a"], None),
])
def test_next_version(messages, expected):
    assert nv.next_version((1, 0, 338), messages) == expected


def test_release_as_fija_la_version():
    assert nv.next_version((1, 0, 338), ["fix: a", "chore(release): publica\n\nRelease-As: 2.0.0"]) == (2, 0, 0)
    # Vale aunque no haya feat ni fix
    assert nv.next_version((1, 0, 338), ["chore: a\n\nRelease-As: v1.5.0"]) == (1, 5, 0)


def test_release_as_manda_el_mas_reciente():
    # git log va del más nuevo al más antiguo
    assert nv.next_version((1, 0, 0), ["chore: b\n\nRelease-As: 3.0.0", "chore: a\n\nRelease-As: 2.0.0"]) == (3, 0, 0)


@pytest.mark.parametrize("forced", ["1.0.338", "1.0.5"])
def test_release_as_no_mayor_falla(forced):
    with pytest.raises(ValueError, match="no es mayor"):
        nv.next_version((1, 0, 338), [f"chore: a\n\nRelease-As: {forced}"])


def test_compute_main_con_release():
    assert nv.compute(MAIN, "412", (1, 0, 338), ["feat: a"]) == {
        "version": "1.1.0", "base": "1.1.0", "is_release": "true"}


def test_compute_main_sin_commits_que_saquen_version():
    assert nv.compute(MAIN, "412", (1, 0, 338), ["docs: a"]) == {
        "version": "1.0.338.412", "base": "1.0.338", "is_release": "false"}


@pytest.mark.parametrize("ref", ["refs/heads/develop", "refs/heads/feature/x", "refs/heads/release"])
def test_compute_otras_ramas_nunca_publican(ref):
    # Ni siquiera con feat o con un Release-As (que además no se valida fuera de main)
    assert nv.compute(ref, "412", (1, 0, 338), ["feat: a", "chore: b\n\nRelease-As: 1.0.0"]) == {
        "version": "1.0.338.412", "base": "1.0.338", "is_release": "false"}


def test_compute_sin_ninguna_release():
    assert nv.compute("refs/heads/develop", "7", None, ["feat: a"])["version"] == "0.0.0.7"
    assert nv.compute(MAIN, "7", None, ["feat: a"])["version"] == "0.1.0"


def test_release_notes_agrupa_por_tipo():
    notes = nv.release_notes([
        "docs: no sale",
        "perf(mount): lista más rápido",
        "fix(web): arregla el login",
        "feat(ui)!: rediseño",
        "feat(tags): perfil genomics",
    ])
    assert notes.index("Cambios incompatibles") < notes.index("Nuevas funciones") < notes.index("Arreglos")
    assert "- perfil genomics" in notes and "- arregla el login" in notes and "- perf: lista más rápido" in notes
    assert "no sale" not in notes
    # Un feat! sale en "Cambios incompatibles" y también en "Nuevas funciones"
    nuevas = notes.split("### Nuevas funciones")[1].split("###")[0]
    assert "- rediseño" in notes.split("### Nuevas funciones")[0] and "- rediseño" in nuevas
    # Del más antiguo al más nuevo dentro de cada grupo (git log da el más nuevo primero)
    assert nuevas.index("perfil genomics") < nuevas.index("rediseño")


def test_release_notes_sin_cambios():
    assert nv.release_notes(["chore: a\n\nRelease-As: 2.0.0"]) == "Sin cambios destacados.\n"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})


def test_con_un_repositorio_git_de_verdad(tmp_path, monkeypatch):
    """Lee los tags y los commits con git: solo cuenta lo de después de la última release, y una rama
    fusionada con merge commit aporta sus commits (no el "Merge …")."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "feat: antes de la release")
    _git(repo, "tag", "v1.0.338")
    _git(repo, "switch", "-q", "-c", "develop")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "fix(web): arregla algo")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "docs: documenta")
    _git(repo, "switch", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "develop", "-m", "Merge pull request #1 from its-irb/develop")
    monkeypatch.chdir(repo)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    last, messages = nv._last_and_messages()
    assert last == (1, 0, 338)
    assert [m.splitlines()[0] for m in messages] == ["docs: documenta", "fix(web): arregla algo"]
    assert nv.compute(MAIN, "9", last, messages)["version"] == "1.0.339"
