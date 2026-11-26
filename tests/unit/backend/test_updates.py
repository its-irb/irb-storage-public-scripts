"""Tests unitarios (sin red) de bifrost_backend.common.updates."""

from __future__ import annotations

import platform
import sys
import zipfile

import pytest

from bifrost_backend.common import updates


@pytest.mark.parametrize("raw, expected", [
    ("v1.10.2", (1, 10, 2)),
    ("1.10.2", (1, 10, 2)),
    ("2.0.0", (2, 0, 0)),
    ("", (0,)),
    ("latest", (0,)),
    ("v1.2.x", (0,)),
])
def test_parse_version(raw, expected):
    assert updates._parse_version(raw) == expected


def test_parse_version_compares_numerically_not_alphabetically():
    assert updates._parse_version("v1.10.0") > updates._parse_version("v1.9.0")


@pytest.mark.parametrize("plat, machine, expected", [
    ("linux", "x86_64", "-linux"),
    ("win32", "AMD64", "-windows.zip"),
    ("darwin", "arm64", "-macos.dmg"),
    ("darwin", "x86_64", "-macos-intel.dmg"),
    ("freebsd", "x86_64", ""),
])
def test_get_update_file_suffix(monkeypatch, plat, machine, expected):
    monkeypatch.setattr(sys, "platform", plat)
    monkeypatch.setattr(platform, "machine", lambda: machine)
    assert updates.get_update_file_suffix() == expected


@pytest.fixture
def clean_env(monkeypatch):
    for var in ("FLET_APP_STORAGE_TEMP", "SLURM_JOB_ID", "BIFROST_CLUSTER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "platform", "darwin")     # que no dependa del sistema donde se lanzan los tests
    monkeypatch.setattr(updates, "__version__", "1.0.338")   # una versión publicada, no la de desarrollo
    monkeypatch.setattr(sys, "argv", ["bifrost-mount.exe"])
    monkeypatch.delattr(sys, "frozen", raising=False)


def test_should_check_flag_update_forces_check(monkeypatch, clean_env):
    monkeypatch.setattr(sys, "argv", ["main.py", "--update"])
    assert updates.should_check_for_updates() is True


def test_should_not_check_when_not_packaged(clean_env):
    assert updates.should_check_for_updates() is False


def test_should_check_when_frozen(monkeypatch, clean_env):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert updates.should_check_for_updates() is True


@pytest.mark.parametrize("version", ["0.0.0.dev", "2.0.0.dev"])
def test_should_not_check_development_version(monkeypatch, clean_env, version):
    # La de version.py en el repositorio: ni con flet run ni en un build local pide actualizar
    monkeypatch.setattr(updates, "__version__", version)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert updates.should_check_for_updates() is False


def test_update_flag_checks_even_with_development_version(monkeypatch, clean_env):
    # flet run --update: para probar la pantalla de actualización
    monkeypatch.setattr(updates, "__version__", "0.0.0.dev")
    monkeypatch.setattr(sys, "argv", ["main.py", "--update"])
    assert updates.should_check_for_updates() is True


def test_manual_version_checks_normally(monkeypatch, clean_env):
    # El "chanchullo" de poner a mano una versión antigua para probar el autoupdate sigue funcionando
    monkeypatch.setattr(updates, "__version__", "1.0.0")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert updates.should_check_for_updates() is True


def test_should_not_check_on_slurm(monkeypatch, clean_env):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("SLURM_JOB_ID", "123")
    assert updates.should_check_for_updates() is False


@pytest.mark.parametrize("argv", [["bifrost-mount"], ["main.py", "--update"]])
def test_should_never_check_on_linux(monkeypatch, clean_env, argv):
    # El clúster (Open OnDemand, sesiones DCV) es Linux y no hay binarios de Linux en las releases
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    assert updates.should_check_for_updates() is False


def test_should_never_check_in_cluster_mode(monkeypatch, clean_env):
    monkeypatch.setenv("BIFROST_CLUSTER", "1")
    monkeypatch.setattr(sys, "argv", ["main.py", "--update"])
    assert updates.should_check_for_updates() is False


def test_should_not_check_cluster_binary(monkeypatch, clean_env):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["bifrost-mount_linux_cluster"])
    assert updates.should_check_for_updates() is False


def _make_zip(path, names):
    with zipfile.ZipFile(path, "w") as z:
        for name in names:
            z.writestr(name, "contenido")
    return path


def test_extract_windows_installer_returns_the_exe_inside_the_zip(tmp_path):
    zip_path = _make_zip(tmp_path / "update.zip", ["bifrost-test-main-windows.exe"])
    dest = tmp_path / "out"
    exe = updates.extract_windows_installer(str(zip_path), str(dest))
    assert exe.endswith("bifrost-test-main-windows.exe")
    assert (dest / "bifrost-test-main-windows.exe").read_text() == "contenido"


def test_extract_windows_installer_fails_without_exe(tmp_path):
    zip_path = _make_zip(tmp_path / "update.zip", ["leeme.txt"])
    with pytest.raises(RuntimeError):
        updates.extract_windows_installer(str(zip_path), str(tmp_path / "out"))


def test_extract_windows_installer_fails_with_several_exe(tmp_path):
    zip_path = _make_zip(tmp_path / "update.zip", ["a.exe", "b.exe"])
    with pytest.raises(RuntimeError):
        updates.extract_windows_installer(str(zip_path), str(tmp_path / "out"))


def test_windows_script_waits_for_installer_before_relaunch():
    """Regresión: sin `start /wait` cmd no espera al instalador (app gráfica) y relanza la app antes de que termine."""
    lines = updates.build_windows_update_script(r"C:\tmp\bifrost-test.exe", "test").splitlines()
    install = next(i for i, l in enumerate(lines) if r"C:\tmp\bifrost-test.exe" in l)
    relaunch = next(i for i, l in enumerate(lines) if "Bifrost-test" in l)
    assert lines[install].startswith("start /wait"), "el instalador debe lanzarse con `start /wait`"
    assert install < relaunch


def test_windows_script_leaves_app_directory_before_installing():
    """Regresión: el .bat hereda el directorio de trabajo de la app (flet\\app). Si no sale de ahí antes de
    instalar y relanzar, la app relanzada no puede borrar flet\\app al arrancar (PathAccessException, errno 32)."""
    lines = updates.build_windows_update_script(r"C:\tmp\bifrost-test.exe", "test").splitlines()
    cd = next((i for i, l in enumerate(lines) if l.lower().startswith("cd /d ")), None)
    install = next(i for i, l in enumerate(lines) if r"C:\tmp\bifrost-test.exe" in l)
    assert cd is not None, "el script debe cambiar de directorio (`cd /d ...`) antes de instalar"
    assert cd < install


def test_windows_script_relaunches_installed_app():
    script = updates.build_windows_update_script(r"C:\tmp\x.exe", "mount")
    assert script.rstrip().splitlines()[-1] == r'start "" "%ProgramFiles(x86)%\Bifrost-mount\bifrost-mount.exe"'


