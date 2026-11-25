"""Dónde busca BIFROST el ejecutable rclone (common/rclone.py)."""

import sys
import types

from bifrost_backend.common import rclone


def _fake_app(tmp_path, monkeypatch, with_rclone=True):
    """Una app falsa: `src/config.py` registrado como módulo `config` y, si se pide, `src/assets/bin/rclone`."""
    src = tmp_path / "bifrost-test" / "src"
    (src / "assets" / "bin").mkdir(parents=True)
    (src / "config.py").write_text("APP_INFO = {}\n")
    config = types.ModuleType("config")
    config.__file__ = str(src / "config.py")
    monkeypatch.setitem(sys.modules, "config", config)
    exe = src / "assets" / "bin" / ("rclone.exe" if sys.platform == "win32" else "rclone")
    if with_rclone:
        exe.write_text("")
    return src, exe


def test_app_assets_dir_sin_config_con_fichero(monkeypatch):
    monkeypatch.setitem(sys.modules, "config", types.ModuleType("config"))   # como el de conftest: sin __file__
    assert rclone.app_assets_dir() is None


def test_app_assets_dir_es_la_carpeta_de_config(tmp_path, monkeypatch):
    src, _ = _fake_app(tmp_path, monkeypatch)
    assert rclone.app_assets_dir() == (src / "assets").resolve()


def test_rclone_de_la_app_sin_flet_assets_dir(tmp_path, monkeypatch):
    # python src/main.py (sin flet run): no hay FLET_ASSETS_DIR y bifrost-shared puede estar en site-packages
    _, exe = _fake_app(tmp_path, monkeypatch)
    monkeypatch.delenv("FLET_ASSETS_DIR", raising=False)
    monkeypatch.setattr(rclone.shutil, "which", lambda name: None)
    assert rclone.get_rclone_executable() == str(exe.resolve())


def test_flet_assets_dir_tiene_prioridad(tmp_path, monkeypatch):
    _fake_app(tmp_path, monkeypatch)
    bundle = tmp_path / "bundle"
    (bundle / "bin").mkdir(parents=True)
    bundled = bundle / "bin" / ("rclone.exe" if sys.platform == "win32" else "rclone")
    bundled.write_text("")
    monkeypatch.setenv("FLET_ASSETS_DIR", str(bundle))
    assert rclone.get_rclone_executable() == str(bundled)


def test_sin_rclone_en_ningun_sitio(tmp_path, monkeypatch):
    _fake_app(tmp_path, monkeypatch, with_rclone=False)
    monkeypatch.delenv("FLET_ASSETS_DIR", raising=False)
    monkeypatch.setattr(rclone.shutil, "which", lambda name: None)
    try:
        rclone.get_rclone_executable()
    except EnvironmentError as ex:
        assert "rclone not found" in str(ex)
    else:
        raise AssertionError("debía fallar")
