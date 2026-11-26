"""Tests unitarios (sin lanzar rclone) de bifrost_backend.mount.s3_mount: el comando con el que se monta un
servidor."""

from __future__ import annotations

import sys

import pytest

from bifrost_backend.mount import s3_mount

PERFORMANCE_OPTIONS = [
    "--vfs-cache-mode", "full",
    "--vfs-read-chunk-size", "32M", "--vfs-read-chunk-size-limit", "32M",
    "--buffer-size", "32M",
    "--s3-no-head-object",
    "--dir-cache-time", "12h",
    "--vfs-cache-max-size", "10G",
]


@pytest.fixture
def command(monkeypatch):
    """`_mount_command` en el sistema que se pida y con los argumentos de arranque de la app que se pidan."""
    monkeypatch.setattr(s3_mount, "get_rclone_executable", lambda: "rclone")

    def build(system: str, argv: list[str] | None = None) -> list[str]:
        monkeypatch.setattr(s3_mount.platform, "system", lambda: system)
        monkeypatch.setattr(sys, "argv", ["main.py", *(argv or [])])
        return s3_mount._mount_command("minio", "X:" if system == "Windows" else "/home/u/rclone-mounts/minio")
    return build


@pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
def test_mounts_the_whole_server_read_only_with_the_performance_options(command, system):
    cmd = command(system)
    assert cmd[:4] == ["rclone", "mount", "minio:", "X:" if system == "Windows" else "/home/u/rclone-mounts/minio"]
    assert cmd[4:6] == ["--read-only", "--links"]
    assert cmd[6:6 + len(PERFORMANCE_OPTIONS)] == PERFORMANCE_OPTIONS


@pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
def test_volume_named_like_the_server(command, system):
    """Sin --volname, --s3-no-head-object haría que el volumen se llamase "minio{EVwtF}"."""
    cmd = command(system)
    assert cmd[cmd.index("--volname") + 1] == "minio"


def test_allow_non_empty_only_outside_windows(command):
    assert "--allow-non-empty" not in command("Windows")
    assert "--allow-non-empty" in command("Darwin")
    assert "--allow-non-empty" in command("Linux")


def test_cache_options_given_to_the_app_go_last(command):
    """rclone se queda con el último valor de una opción repetida: así mandan las que se pasan al arrancar."""
    cmd = command("Darwin", ["--vfs-cache-max-size", "2G", "--cache-dir", "/scratch/cache", "--other", "x"])
    assert cmd[-4:] == ["--vfs-cache-max-size", "2G", "--cache-dir", "/scratch/cache"]
    assert "--other" not in cmd
