"""Tests unitarios (sin lanzar procesos) de bifrost_backend.mount.processes: reconocer los `rclone mount` en la
salida de `ps` (macOS/Linux) y de PowerShell (Windows), y encontrar el que sirve una carpeta."""

from __future__ import annotations

from bifrost_backend.mount import processes

# Salida real de `ps -A -ww -o pid=,ucomm=,args=` en macOS con un montaje de fuse-t (recortada), más una copia de
# Bifrost Transfer y un proceso que no es rclone.
PS_OUTPUT = """\
    1 launchd          /sbin/launchd
 8202 go-nfsv4         /Library/Frameworks/fuse_t.framework/Resources/go-nfsv4 --volname minio -r /Users/n/rclone-mounts/minio
 8201 rclone           /Users/n/bifrost-mount/src/assets/bin/rclone mount minio: /Users/n/rclone-mounts/minio --read-only --links --allow-non-empty
 8300 rclone           /Users/n/bifrost-mount/src/assets/bin/rclone copy /Users/n/rclone-mounts/minio/bkt minio:dst
 8400 rclone           /usr/local/bin/rclone mount minio:bkt2 /Users/n/rclone-mounts/minio/bkt2 --read-only
"""

# Salida con la forma de `Get-CimInstance Win32_Process … "$($_.ProcessId)`t$($_.CommandLine)"`. No está capturada
# en Windows (esa parte no se ha probado allí): reproduce un ejecutable entre comillas, barras de los dos tipos, una
# copia y un proceso sin línea de comandos (sin permisos para leerla).
POWERSHELL_OUTPUT = (
    '4321\t"C:\\Program Files (x86)\\Bifrost-mount\\rclone.exe" mount minio:bkt C:/rclone-mounts/minio/bkt '
    '--read-only --links\r\n'
    '4400\t"C:\\Program Files (x86)\\Bifrost-mount\\rclone.exe" copy C:/data minio:bkt\r\n'
    '4500\t\r\n'
    '4600\tC:\\tools\\rclone.exe mount minio: X: --read-only\r\n'
)


def test_ps_only_rclone_mount_processes():
    found = processes.parse_mount_processes(PS_OUTPUT, windows=False)
    assert [pid for pid, _ in found] == [8201, 8400]          # ni launchd, ni go-nfsv4, ni la copia


def test_ps_keeps_the_command_line_as_is():
    found = dict(processes.parse_mount_processes(PS_OUTPUT, windows=False))
    assert found[8201] == ("/Users/n/bifrost-mount/src/assets/bin/rclone mount minio: /Users/n/rclone-mounts/minio "
                           "--read-only --links --allow-non-empty")


def test_powershell_only_rclone_mount_processes():
    found = processes.parse_mount_processes(POWERSHELL_OUTPUT, windows=True)
    assert [pid for pid, _ in found] == [4321, 4600]          # ni la copia, ni el proceso sin línea de comandos


def test_powershell_command_line_is_normalized():
    """Como `normalized` en Windows: minúsculas y "\\", para compararla con la carpeta de montaje."""
    found = dict(processes.parse_mount_processes(POWERSHELL_OUTPUT, windows=True))
    assert "mount minio:bkt c:\\rclone-mounts\\minio\\bkt --read-only" in found[4321]
    assert found[4600] == "c:\\tools\\rclone.exe mount minio: x: --read-only"


def test_empty_output():
    assert processes.parse_mount_processes("", windows=False) == []
    assert processes.parse_mount_processes("", windows=True) == []


def test_pids_serving_matches_the_whole_folder(monkeypatch):
    """…/bkt no es …/bkt2, y la carpeta de una copia no cuenta (solo se miran `rclone mount`)."""
    monkeypatch.setattr(processes, "rclone_mount_processes",
                        lambda: processes.parse_mount_processes(PS_OUTPUT, windows=False))
    assert processes.pids_serving("/Users/n/rclone-mounts/minio") == [8201]
    assert processes.pids_serving("/Users/n/rclone-mounts/minio/bkt2") == [8400]
    assert processes.pids_serving("/Users/n/rclone-mounts/minio/bkt") == []
    assert processes.pids_serving("/Users/n/rclone-mounts/minio/") == [8201]     # la barra final no importa
