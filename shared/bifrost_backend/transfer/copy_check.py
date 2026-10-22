"""Ejecución de rclone copy y rclone check.

La salida de rclone se interpreta con common/rclone_output.RunSummary: el panel recibe solo líneas para el
usuario (progreso, resumen, qué hacer) y la salida cruda va al log técnico.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from sys import platform as sys_platform

from ..common.rclone import _get_user_agent, _subprocess_kwargs, get_rclone_executable
from ..common.rclone_output import RunSummary
from .s3_tags import construir_tag_string

log = logging.getLogger("bifrost.copy")

_EXCLUDES = [
    "--exclude", "**/.DS_Store",
    "--exclude", "**/*.Thumbs.db",
    "--exclude", ".snapshot/**",
    "--exclude", "**/.snapshot/**",
    "--exclude", ".snapshot/",
    "--exclude", "**/.Trash*/**",
    "--exclude", "**/.cache/**",
]
# Salida JSON que interpreta RunSummary. Solo cambia el formato de la salida, no qué se copia ni cómo.
_OUTPUT_FLAGS = ["--use-json-log", "--log-level", "INFO", "--stats", "1s", "--stats-log-level", "NOTICE"]

# Opciones del campo "Additional rclone flags (advanced)" que no se aceptan: cambian o desvían la salida (la
# app dejaría de entenderla), escriben informes propios, piden respuestas por teclado o pueden volcar secretos
# al log. Las opciones cortas agrupadas (-vP) también se rechazan: no se pueden revisar una a una.
_FORBIDDEN_FLAG = re.compile(
    r"^(-[A-Za-z]{2,}|-v|-q|-P|-i|--verbose|--quiet|--progress|--interactive|--log-.*|--use-json-log|"
    r"--syslog.*|--stats.*|--dump.*|--config|--combined|--missing-on-.*|--differ|--match|--error|"
    r"--header.*|--.*(secret|token|pass|key).*)$",
)


def flags_no_permitidos(flags: list[str]) -> list[str]:
    """Opciones de `flags` que no se pueden usar en la copia o el check (ver _FORBIDDEN_FLAG)."""
    return [f for f in flags if _FORBIDDEN_FLAG.match(f.split("=", 1)[0])]


def _es_prueba(flags: list[str]) -> bool:
    return any(f in ("-n", "--dry-run") for f in flags)


def _comando_para_log(comando: list[str], tag_keys: list[str]) -> str:
    """Comando completo para el log técnico, sin los valores de las etiquetas (son metadatos personales)."""
    shown = [f"x-amz-tagging:<{', '.join(tag_keys) or 'no tags'}>" if a.startswith("x-amz-tagging:") else a
             for a in comando]
    return " ".join(shlex.quote(a) for a in shown)


def _ejecutar(operacion: str, comando: list[str], summary: RunSummary, log_fn, expose_proceso) -> int:
    """Lanza rclone, pasa su salida por `summary` y devuelve el código de salida."""
    # Prioridad baja para que el proceso de la app (Hypercorn en web) siempre pueda ejecutarse aunque rclone
    # sature los núcleos. nice(10): Linux/macOS; en Windows no hay preexec_fn.
    _preexec = (lambda: os.nice(10)) if sys_platform != "win32" else None
    proceso = subprocess.Popen(
        comando,
        stdin=subprocess.DEVNULL,            # rclone nunca debe quedarse esperando una respuesta
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        preexec_fn=_preexec,
        **_subprocess_kwargs(),
    )
    if expose_proceso is not None:
        expose_proceso["proc"] = proceso
        expose_proceso["summary"] = summary        # la pantalla lee de aquí el progreso (progress_snapshot)
    try:
        for linea in proceso.stdout:
            for out in summary.feed(linea, time.monotonic()):
                log_fn(out)
        proceso.wait()
        return proceso.returncode
    finally:
        # No dejar rclone en marcha si la lectura de la salida ha fallado.
        if proceso.poll() is None:
            proceso.terminate()
        if expose_proceso is not None and expose_proceso.get("proc") is proceso:
            expose_proceso["proc"] = None


_TEMP_PREFIXES = ("bifrost-copy-", "bifrost-check-")
_TEMP_MAX_AGE = 7 * 86400    # s
# rclone aborta la operación entera si no puede crear una lista (comprobado con el disco lleno). Las listas
# ocupan ~60 MB por millón de ficheros; con menos de esto libre se trabaja sin ellas.
_TEMP_MIN_FREE = 100 * 1024 * 1024


def _borrar_temporales_antiguos() -> None:
    """Borra carpetas temporales de operaciones que se cortaron de golpe (la app murió antes de borrarlas).

    Solo las del usuario y sin cambios en 7 días: en un nodo compartido el mismo usuario puede tener otra
    sesión con una operación en marcha, y su lista se sigue escribiendo.
    """
    limite = time.time() - _TEMP_MAX_AGE
    for carpeta in Path(tempfile.gettempdir()).glob("bifrost-*"):
        try:
            if not (carpeta.name.startswith(_TEMP_PREFIXES) and carpeta.is_dir()):
                continue
            st = carpeta.stat()
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                continue
            if max([st.st_mtime] + [f.stat().st_mtime for f in carpeta.iterdir()]) < limite:
                shutil.rmtree(carpeta, ignore_errors=True)
                log.info("removed leftover temporary folder %s", carpeta.name)
        except OSError:
            continue


def _ficheros_de_informe(operacion: str, nombres: tuple[str, ...]) -> tuple[Path | None, dict[str, Path] | None]:
    """Carpeta temporal para las listas por fichero que escribe rclone (se borra al terminar).

    rclone anota ahí la decisión que ya toma con cada fichero: no añade lecturas ni peticiones a MinIO. Sin
    listas, copy no dice cuántos ficheros ya estaban y check usa los totales de rclone.
    """
    _borrar_temporales_antiguos()
    try:
        libre = shutil.disk_usage(tempfile.gettempdir()).free
        if libre < _TEMP_MIN_FREE:
            log.warning("%s: only %d MB free in the temporary folder; running without per-file lists",
                        operacion, libre // 2**20)
            return None, None
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"bifrost-{operacion}-"))
    except OSError as e:
        log.warning("%s: cannot create the per-file lists (%s); running without them", operacion, e)
        return None, None
    return tmp_dir, {k: tmp_dir / f"{k}.txt" for k in nombres}


def ejecutar_rclone_copy(
    origen: str,
    destino_perfil: str,
    destino_path: str,
    rclone_config_path: str,
    metadatos_dict: dict,
    flags_adicionales: list[str],
    log_fn,
    on_finish=None,
    expose_proceso: dict | None = None,
    is_web: bool = False,
) -> None:
    """Lanza rclone copy y llama a `on_finish(summary)` al terminar, siempre.

    Si *expose_proceso* es un dict, guarda el Popen en expose_proceso['proc']; la vista pone
    expose_proceso['cancelled'] = True antes de terminarlo al pulsar Cancel.

    Los ficheros que ya estaban idénticos en MinIO (y que por tanto no reciben las etiquetas) salen del informe
    --match de rclone.
    """
    summary = RunSummary("copy", is_web=is_web, dry_run=_es_prueba(flags_adicionales))
    rc = None
    tmp_dir, reports = None, None
    try:
        tmp_dir, reports = _ficheros_de_informe("copy", ("match",))
        tag_string = construir_tag_string(metadatos_dict)
        comando = [
            get_rclone_executable(), "copy",
            origen,
            f"{destino_perfil}:/{destino_path}",
            "--config", rclone_config_path,
            "--checksum",
            "--check-first",
            "--copy-links",
            *_EXCLUDES,
            *_OUTPUT_FLAGS,
            "--header-upload", f"x-amz-tagging:{tag_string}",
            "--user-agent", _get_user_agent(),
            *(["--match", str(reports["match"])] if reports else []),
            *flags_adicionales,
        ]
        log.info("copy command: %s", _comando_para_log(comando, [k for k, v in metadatos_dict.items() if v]))
        rc = _ejecutar("copy", comando, summary, log_fn, expose_proceso)
    except Exception as e:
        log.exception("copy could not run")
        summary.add_internal_error(str(e))
    finally:
        _terminar("copy", summary, rc, log_fn, on_finish, expose_proceso, reports, tmp_dir)


def ejecutar_rclone_check(
    origen: str,
    destino_perfil: str,
    destino_path: str,
    rclone_config_path: str,
    flags_adicionales: list[str],
    mounts_activos: list,
    log_fn,
    on_finish=None,
    expose_proceso: dict | None = None,
    is_web: bool = False,
) -> None:
    """Lanza rclone check y llama a `on_finish(summary)` al terminar, siempre.

    Las listas de ficheros con problemas salen de los informes de rclone --missing-on-dst, --differ y
    --error (solo rutas con problemas; los idénticos no se guardan).
    """
    summary = RunSummary("check", is_web=is_web)
    rc = None
    tmp_dir, reports = None, None
    try:
        origen_ajustado, fichero = preparar_origen_para_check(origen, mounts_activos, rclone_config_path)
        tmp_dir, reports = _ficheros_de_informe("check", ("missing", "differ", "error"))
        comando = [
            get_rclone_executable(), "check",
            origen_ajustado,
            f"{destino_perfil}:/{destino_path}",
            "--config", rclone_config_path,
            "--one-way",
            "--copy-links",
            *([] if fichero else _EXCLUDES),
            *_OUTPUT_FLAGS,
        ]
        if reports:
            comando += ["--missing-on-dst", str(reports["missing"]), "--differ", str(reports["differ"]),
                        "--error", str(reports["error"])]
        comando += flags_adicionales
        log.info("check command: %s", " ".join(shlex.quote(a) for a in comando))
        rc = _ejecutar("check", comando, summary, log_fn, expose_proceso)
    except Exception as e:
        log.exception("check could not run")
        summary.add_internal_error(str(e))
    finally:
        _terminar("check", summary, rc, log_fn, on_finish, expose_proceso, reports, tmp_dir)


def _terminar(operacion, summary: RunSummary, rc, log_fn, on_finish, expose_proceso, reports, tmp_dir) -> None:
    """Fija el resultado, escribe el resumen en el panel, llama a on_finish(summary) y borra *tmp_dir*."""
    cancelled = bool(expose_proceso and expose_proceso.get("cancelled"))
    try:
        summary.finish(rc, cancelled, reports)
        for line in summary.final_lines():
            log_fn(line)
        log.info("%s finished: %s", operacion, summary.log_line())
    except Exception:
        log.exception("%s: could not build the summary", operacion)
        summary.outcome = "failed"
        log_fn(f"\n❌ The {operacion} ended, but BIFROST could not read its result. Do not delete the "
               "original. If it keeps happening, contact ITS and send them the report saved at the end of this log.\n")
    finally:
        try:
            if on_finish:
                on_finish(summary)
        finally:
            if tmp_dir is not None:
                shutil.rmtree(tmp_dir, ignore_errors=True)


def es_directorio_rclone(ruta_rclone: str, config_path: str) -> bool:
    """Devuelve True si la ruta rclone apunta a un directorio."""
    rclone = get_rclone_executable()
    try:
        resultado = subprocess.run(
            [rclone, "lsjson", ruta_rclone, "--config", config_path],
            capture_output=True,
            check=True,
            encoding="utf-8",
            errors="replace",
            **_subprocess_kwargs(),
        )
        if not resultado.stdout:
            return False
        salida = json.loads(resultado.stdout)
        if not salida:
            return False
        if len(salida) > 1:
            return True
        return salida[0].get("IsDir", False)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return False


def traducir_a_ruta_local_montada(
    origen: str,
    mounts_activos: list,
) -> str:
    """Si 'origen' es un remote rclone con mount activo, devuelve la ruta local equivalente."""
    if ":" in origen and not origen.startswith("/"):
        try:
            remote, ruta_relativa = origen.split(":", 1)
        except ValueError:
            return origen
        ruta_relativa = ruta_relativa.lstrip("/")
        for mount in mounts_activos:
            if all(k in mount for k in ("remote_name", "mount_path", "remote_subpath")):
                if (
                    mount["remote_name"] == remote
                    and ruta_relativa.startswith(mount["remote_subpath"])
                ):
                    subruta = ruta_relativa[len(mount["remote_subpath"]):].lstrip("/")
                    return str(Path(mount["mount_path"]) / subruta)
    return origen


def preparar_origen_para_check(
    origen: str,
    mounts_activos: list,
    rclone_config_path: str,
) -> tuple[str, str | None]:
    """Analiza el origen y lo normaliza para rclone check."""
    if ":" in origen and not origen.startswith("/"):
        remote, ruta_local = origen.split(":", 1)
        ruta_local = ruta_local.lstrip("/")
        if es_directorio_rclone(origen, rclone_config_path):
            carpeta = traducir_a_ruta_local_montada(origen, mounts_activos)
            return carpeta, None
        else:
            ruta_local_path = Path(ruta_local)
            fichero = ruta_local_path.name
            carpeta_remota = f"{remote}:{str(ruta_local_path.parent)}"
            carpeta = traducir_a_ruta_local_montada(
                carpeta_remota, mounts_activos
            )
            return carpeta + f"/{fichero}", fichero
    else:
        if os.path.isfile(origen):
            ruta_local_path = Path(origen)
            fichero = ruta_local_path.name
            return str(ruta_local_path.parent) + f"/{fichero}", fichero
        return origen, None
