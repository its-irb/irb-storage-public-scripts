"""Cliente S3 (boto3) y gestión de etiquetas de objetos y carpetas de MinIO."""

from __future__ import annotations

import configparser
import logging
import threading
import time
import urllib.parse
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

from ..common.constants import DEFAULT_S3_REGION
from ..common.rclone import obtener_ruta_rclone_conf
from ..common.rclone_output import (
    MAX_REPORTED_NAMES, UserIssue, by_cause, duration_text, error_text, issue_for_exception,
)

log = logging.getLogger("bifrost.tags")

_PAGE_SIZE = 1000          # objetos por página al listar una carpeta; se etiquetan antes de pedir la siguiente
_WORKERS = 8               # objetos que se etiquetan a la vez
MAX_FAILED_KEPT = 10_000   # fallidos que se guardan para reintentar solo esos; con más, se repite la carpeta
# Errores que afectan a todos los ficheros: seguir solo alargaría la espera (cada objeto agota los reintentos
# de botocore). MINIO_PERMISSION solo si fallan los primeros _PERMISSION_STOP_AFTER sin ninguno correcto.
_STOP_ALWAYS = {"CREDENTIALS_EXPIRED", "PROFILE_MISSING", "NETWORK", "CLOCK_SKEW"}
_PERMISSION_STOP_AFTER = 20


def get_s3_client_from_profile(profile_name: str, endpoint: str):
    """Crea un cliente boto3 S3 con las credenciales STS del perfil rclone dado."""
    import boto3
    config_path = obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    section = config[profile_name]
    region_name = section.get("region") or DEFAULT_S3_REGION
    log.info("S3 client: profile=%s endpoint=%s region=%s", profile_name, endpoint, region_name)
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=section["access_key_id"],
        aws_secret_access_key=section["secret_access_key"],
        aws_session_token=section.get("session_token") or None,
        region_name=region_name,
    )


def read_object_tags(s3_client, bucket: str, key: str) -> tuple[dict[str, str], datetime | None]:
    """Etiquetas de un objeto (clave → valor) y cuándo se subió a MinIO su versión actual.

    La fecha es el LastModified del objeto: no cambia al tocar las etiquetas. Si no se puede leer (p. ej. sin
    permiso de lectura del objeto) es None; un error al leer las etiquetas sí se lanza.
    """
    resp = s3_client.get_object_tagging(Bucket=bucket, Key=key)
    tags = {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    try:
        uploaded = s3_client.head_object(Bucket=bucket, Key=key)["LastModified"]
    except Exception as ex:
        log.info("tags: upload date not available: %s", error_text(str(ex), key))
        uploaded = None
    return tags, uploaded


def apply_tags_to_object(s3_client, bucket: str, key: str, tagset: dict[str, str]) -> None:
    """Aplica tagset a un objeto. Sustituye todas sus etiquetas."""
    tag_list = [{"Key": k, "Value": v} for k, v in tagset.items()]
    s3_client.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": tag_list})


# ============================================================================
# APLICAR ETIQUETAS A MUCHOS OBJETOS
# ============================================================================

@dataclass
class TagRun:
    """Resultado de aplicar etiquetas a una carpeta (o a una lista de ficheros) y sus textos para el usuario."""

    ok: int = 0
    failed: dict[str, UserIssue] = field(default_factory=dict)   # los primeros MAX_FAILED_KEPT
    failed_count: int = 0
    causes: Counter[UserIssue] = field(default_factory=Counter)   # causa de cada fallo (todos)
    stopped: UserIssue | None = None                              # error general que paró la operación
    cancelled: bool = False                                       # la paró el usuario
    seconds: float = 0.0

    @property
    def outcome(self) -> str:
        if self.stopped:
            return "stopped"
        if self.cancelled:
            return "cancelled"
        if self.failed_count:
            return "partial"
        return "ok" if self.ok else "empty"

    @property
    def main_issue(self) -> UserIssue | None:
        """El error que explica el resultado: el que paró la operación o la causa de fallo más frecuente."""
        if self.stopped:
            return self.stopped
        return self.causes.most_common(1)[0][0] if self.causes else None

    @property
    def causes_text(self) -> str:
        """'20 × No permission in MinIO': recuento de los fallos por causa."""
        return by_cause(self.causes.elements())

    @property
    def can_retry_failed_only(self) -> bool:
        """True si se guardaron todos los fallidos y "Try again" puede reintentar solo esos."""
        return 0 < self.failed_count == len(self.failed)

    def _done(self) -> str:
        text = f"{self.ok} file(s) have the new tags"
        return text + (f"; {self.failed_count} could not be changed" if self.failed_count else "")

    def final_lines(self, is_web: bool) -> list[str]:
        """Resumen para el panel (y el informe), sin nombres de ficheros."""
        o = self.outcome
        if o == "empty":
            return ["No files found in this folder."]
        if o == "cancelled":
            return [f"⏹ Stopped. {self._done()}; the rest were not changed."]
        if o == "stopped":
            hint = self.stopped.hint_for(is_web, screen="tags")
            return [f"❌ Stopped — {self.stopped.title}. {self._done()}; the rest of the folder was not changed.",
                    f"   {self.stopped.message}"] + ([f"   What you can do: {hint}"] if hint else [])
        took = f" in {duration_text(self.seconds)}"
        if o == "ok":
            return [f"✅ Tags set on {self.ok} file(s){took}."]
        hints = dict.fromkeys(i.hint_for(is_web, screen="tags") for i in self.causes if i.hint)
        return ([f"⚠️ Tags set on {self.ok} file(s){took}. {self.failed_count} file(s) could not be changed: "
                 f"{self.causes_text}."]
                + [f"   What you can do: {h}" for h in list(hints)[:3]]
                + ["   The list of these files is in the report."])

    def problem_lines(self) -> list[str]:
        """Para el informe: los ficheros que no se pudieron cambiar y su causa (hasta MAX_REPORTED_NAMES)."""
        if not self.failed_count:
            return []
        shown = list(self.failed.items())[:MAX_REPORTED_NAMES]
        out = [f"Files whose tags could not be set ({self.failed_count}):"]
        out += [f"  {key} — {issue.title}" for key, issue in shown]
        if self.failed_count > len(shown):
            out.append(f"  … and {self.failed_count - len(shown)} more not listed (the report lists up to "
                       f"{MAX_REPORTED_NAMES} files)")
        return out

    def log_line(self) -> str:
        """Resultado en una línea para el log técnico (sin nombres de ficheros ni valores de etiquetas)."""
        stopped = self.stopped.code if self.stopped else "-"
        return (f"outcome={self.outcome} total={self.ok + self.failed_count} ok={self.ok} "
                f"failed={self.failed_count} stopped={stopped} duration={self.seconds:.0f}s")


def apply_tags_to_prefix(s3_client, bucket: str, prefix: str, tagset: dict[str, str], *,
                         stop: threading.Event | None = None,
                         on_progress: Callable[[int], None] | None = None) -> TagRun:
    """Aplica tagset a todos los objetos bajo prefix (sustituye todas sus etiquetas), por páginas de 1.000:
    empieza enseguida y usa la misma memoria con cualquier tamaño de carpeta."""
    return _apply_tags(s3_client, bucket, _pages_of_prefix(s3_client, bucket, prefix), tagset,
                       stop=stop, on_progress=on_progress)


def apply_tags_to_keys(s3_client, bucket: str, keys: list[str], tagset: dict[str, str], *,
                       stop: threading.Event | None = None,
                       on_progress: Callable[[int], None] | None = None) -> TagRun:
    """Como apply_tags_to_prefix, para una lista de objetos (reintentar los que fallaron)."""
    pages = (keys[i:i + _PAGE_SIZE] for i in range(0, len(keys), _PAGE_SIZE))
    return _apply_tags(s3_client, bucket, pages, tagset, stop=stop, on_progress=on_progress)


def _pages_of_prefix(s3_client, bucket: str, prefix: str) -> Iterator[list[str]]:
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix, PaginationConfig={"PageSize": _PAGE_SIZE}):
        if keys := [obj["Key"] for obj in page.get("Contents") or []]:
            yield keys


def _apply_tags(s3_client, bucket: str, key_pages: Iterable[list[str]], tagset: dict[str, str], *,
                stop: threading.Event | None, on_progress: Callable[[int], None] | None) -> TagRun:
    """Etiqueta los objetos página a página, _WORKERS a la vez.

    `stop` lo activa el usuario (Cancel) o esta función ante un error general: deja de enviar objetos y espera
    a los que están en curso. `on_progress(ficheros hechos)` se llama como mucho una vez por segundo.
    """
    run = TagRun()
    stop = stop or threading.Event()
    lock = threading.Lock()
    tag_list = [{"Key": k, "Value": v} for k, v in tagset.items()]
    logged_errors: set[str] = set()
    last_progress = [0.0]
    start = time.monotonic()

    def _tag_one(key: str) -> None:
        if stop.is_set():
            return
        try:
            s3_client.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": tag_list})
            with lock:
                run.ok += 1
        except Exception as ex:
            _record_failure(key, ex)
        _report_progress()

    def _record_failure(key: str, ex: Exception) -> None:
        issue = issue_for_exception(ex)
        with lock:
            run.failed_count += 1
            run.causes[issue] += 1
            if len(run.failed) < MAX_FAILED_KEPT:
                run.failed[key] = issue
            text = error_text(str(ex), key)          # al log técnico, una vez por tipo y sin nombres
            if text not in logged_errors:
                logged_errors.add(text)
                log.warning("tags: %s", text)
            general = issue.code in _STOP_ALWAYS or (
                issue.code == "MINIO_PERMISSION" and not run.ok and run.failed_count >= _PERMISSION_STOP_AFTER)
            if general and run.stopped is None:
                run.stopped = issue
                stop.set()

    def _report_progress() -> None:
        if on_progress is None:
            return
        now = time.monotonic()
        with lock:
            if now - last_progress[0] < 1:
                return
            last_progress[0] = now
            done = run.ok + run.failed_count
        on_progress(done)

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        try:
            for page in key_pages:
                if stop.is_set():
                    break
                list(pool.map(_tag_one, page))
        except Exception as ex:                      # al listar la carpeta
            log.warning("tags: listing failed: %s", error_text(str(ex)))
            run.stopped = run.stopped or issue_for_exception(ex)
    run.cancelled = stop.is_set() and run.stopped is None
    run.seconds = time.monotonic() - start
    return run


def get_bucket_tags(s3_client, bucket: str) -> dict[str, str]:
    """Devuelve las etiquetas del bucket como dict clave → valor. Vacío si no hay o no se pueden leer."""
    try:
        resp = s3_client.get_bucket_tagging(Bucket=bucket)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    except Exception:
        return {}


def construir_tag_string(metadatos_dict: dict) -> str:
    """Convierte el diccionario de metadatos en una cadena x-amz-tagging URL-encoded."""
    return "&".join(
        f"{k}={urllib.parse.quote(v)}" for k, v in metadatos_dict.items()
    )
