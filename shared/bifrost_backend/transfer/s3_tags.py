"""Cliente S3 (boto-like) y gestión de tags de objetos/prefijos."""

from __future__ import annotations

import configparser
import urllib.parse

from ..common.constants import DEFAULT_S3_REGION
from ..common.rclone import obtener_ruta_rclone_conf


def get_s3_client_from_profile(profile_name: str, endpoint: str):
    """Crea un cliente boto3 S3 con las credenciales STS del perfil rclone dado."""
    import boto3
    config_path = obtener_ruta_rclone_conf()
    config = configparser.ConfigParser()
    config.read(config_path)
    section = config[profile_name]
    region_from_rclone = section.get("region")
    region_name = region_from_rclone or DEFAULT_S3_REGION
    print(f"[s3-client] {profile_name} → {endpoint} (region={region_name!r})", flush=True)
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=section["access_key_id"],
        aws_secret_access_key=section["secret_access_key"],
        aws_session_token=section.get("session_token") or None,
        region_name=region_name,
    )


def get_object_tags(s3_client, bucket: str, key: str) -> dict[str, str]:
    """Devuelve los tags de un objeto S3 como dict key→value."""
    resp = s3_client.get_object_tagging(Bucket=bucket, Key=key)
    return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}


def apply_tags_to_prefix(
    s3_client,
    bucket: str,
    prefix: str,
    tagset: dict[str, str],
    log_fn=None,
    on_progress=None,
) -> int:
    """Aplica tagset (replace completo) a todos los objetos bajo prefix.

    Returns:
        Número de objetos tagueados con éxito.
    """
    from concurrent.futures import ThreadPoolExecutor

    paginator = s3_client.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents") or []:
            keys.append(obj["Key"])

    tag_list = [{"Key": k, "Value": v} for k, v in tagset.items()]
    total = len(keys)
    done = {"ok": 0, "err": 0}

    def _tag_one(key: str) -> None:
        try:
            s3_client.put_object_tagging(
                Bucket=bucket, Key=key,
                Tagging={"TagSet": tag_list},
            )
            done["ok"] += 1
            if log_fn:
                log_fn(f"  ✓ {key}\n")
        except Exception as ex:
            done["err"] += 1
            if log_fn:
                log_fn(f"  ✗ {key}: {ex}\n")
        if on_progress:
            on_progress(done["ok"] + done["err"], total)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(_tag_one, keys))

    return done["ok"]


def apply_tags_to_object(
    s3_client,
    bucket: str,
    key: str,
    tagset: dict[str, str],
) -> None:
    """Aplica tagset (replace completo) a un único objeto S3."""
    tag_list = [{"Key": k, "Value": v} for k, v in tagset.items()]
    s3_client.put_object_tagging(
        Bucket=bucket, Key=key,
        Tagging={"TagSet": tag_list},
    )


def get_bucket_tags(s3_client, bucket: str) -> dict[str, str]:
    """Devuelve los tags del bucket como dict key→value. Vacío si no hay tags."""
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
