"""Autenticación STS (MinIO), credenciales rclone y validación LDAP."""

from __future__ import annotations

import configparser
import jwt
import os
import requests
from datetime import datetime, timezone
from ldap3 import Connection, SIMPLE, SUBTREE, Server
from sys import platform as sys_platform
from xml.etree import ElementTree as etree

from .constants import LDAP_BASE_DN, LDAP_SERVER_URL
from .rclone import obtener_ruta_rclone_conf


def get_credentials(endpoint: str, username: str, password: str, durationseconds: int = 86400) -> dict | None:
    """
    Obtiene credenciales STS temporales desde MinIO vía LDAP.

    Returns:
        Dict con AccessKeyId, SecretAccessKey, SessionToken o None si falla.
    """
    payload = {
        "Action": "AssumeRoleWithLDAPIdentity",
        "LDAPUsername": username,
        "LDAPPassword": password,
        "DurationSeconds": durationseconds,
        "Version": "2011-06-15",
    }
    r = requests.post(endpoint, data=payload)

    print(f"[STS] HTTP {r.status_code}")
    if r.status_code >= 400:
        print(f"[STS] Response headers: {dict(r.headers)}")
        print(f"[STS] Response body:\n{r.text}")

    try:
        root = etree.fromstring(r.content)
    except Exception as e:
        print(f"[STS] ERROR: respuesta no es XML válido: {e}")
        print(f"[STS] Raw body:\n{r.text}")
        return None

    ns = {"ns": "https://sts.amazonaws.com/doc/2011-06-15/"}

    err = root.find("ns:Error", ns) or root.find(".//ns:Error", ns)
    if err is not None:
        code  = err.findtext("ns:Code", namespaces=ns)
        msg   = err.findtext("ns:Message", namespaces=ns)
        reqid = root.findtext(".//ns:RequestId", namespaces=ns)
        print(f"[STS] Error Code={code} Message={msg} RequestId={reqid}")

    et = root.find("ns:AssumeRoleWithLDAPIdentityResult/ns:Credentials", ns)
    if et is None:
        print("[STS] No se encontró Credentials en la respuesta XML.")
        print(f"[STS] Body (XML):\n{r.text}")
        print("ERROR: Invalid LDAP credentials")
        return None

    credentials = {}
    for el in et:
        _, _, tag = el.tag.rpartition("}")
        credentials[tag] = el.text
    return credentials


def get_usuario_from_session_token(session_token: str) -> str | None:
    """Extrae el usuario del JWT del session_token de MinIO."""
    try:
        payload = jwt.decode(session_token, options={"verify_signature": False})
        #print(f"[token] payload keys: {list(payload.keys())}")
        usuario = payload.get("ldapUsername") or payload.get("sub")
        print(f"[token] ldapUsername={usuario!r}")
        return usuario
    except Exception as e:
        print(f"Error leyendo usuario del token: {e}")
        return None


def configure_rclone(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str,
    endpoint: str,
    profilename: str = "minio-gordo",
    extra_config: dict | None = None,
) -> None:
    """Crea o actualiza un perfil S3/MinIO en rclone.conf con las credenciales STS."""
    config_path = obtener_ruta_rclone_conf()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    if config_path.exists():
        config.read(config_path)

    if profilename in config:
        section = config[profilename]
        section["endpoint"]          = endpoint
        section["access_key_id"]     = aws_access_key_id
        section["secret_access_key"] = aws_secret_access_key
        section["session_token"]     = aws_session_token
    else:
        config[profilename] = {
            "type":              "s3",
            "provider":          "Minio",
            "endpoint":          endpoint,
            "acl":               "bucket-owner-full-control",
            "env_auth":          "false",
            "access_key_id":     aws_access_key_id,
            "secret_access_key": aws_secret_access_key,
            "session_token":     aws_session_token,
        }

    if extra_config:
        for key, value in extra_config.items():
            config[profilename][key] = str(value)

    with open(config_path, "w") as f:
        config.write(f)


def get_rclone_session_token(profile_name: str, config_path: str | None = None) -> str:
    """Lee el session_token del perfil rclone dado. Devuelve '' si no existe."""
    if not config_path:
        if sys_platform == "darwin":
            config_path = os.path.expanduser("~/.config/rclone/rclone.conf")
        elif sys_platform == "win32":
            config_path = os.path.join(
                os.path.expanduser("~"), "AppData", "Roaming", "rclone", "rclone.conf"
            )
        else:
            config_path = os.path.expanduser("~/.config/rclone/rclone.conf")

    if not os.path.isfile(config_path):
        print(f"El fichero de configuracion de rclone {config_path} no existe")
        return ""

    config = configparser.ConfigParser()
    config.read(config_path)

    if profile_name not in config:
        print(f"Perfil '{profile_name}' no encontrado en {config_path}")
        return ""

    return config[profile_name].get("session_token", "")


def get_expiration_from_session_token(session_token: str):
    """
    Decodifica el JWT del session_token y devuelve el tiempo restante hasta expiración.

    Returns:
        timedelta restante o None si no se puede leer.
    """
    try:
        payload = jwt.decode(session_token, options={"verify_signature": False})
        exp_timestamp = payload.get("exp")
        if not exp_timestamp:
            print("El token no contiene 'exp'.")
            return None
        exp_time = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = exp_time - now
        print(f"Expira en: {remaining} ({exp_time})")
        return remaining
    except Exception as e:
        print(f"Error decodificando token: {e}")
        return None


def validar_credenciales_ldap(credenciales_ldap: dict | None) -> tuple[bool, str | None]:
    """Valida credenciales LDAP mediante un bind autenticado."""
    if not credenciales_ldap:
        return False
    usuario  = credenciales_ldap["usuario"]
    password = credenciales_ldap["password"]
    server = Server(LDAP_SERVER_URL)
    try:
        conn = Connection(server, auto_bind=True)
        conn.search(LDAP_BASE_DN, f"(cn={usuario})", SUBTREE, attributes=["dn"])
        print(f"[debug] - LDAP: Search for user '{usuario}' returned {len(conn.entries)} entries.")
        if not conn.entries:
            print("[debug] - LDAP: No se encontró el usuario. conn.entries")
            return False, "invalid"
        user_dn = conn.entries[0].entry_dn
        conn_auth = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
        print(f"[debug] - LDAP: Validating credentials for user: {conn_auth}")
        if conn_auth.bind():
            conn_auth.unbind()
            conn.unbind()
            return True, None
        return False, "invalid"
    except Exception as e:
        print(f"LDAP validation error: {e}")
        if "invalid server address" in str(e).lower():
            return False, "vpn"
        return False, "invalid"
