"""Autenticación STS (MinIO), credenciales rclone y validación LDAP."""

from __future__ import annotations

import configparser
import jwt
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ldap3 import Connection, SIMPLE, SUBTREE, Server
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
    r = requests.post(endpoint, data=payload, timeout=30)

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

    err = root.find(".//ns:Error", ns)
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


@dataclass(frozen=True)
class SessionInfo:
    """Usuario y tiempo restante del session_token STS guardado en un perfil rclone."""
    usuario: str | None = None
    remaining: timedelta | None = None   # None si el JWT no se pudo leer o no trae 'exp'

    @property
    def expired(self) -> bool:
        return self.remaining is not None and self.remaining <= timedelta(0)

    def needs_renewal(self, usuario: str, threshold_days: int) -> bool:
        """True si el token es de otro usuario, no se puede leer o caduca en <= threshold_days."""
        return (
            self.usuario != usuario
            or self.remaining is None
            or self.remaining <= timedelta(days=threshold_days)
        )

    def remaining_text(self) -> str:
        if self.remaining is None:
            return "unknown"
        if self.expired:
            return "expired"
        return f"{self.remaining.days}d {self.remaining.seconds // 3600}h"


def get_session_info(profile_name: str) -> SessionInfo | None:
    """
    Lee el session_token del perfil rclone y lo decodifica una sola vez.

    Returns:
        None si no se puede leer rclone.conf o el perfil no existe / no tiene token (= no hay credenciales).
        SessionInfo con usuario y remaining a None si el token existe pero no se puede leer.
    """
    try:
        config = configparser.ConfigParser(interpolation=None)
        config.read(obtener_ruta_rclone_conf())   # read() ignora ficheros inexistentes
    except Exception as e:
        print(f"[token] No pude leer rclone.conf: {e}")
        return None

    token = config[profile_name].get("session_token", "") if profile_name in config else ""
    if not token:
        print(f"[token] Sin session_token para el perfil '{profile_name}'")
        return None

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        print(f"[token] Error decodificando token: {e}")
        return SessionInfo()

    exp = payload.get("exp")
    remaining = datetime.fromtimestamp(exp, tz=timezone.utc) - datetime.now(timezone.utc) if exp else None
    return SessionInfo(usuario=payload.get("ldapUsername") or payload.get("sub"), remaining=remaining)


def validar_credenciales_ldap(credenciales_ldap: dict | None) -> tuple[bool, str | None]:
    """Valida credenciales LDAP mediante un bind autenticado."""
    if not credenciales_ldap:
        return False, "invalid", "invalid"
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
