"""Autenticación STS (MinIO), credenciales rclone y validación LDAP."""

from __future__ import annotations

import configparser
import logging
import jwt
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ldap3 import Connection, SIMPLE, SUBTREE, Server
from ldap3.core.exceptions import LDAPCommunicationError
from ldap3.utils.conv import escape_filter_chars
from xml.etree import ElementTree as etree

from .constants import LDAP_BASE_DN, LDAP_SERVER_URL, STS_RENEWAL_THRESHOLD_DAYS
from .rclone import obtener_ruta_rclone_conf

log = logging.getLogger("bifrost.auth")

LDAP_TIMEOUT = 10  # segundos: conexión y respuesta
_LOGGED_BODY = 300  # caracteres de una respuesta inesperada de MinIO que van al log técnico (en una línea)


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
    ns = {"ns": "https://sts.amazonaws.com/doc/2011-06-15/"}
    try:
        root = etree.fromstring(r.content)
    except etree.ParseError:
        root = etree.Element("not-xml")      # sin XML: no hay ni credenciales ni error de STS
    et = root.find("ns:AssumeRoleWithLDAPIdentityResult/ns:Credentials", ns)
    if et is not None:
        log.debug("sts: credentials obtained (http %s)", r.status_code)
        return {el.tag.rpartition("}")[2]: el.text for el in et}

    err = root.find(".//ns:Error", ns)
    if err is not None:
        log.warning("sts: request failed: http=%s code=%s message=%s request_id=%s", r.status_code,
                    err.findtext("ns:Code", namespaces=ns), err.findtext("ns:Message", namespaces=ns),
                    root.findtext(".//ns:RequestId", namespaces=ns) or "-")
    else:                                   # ni credenciales ni un error de STS (p. ej. la página de un proxy)
        log.warning("sts: unexpected response: http=%s body=%s", r.status_code,
                    " ".join(r.text.split())[:_LOGGED_BODY])
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

    if profilename not in config:
        config[profilename] = {
            "type":     "s3",
            "provider": "Minio",
            "acl":      "bucket-owner-full-control",
            "env_auth": "false",
        }
    section = config[profilename]
    section["endpoint"]          = endpoint
    section["access_key_id"]     = aws_access_key_id
    section["secret_access_key"] = aws_secret_access_key
    section["session_token"]     = aws_session_token
    # No comprobar ni crear el bucket antes de escribir: los buckets los crea ITS y los usuarios no tienen
    # permiso para crearlos. Se escribe siempre para que también lo tengan los perfiles creados sin esta opción.
    section["no_check_bucket"]   = "true"
    for key, value in (extra_config or {}).items():
        section[key] = str(value)

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
        log.warning("credentials: could not read rclone.conf: %s", e)
        return None

    token = config[profile_name].get("session_token", "") if profile_name in config else ""
    if not token:
        log.debug("credentials: no session token for profile %s", profile_name)
        return None

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        log.warning("credentials: could not decode the session token of profile %s: %s", profile_name, e)
        return SessionInfo()

    exp = payload.get("exp")
    remaining = datetime.fromtimestamp(exp, tz=timezone.utc) - datetime.now(timezone.utc) if exp else None
    return SessionInfo(usuario=payload.get("ldapUsername") or payload.get("sub"), remaining=remaining)


def hay_que_renovar_credenciales(perfil: str, usuario: str, umbral_dias: int = STS_RENEWAL_THRESHOLD_DAYS) -> bool:
    """True si hay que pedir a MinIO credenciales nuevas para `perfil`: no hay token, es de otro usuario, no se puede
    leer o caduca en `umbral_dias` o menos. Deja la decisión en el log técnico."""
    info = get_session_info(perfil)
    if info is None:
        log.info("credentials: profile=%s no token → renewal needed", perfil)
        return True
    renew = info.needs_renewal(usuario, umbral_dias)
    log.info("credentials: profile=%s token_user=%s login_user=%s expiry=%s → %s", perfil, info.usuario, usuario,
             info.remaining_text(), "renewal needed" if renew else "valid")
    return renew


def validar_credenciales_ldap(credenciales_ldap: dict | None) -> tuple[bool, str | None]:
    """
    Valida credenciales LDAP mediante un bind autenticado.

    Returns:
        (True, None) si son correctas. Si no, (False, motivo) con motivo en:
          "invalid"          sin credenciales
          "user_not_found"   el usuario no existe en LDAP
          "invalid_password" el usuario existe pero la contraseña no es correcta
          "vpn"              no se resuelve el servidor (sin red del IRB / VPN)
          "network"          otro fallo de comunicación (timeout, conexión rechazada)
          "error"            cualquier otra excepción
    """
    if not credenciales_ldap:
        return False, "invalid"
    usuario  = credenciales_ldap["usuario"]
    password = credenciales_ldap["password"]
    server = Server(LDAP_SERVER_URL, connect_timeout=LDAP_TIMEOUT)
    try:
        conn = Connection(server, auto_bind=True, receive_timeout=LDAP_TIMEOUT)
        conn.search(LDAP_BASE_DN, f"(cn={escape_filter_chars(usuario)})", SUBTREE, attributes=["dn"])
        if not conn.entries:
            log.debug("ldap: user %s not found", usuario)
            return False, "user_not_found"
        user_dn = conn.entries[0].entry_dn
        log.debug("ldap: user found dn=%s", user_dn)
        conn_auth = Connection(server, user=user_dn, password=password,
                               authentication=SIMPLE, receive_timeout=LDAP_TIMEOUT)
        if conn_auth.bind():
            conn_auth.unbind()
            conn.unbind()
            return True, None
        return False, "invalid_password"
    except LDAPCommunicationError as e:
        log.warning("ldap: communication error: %s", e)
        if "invalid server address" in str(e).lower():
            return False, "vpn"
        return False, "network"
    except Exception:
        log.exception("ldap: validation failed")
        return False, "error"
