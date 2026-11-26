"""Consulta de grupos LDAP (bifrost-transfer)."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from ..common.constants import LDAP_BASE_DN
from ..common.ldap_server import ldap_server

LDAP_TIMEOUT = 10  # segundos: conexión y respuesta


def get_ldap_groups(usuario: str) -> list[str]:
    """Obtiene los grupos LDAP a los que pertenece un usuario (búsqueda anónima, por LDAPS)."""
    conn = Connection(ldap_server(LDAP_TIMEOUT), auto_bind=True, receive_timeout=LDAP_TIMEOUT)
    conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=f"(uid={escape_filter_chars(usuario)})",
        search_scope=SUBTREE,
        attributes=["groupMembership"],
    )
    cn_grupos = []
    for entrada in conn.entries:
        for dn in entrada.groupMembership.values:
            partes = dn.split(",")
            cn = next(
                (p.split("=")[1] for p in partes if p.lower().startswith("cn=")), None
            )
            if cn:
                cn_grupos.append(cn)
    conn.unbind()
    return cn_grupos
