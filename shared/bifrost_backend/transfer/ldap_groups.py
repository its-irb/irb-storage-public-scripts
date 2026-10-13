"""Consulta de grupos LDAP (bifrost-transfer)."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE, Server

from ..common.constants import LDAP_BASE_DN, LDAP_SERVER_URL


def get_ldap_groups(usuario: str) -> list[str]:
    """Obtiene los grupos LDAP a los que pertenece un usuario."""
    server = Server(LDAP_SERVER_URL)
    conn = Connection(server, auto_bind=True)
    conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=f"(uid={usuario})",
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
    return cn_grupos
