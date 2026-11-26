"""Conexión LDAPS al LDAP del IRB, compartida por el login (auth.py) y los grupos (transfer/ldap_groups.py).

La contraseña solo viaja por TLS y solo hacia un servidor cuyo certificado firma la CA del IRB con el nombre
LDAP_CERT_NAME. Si el certificado no se puede verificar, la conexión se corta antes de enviar nada y no se vuelve a
intentar sin cifrar.
"""

from __future__ import annotations

import ssl

from ldap3 import Server, Tls

from .constants import LDAP_CERT_NAME, LDAP_HOST, LDAP_PORT

# CA "O=IRBBARCELONA-TREE, OU=Organizational CA" (eDirectory), la que firma el certificado de irbedir3.
# Válida hasta 2031-05-05. SHA-256:
# DC:B8:DD:F7:F3:50:A5:8A:5B:2D:64:73:C2:98:D0:45:4E:48:5B:20:7B:B9:F8:E8:57:63:FC:FA:F2:75:3C:6C
# TODO(seguridad): obtenida del propio servidor; pendiente de que ITS confirme la huella por otra vía.
IRB_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIFLzCCBBegAwIBAgIUA/vHledFGcbxcopID7xbHPvEJeYwDQYJKoZIhvcNAQEL
BQAwODEaMBgGA1UEChMRSVJCQkFSQ0VMT05BLVRSRUUxGjAYBgNVBAsTEU9yZ2Fu
aXphdGlvbmFsIENBMB4XDTIxMDUwNTA2NDg1OVoXDTMxMDUwNTA2NDg1OVowODEa
MBgGA1UEChMRSVJCQkFSQ0VMT05BLVRSRUUxGjAYBgNVBAsTEU9yZ2FuaXphdGlv
bmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqhBiazJ5m6rq
itLHfgw473Kc1vyIRG7LVa+7xG84GSolPlr+NoiQ9r+3Qi4pj0semISeVqg1yz1r
x9yEIs/2DuKQGocFGrV8+5seq/NR3IxvmcT1UR1SEy8TtT+u0o/cs0nQHgIYuFup
D6F1HArUPRvgg9rlb7JX2vJwA2NIJMjvODVxAKVDJpL1z6JTJpVKFnXCEx3z5LAF
1UI2p2jyx5FhZd8tEKiJEeCltaVZF9rutxDCg1Max2gfm7NrgTMZ8QHGeS8MYF0o
W46YcVf5IOIacMDvIticRwZslykdz8Gb1XZNp32x3lf7kdFnfXDCDWkCjS/NuJxv
SWJdg+Xj3wIDAQABo4ICLzCCAiswHQYDVR0OBBYEFCt11pnnEm5MyqrnpAznz14/
O47aMB8GA1UdIwQYMBaAFCt11pnnEm5MyqrnpAznz14/O47aMAwGA1UdEwQFMAMB
Af8wCwYDVR0PBAQDAgEGMIIBzAYLYIZIAYb4NwEJBAEEggG7MIIBtwQCAQABAf8T
HU5vdmVsbCBTZWN1cml0eSBBdHRyaWJ1dGUodG0pFkNodHRwOi8vZGV2ZWxvcGVy
Lm5vdmVsbC5jb20vcmVwb3NpdG9yeS9hdHRyaWJ1dGVzL2NlcnRhdHRyc192MTAu
aHRtMIIBSKAaAQEAMAgwBgIBAQIBRjAIMAYCAQECAQoCAWmhGgEBADAIMAYCAQEC
AQAwCDAGAgEBAgEAAgEAogYCARgBAf+jggEEoFgCAQICAgD/AgEAAw0AgAAAAAAA
AAAAAAAAAwkAgAAAAAAAAAAwGDAQAgEAAgh//////////wEBAAIEBvDfSDAYMBAC
AQACCH//////////AQEAAgQG8N9IoVgCAQICAgD/AgEAAw0AQAAAAAAAAAAAAAAA
AwkAQAAAAAAAAAAwGDAQAgEAAgh//////////wEBAAIEEf+viTAYMBACAQACCH//
////////AQEAAgQR/6+Jok4wTAIBAgICAP8CAQADDQCA//////////////8DCQCA
/////////zASMBACAQACCH//////////AQH/MBIwEAIBAAIIf/////////8BAf8w
DQYJKoZIhvcNAQELBQADggEBAKfDU5FIaLDs3Q9iTVUFkKCz7sBzUn/QVncgtVBR
gj4M+BmT9cZkXcoHEz/hAcViEIWt/6hJeWTLiK5RCut3mfxfwPz9Xx8+xWFdmGes
drzacsfQjRpi1FcyJKYl3W/gN9LB4Ff+jTQdMQu4IecvrnG7nqY6mnIH9/sOn/+B
jNhPs2n3roFHrvmjn9Hkg4ljDYhP8HSuRQaNVeO13OHS5+Z/A0JQsQiH3UUHMBzx
xTPfWCGRdxcGddvNNkxLdKB3n8Us8Y2wsa6Mq5upWHzuSzfN2+Jr1g0KIwz5qHpR
UJ3etJWRTlgfmjk7iQ23bUSzTazmvMP54VaaW1MCG2AXBc4=
-----END CERTIFICATE-----
"""


def ldap_server(timeout: int) -> Server:
    """Servidor LDAP del IRB por LDAPS, verificando el certificado contra la CA del IRB."""
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        # Contexto TLS sin VERIFY_X509_STRICT (activo por defecto desde Python 3.13): la CA del IRB no marca
        # Basic Constraints como crítico y ese modo la rechaza. La cadena y el nombre se siguen verificando.
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_data=IRB_CA_PEM,
        # Con Python >= 3.12, ldap3 compara con su tls_backport, que ignora la IP del SAN y usa el CN (irbedir3).
        valid_names=[LDAP_CERT_NAME],
    )
    return Server(LDAP_HOST, port=LDAP_PORT, use_ssl=True, tls=tls, connect_timeout=timeout)


def es_error_tls(error: Exception) -> bool:
    """True si la conexión falló al verificar el certificado (servidor no fiable o certificado cambiado)."""
    return "ssl wrapping error" in str(error).lower()
