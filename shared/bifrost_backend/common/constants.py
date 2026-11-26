"""Constantes compartidas por mount y transfer."""

from __future__ import annotations

import os


# El orden es el de las pantallas: las tarjetas de mount y la lista de transfer (el primero sale seleccionado).
MINIO_SERVERS = {
    "minio": {
        "IRB": {
            "profile": "minio",
            "endpoint": "https://minio.sc.irbbarcelona.org:9000",
            "extra_rclone_config": {
                "region": "eu-south-2",
            }
        }
    },
    "minio-archive": {
        "IRB": {
            "profile": "minio-archive",
            "endpoint": "https://minio-archive.sc.irbbarcelona.org:9000"
        }
    },
    "irbminio": {
        "IRB": {
            "profile": "irbminio",
            "endpoint": "http://irbminio.sc.irbbarcelona.org:9000"
        }
    },
}


DEFAULT_S3_REGION = "eu-south-2"


REPO = "its-irb/irb-storage-public-scripts"


# Versión de desarrollo: la de version.py en el repositorio (y la de reserva si no existe). CI la sobrescribe
# siempre con la real (X.Y.Z o X.Y.Z.N); con ella la app no busca actualizaciones (updates.py).
DEV_VERSION = "0.0.0.dev"

try:
    from version import __version__
except ImportError:
    __version__ = DEV_VERSION


EMOJI_FONT_FILENAME = "NotoColorEmoji-noflags.ttf"


# LDAP del IRB (eDirectory), siempre por LDAPS: la conexión se monta en common/ldap_server.py.
LDAP_HOST = "irbedir3.sc.irbbarcelona.org"
LDAP_PORT = 636
# Nombre que figura en el certificado del servidor (solo CN=irbedir3, sin el dominio). ldap3 lo acepta como válido
# aunque se conecte por el nombre completo. Sobra cuando ITS reemita el certificado con el FQDN en el SAN.
LDAP_CERT_NAME = "irbedir3"


LDAP_BASE_DN = "o=irbbarcelona"


# Umbral (en días) por debajo del cual se renuevan las credenciales STS automáticamente
STS_RENEWAL_THRESHOLD_DAYS = 3
# Duración (en días) de las credenciales STS renovadas automáticamente
STS_AUTO_RENEWAL_DAYS = 7


# Máquinas sin acceso a LDAP pero con acceso a MinIO (ej. IVIS).
# Setear BIFROST_NO_LDAP=1 como variable de sistema para saltarse la validación LDAP.
NO_LDAP = os.environ.get("BIFROST_NO_LDAP") == "1"
