"""Constantes compartidas por mount y transfer."""

from __future__ import annotations



MINIO_SERVERS = {
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
    "minio": {
        "IRB": {
            "profile": "minio",
            "endpoint": "https://minio.sc.irbbarcelona.org:9000",
            "extra_rclone_config": {
                "no_check_bucket": "true",
                "region": "eu-south-2",
            }
        }
    }
}


DEFAULT_S3_REGION = "eu-south-2"


REPO = "its-irb/irb-storage-public-scripts"


try:
    from version import __version__
except ImportError:
    __version__ = "1.0.1"


EMOJI_FONT_FILENAME = "NotoColorEmoji-noflags.ttf"


LDAP_SERVER_URL = "ldap://irbldap3.sc.irbbarcelona.org"


LDAP_BASE_DN = "o=irbbarcelona"


# Umbral (en días) por debajo del cual se renuevan las credenciales STS automáticamente
STS_RENEWAL_THRESHOLD_DAYS = 3
# Duración (en días) de las credenciales STS renovadas automáticamente
STS_AUTO_RENEWAL_DAYS = 7
