"""Modo de ejecución de bifrost-mount (variables de entorno)."""

import os

# Máquinas sin acceso a LDAP pero con acceso a MinIO (ej. IVIS).
# Setear BIFROST_NO_LDAP=1 como variable de sistema para saltarse la validación LDAP.
NO_LDAP = os.environ.get("BIFROST_NO_LDAP") == "1"
