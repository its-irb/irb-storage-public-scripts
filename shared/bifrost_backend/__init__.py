import urllib3

# Efecto global compartido por todo el backend (antes en backend.py): los
# requests a MinIO internos usan verify=False.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
