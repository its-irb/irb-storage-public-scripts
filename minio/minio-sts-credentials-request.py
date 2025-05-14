"""
Script para generar credenciales temporales de acceso al servidor de Minio de IRB Barcelona.
Si se pasa el flag -r o --rclone, se generará un perfil en el fichero de configuración de rclone
En caso contrario, se generarán variables de entorno para AWS CLI y s5cmd.
"""
import minio_functions

import getpass
import argparse
import boto3
import sys

minio_functions.check_version()

parser = argparse.ArgumentParser(description="Generate STS credentials for Minio IRB servers.")
parser.add_argument("-u", "--username", required=True, type=str, help="LDAP username")
parser.add_argument(
    "-e", "--endpoint", default="http://minio-gordo.hpc.irbbarcelona.pcb.ub.es:9000", help="MINIO STS endpoint"
)
parser.add_argument(
    "-d", "--durationdays", default="30", help="STS credentials time expiry in days (default 30)"
)
parser.add_argument(
    "-r", "--rclone", action="store_true", help="Create (or modify) and configure profile into rclone config file for current user instead of generating environment variables (default False)"
)
parser.add_argument(
    "-p", "--profilename", default="minio-gordo-hpc", help="Profile name for rclone configuration (default minio-gordo-hpc)"
)
args = parser.parse_args()

password = getpass.getpass("Introduce your LDAP password: ")
username = args.username
endpoint = args.endpoint
durationdays = args.durationdays
rclone = args.rclone
profilename = args.profilename

credentials = minio_functions.get_credentials(endpoint, username, password, 86400 * int(durationdays))

if credentials is None:
    sys.exit(1)

if not rclone:
    print("---------------------------------------------------------------------------------------------------------------")
    print("COPY AND PASTE THE FOLLOWING LINES IN YOUR COMMAND LINE TO CONFIGURE AWS CLI IN LINUX OR MACOS")
    print("---------------------------------------------------------------------------------------------------------------")
    print(f"export AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
    print(f"export AWS_SECRET_ACCESS_KEY={credentials['SecretAccessKey']}")
    print(f"export AWS_SESSION_TOKEN={credentials['SessionToken']}")
    print(f"export AWS_ENDPOINT_URL={endpoint}")
    print("---------------------------------------------------------------------------------------------------------------")

    print("---------------------------------------------------------------------------------------------------------------")
    print("COPY AND PASTE THE FOLLOWING LINES IN YOUR COMMAND LINE TO CONFIGURE AWS CLI IN WINDOWS")
    print("---------------------------------------------------------------------------------------------------------------")
    print(f"set AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
    print(f"set AWS_SECRET_ACCESS_KEY={credentials['SecretAccessKey']}")
    print(f"set AWS_SESSION_TOKEN={credentials['SessionToken']}")
    print(f"set AWS_ENDPOINT_URL={endpoint}")
    print("---------------------------------------------------------------------------------------------------------------")

    print("---------------------------------------------------------------------------------------------------------------")
    print("COPY AND PASTE THE FOLLOWING LINES IN YOUR COMMAND LINE TO CONFIGURE S5CMD")
    print("---------------------------------------------------------------------------------------------------------------")
    print(f"export AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
    print(f"export AWS_SECRET_ACCESS_KEY={credentials['SecretAccessKey']}")
    print(f"export AWS_SESSION_TOKEN={credentials['SessionToken']}")
    print(f"export S3_ENDPOINT_URL={endpoint}")
    print("---------------------------------------------------------------------------------------------------------------")
else:
    minio_functions.configure_rclone(credentials['AccessKeyId'], credentials['SecretAccessKey'], credentials['SessionToken'], endpoint, profilename)
    print("---------------------------------------------------------------------------------------------------------------")
    print("Rclone credentials configured, you can now use the minio-gordo-hpc profile to mount S3 bucket")
    print("---------------------------------------------------------------------------------------------------------------")

s3_resource = boto3.resource(
    "s3",
    aws_access_key_id=credentials["AccessKeyId"],
    aws_secret_access_key=credentials["SecretAccessKey"],
    aws_session_token=credentials["SessionToken"],
    region_name="us-west-1",
    endpoint_url=endpoint,
)

print("BUCKETS AVAILABLE WITH THESE CREDENTIALS:")
for bucket in s3_resource.buckets.all():
    print(bucket.name)
