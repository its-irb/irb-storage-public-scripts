#!/usr/bin/env python3
"""
MinIO STS Credentials Generator & Rclone Configurator
======================================================
Generates temporary STS credentials for MinIO IRB servers via LDAP
and optionally writes them to an rclone profile.

Usage:
    python minio_sts.py -u <username> [-s <server>] [-d <days>] [-r] [-p <profile>]

Requirements:
    pip install requests urllib3
"""

import configparser
import getpass
import sys
from pathlib import Path
from xml.etree import ElementTree as etree

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Server definitions ────────────────────────────────────────────────────────

MINIO_SERVERS = {
    "minio-archive": {
        "endpoint": "https://minio-archive.sc.irbbarcelona.org:9000",
        "profile": "minio-archive",
    },
    "irbminio": {
        "endpoint": "http://irbminio.sc.irbbarcelona.org:9000",
        "profile": "irbminio",
    },
    "minio": {
        "endpoint": "https://minio.sc.irbbarcelona.org:9000",
        "profile": "minio",
        "extra_rclone_config": {
            "no_check_bucket": "true",
            "region": "eu-south-2",
        },
    },
}

# ── STS credential retrieval ──────────────────────────────────────────────────

def get_credentials(endpoint: str, username: str, password: str, duration_seconds: int = 86400) -> dict | None:
    """Get temporary STS credentials from a MinIO server via LDAP."""
    payload = {
        "Action": "AssumeRoleWithLDAPIdentity",
        "LDAPUsername": username,
        "LDAPPassword": password,
        "DurationSeconds": duration_seconds,
        "Version": "2011-06-15",
    }
    try:
        r = requests.post(endpoint, data=payload, verify=False, timeout=15)
    except requests.exceptions.ConnectionError as e:
        print(f"ERROR: Could not connect to {endpoint}: {e}")
        return None

    if r.status_code >= 400:
        print(f"ERROR: HTTP {r.status_code} from STS endpoint.")
        print(r.text)
        return None

    try:
        root = etree.fromstring(r.content)
    except Exception as e:
        print(f"ERROR: Invalid XML response: {e}\n{r.text}")
        return None

    ns = {"ns": "https://sts.amazonaws.com/doc/2011-06-15/"}

    err = root.find(".//ns:Error", ns)
    if err is not None:
        code = err.findtext("ns:Code", namespaces=ns)
        msg  = err.findtext("ns:Message", namespaces=ns)
        print(f"ERROR: STS Error [{code}]: {msg}")
        return None

    creds_el = root.find("ns:AssumeRoleWithLDAPIdentityResult/ns:Credentials", ns)
    if creds_el is None:
        print("ERROR: No credentials found in STS response. Check your username/password.")
        return None

    credentials = {}
    for el in creds_el:
        _, _, tag = el.tag.rpartition("}")
        credentials[tag] = el.text
    return credentials


# ── Rclone config helpers ─────────────────────────────────────────────────────

def get_rclone_config_path() -> Path:
    """Returns the default rclone.conf path for the current OS."""
    if sys.platform == "win32":
        return Path.home() / "AppData" / "Roaming" / "rclone" / "rclone.conf"
    return Path.home() / ".config" / "rclone" / "rclone.conf"


def configure_rclone(
    access_key_id: str,
    secret_access_key: str,
    session_token: str,
    endpoint: str,
    profile_name: str = "minio",
    extra_config: dict | None = None,
) -> None:
    """Create or update an S3/MinIO profile in rclone.conf."""
    config_path = get_rclone_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    if config_path.exists():
        config.read(config_path)

    config[profile_name] = {
        "type":              "s3",
        "provider":          "Minio",
        "endpoint":          endpoint,
        "acl":               "bucket-owner-full-control",
        "env_auth":          "false",
        "access_key_id":     access_key_id,
        "secret_access_key": secret_access_key,
        "session_token":     session_token,
    }
    if extra_config:
        for k, v in extra_config.items():
            config[profile_name][k] = v

    with open(config_path, "w") as f:
        config.write(f)

    print(f"Rclone profile '{profile_name}' written to {config_path}")


# ── Output helpers ────────────────────────────────────────────────────────────

def print_env_vars(credentials: dict, endpoint: str) -> None:
    key    = credentials["AccessKeyId"]
    secret = credentials["SecretAccessKey"]
    token  = credentials["SessionToken"]
    sep    = "-" * 80

    print(f"\n{sep}")
    print("Linux / macOS  —  AWS CLI & s5cmd")
    print(sep)
    print(f"export AWS_ACCESS_KEY_ID={key}")
    print(f"export AWS_SECRET_ACCESS_KEY={secret}")
    print(f"export AWS_SESSION_TOKEN={token}")
    print(f"export AWS_ENDPOINT_URL={endpoint}")
    print(f"export S3_ENDPOINT_URL={endpoint}")

    print(f"\n{sep}")
    print("Windows  —  AWS CLI & s5cmd")
    print(sep)
    print(f"set AWS_ACCESS_KEY_ID={key}")
    print(f"set AWS_SECRET_ACCESS_KEY={secret}")
    print(f"set AWS_SESSION_TOKEN={token}")
    print(f"set AWS_ENDPOINT_URL={endpoint}")
    print(f"set S3_ENDPOINT_URL={endpoint}")
    print(sep)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate temporary STS credentials for MinIO IRB servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available servers: {', '.join(MINIO_SERVERS)}",
    )
    parser.add_argument("-u", "--username", required=True, help="LDAP username")
    parser.add_argument(
        "-s", "--server",
        default="irbminio",
        choices=list(MINIO_SERVERS),
        help="MinIO server (default: irbminio)",
    )
    parser.add_argument(
        "-d", "--durationdays",
        default=1,
        type=int,
        metavar="DAYS",
        help="Credential validity in days (default: 1)",
    )
    parser.add_argument(
        "-r", "--rclone",
        action="store_true",
        help="Write credentials to rclone.conf instead of printing env vars",
    )
    parser.add_argument(
        "-p", "--profilename",
        default=None,
        help="Rclone profile name (default: server name)",
    )
    args = parser.parse_args()

    server_cfg = MINIO_SERVERS[args.server]
    endpoint   = server_cfg["endpoint"]
    profile    = args.profilename or server_cfg["profile"]
    extra_cfg  = server_cfg.get("extra_rclone_config")

    password = getpass.getpass(f"LDAP password for '{args.username}': ")

    print(f"Requesting STS credentials from {endpoint} ...")
    credentials = get_credentials(endpoint, args.username, password, 86400 * args.durationdays)

    if credentials is None:
        sys.exit(1)

    expiry = credentials.get("Expiration", "unknown")
    print(f"Credentials obtained (expire: {expiry})")

    if args.rclone:
        configure_rclone(
            credentials["AccessKeyId"],
            credentials["SecretAccessKey"],
            credentials["SessionToken"],
            endpoint,
            profile_name=profile,
            extra_config=extra_cfg,
        )
    else:
        print_env_vars(credentials, endpoint)


if __name__ == "__main__":
    main()