# BIFROST
**Data transfer tool between SMB/CIFS shares and MinIO S3 — IRB Barcelona**

---

## What it does

BIFROST lets you copy data from network shares (SMB/CIFS) to MinIO S3 buckets, with integrity verification and automatic metadata tagging on every transferred object.

---

## Requirements

- Python 3.10+
- [`rclone`](https://rclone.org/) installed and available in PATH
- Access to the IRB network (LDAP + NetApp proxy reachable)

Install Python dependencies:
```bash
pip install ldap3 boto3 requests urllib3
```

---

## Files

| File | Purpose |
|---|---|
| `frontend.py` | GUI (tkinter). Entry point. |
| `backend.py` | All business logic (LDAP, rclone, SMB, S3). |
| `minio_functions.py` | MinIO/S3 specific helpers. |

All three files must be in the same directory.

---

## How to run

```bash
python frontend.py
```

To log in as a different user than the system user:
```bash
python frontend.py --customuser
```

---

## Flow

1. **LDAP login** — authenticate with your IRB credentials
2. **Select shares** — choose which SMB/CIFS shares to mount
3. **Select MinIO server** — pick the target S3 instance
4. **Credentials** — renew or keep existing STS temporary credentials
5. **Transfer** — copy data, attach metadata tags, verify integrity

---

## Notes

- SMB shares are mounted read-only via `rclone mount`
- Shares are automatically unmounted when the app closes
- ITS members can optionally use `admin_` privileges for wider share access
- Metadata fields (project, sample type, etc.) are stored as S3 object tags (`x-amz-tagging`)
