# BIFROST user guide

BIFROST is a set of two apps from IRB Barcelona to work with the lab data
storage, called **MinIO**:

- **Bifrost transfer** copies your data to MinIO and lets you describe it
  with labels (called *tags*).
- **Bifrost mount** makes a MinIO folder appear on your computer as if it were
  a local folder. *Mounting a folder* means exactly that: making it available
  on your computer (or session) as if it were local.

Choose the guide that matches what you want to do:

| I want to… | Guide |
|---|---|
| Install BIFROST and sign in for the first time | [getting-started.md](getting-started.md) |
| Understand what I can read, write and delete in MinIO, and how the folders are organised | [minio-permissions-and-folders.md](minio-permissions-and-folders.md) |
| Copy data to MinIO | [transfer-data.md](transfer-data.md) |
| Add or fix labels on data that is already in MinIO | [tag-manager.md](tag-manager.md) |
| Open a MinIO folder as if it were on my computer | [mount-buckets.md](mount-buckets.md) |
| Use BIFROST on the cluster, through Open OnDemand | [web-mode-ood.md](web-mode-ood.md) |
| Fix a problem | [troubleshooting.md](troubleshooting.md) |

## Which app should I use?

| If you want to… | Use |
|---|---|
| Copy data **to** MinIO, or label data already there | Bifrost transfer |
| **Open** data that is in MinIO, without copying it | Bifrost mount |

> **Important:** BIFROST only **copies** data. It never deletes the original
> files from where they were. And once data is in MinIO, it cannot be deleted
> (see [minio-permissions-and-folders.md](minio-permissions-and-folders.md)).

## What you need

- The **Nexica VPN** (Forticlient) switched on.
- Your **IRB username and password** (the ones you use to sign in to your IRB
  computer).
- On Windows, to use Bifrost mount you also need a small helper program called
  **WinFsp**. The app offers to install it for you if it is missing (see
  [mount-buckets.md](mount-buckets.md)).

## Notes

- The MinIO servers and folders you see depend on your research group. If you
  do not see the one you expect, you probably do not have access yet (see
  [troubleshooting.md](troubleshooting.md)).
- Technical documentation for developers is in
  [../development/README.md](../development/README.md).
