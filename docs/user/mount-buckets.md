# Open a MinIO folder as if it were on your computer (Bifrost mount)

## Goal

Make a MinIO folder appear on your computer as if it were a local folder, so
you can open its files with your usual programs. This is called **mounting** a
folder: making it available on your computer (or session) as if it were local.

## When to use it

- You want to **open files** in MinIO directly, without copying them first.
- You want to read MinIO data from a program on the cluster (see
  [web-mode-ood.md](web-mode-ood.md)).

Use something else if:

- You want to **put new data into MinIO** → [transfer-data.md](transfer-data.md).
  Bifrost mount does not add labels to the data.

> Bifrost mount works on your computer's desktop (Windows, macOS, Linux) and in
> a cluster desktop session (DCV). It does **not** work in the browser mode of
> Open OnDemand.

## Before you start

- The Nexica VPN is on and you have signed in (see
  [getting-started.md](getting-started.md)).
- **Windows**: the helper program **WinFsp** must be installed. If it is
  missing, the app tells you and offers to install it (it asks for
  administrator permission). You can also install it yourself from
  `winfsp.dev`.
- **macOS**: nothing to install; the needed component travels inside the app.
- **Linux**: uses the FUSE component of your system.

## How to mount a folder

1. Open **Bifrost mount** and sign in.
2. Choose your **MinIO server**.
3. On the mount screen, browse to the MinIO folder you want to mount.
4. Click **Mount**.

## Expected result

- On Windows a new **drive letter** appears; on macOS and Linux, a new folder.
  Its contents are the contents of the MinIO folder.
- You can open and copy files from there.
- What you can write depends on your permissions (see
  [minio-permissions-and-folders.md](minio-permissions-and-folders.md)).
  Data cannot be deleted.

## Unmount when you finish

Click **Unmount** to release the drive. The app can unmount the selected drive
or all mounted drives at once.

## Limits

- Opening very large folders can be slow, because MinIO takes longer to list
  them. If it is too slow, copy the data you need with Bifrost transfer.
- On Windows, mounting depends on WinFsp being installed and working.

## If something goes wrong

| Problem | What to do |
|---|---|
| Windows: it does not mount, or a driver error appears | Accept the automatic WinFsp installation offered by the app, or install it from `winfsp.dev`, then try again. |
| It cannot connect | Check that the Nexica VPN is on. |
| You do not see the folder | You probably do not have access. Ask your group's data manager. |
