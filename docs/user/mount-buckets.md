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
3. On the mount screen, select the bucket you want to mount. If the list does not load (for example, the VPN
   was off), turn on the VPN and click **⟳** next to the list title to load it again.
4. Click **⊞ Mount bucket** (or double-click the bucket). BIFROST checks that the folder really answers before it says **✅ Mounted!** and opens it. If the bucket is already mounted, BIFROST just opens its folder again. If macOS disconnected it (for example, after you clicked **Disconnect** when the connection was lost), BIFROST mounts it again.

## Expected result

- A new folder opens: `C:\rclone-mounts\<server>\<bucket>` on Windows,
  `~/rclone-mounts/<server>/<bucket>` on macOS and Linux. Its contents are the contents of the MinIO bucket.
- You can open and copy files from there.
- What you can write depends on your permissions (see
  [minio-permissions-and-folders.md](minio-permissions-and-folders.md)).
  Data cannot be deleted.

## Unmount when you finish

Click **⊠ Unmount all** to release all the mounted folders. If a folder is
still in use (a Finder or Explorer window, or a program with a file open), the
app tells you which one could not be unmounted: close what is using it and
click **⊠ Unmount all** again.

## Limits

- Opening very large folders can be slow, because MinIO takes longer to list
  them. If it is too slow, copy the data you need with Bifrost transfer.
- On Windows, mounting depends on WinFsp being installed and working.

## If something goes wrong

| Problem | What to do |
|---|---|
| A window says **Could not mount the bucket** | Follow its "What you can do" line. The window also shows the path of BIFROST's log file (**Details: …**): send it to ITS if the problem continues. |
| **MinIO access expired** | Click **🔑 Renew credentials** and mount again. |
| Mac: **BIFROST cannot open the mounted folder** | In **System Settings → Privacy & Security → Files and Folders**, allow BIFROST to access network volumes, then mount again. |
| **The folder did not respond** | MinIO did not answer in time. Check that the Nexica VPN is on and try again. |
| **Could not unmount** | Close the windows or programs that are using the folder and click **⊠ Unmount all** again. |
| Windows: it does not mount, or a driver error appears | Accept the automatic WinFsp installation offered by the app, or install it from `winfsp.dev`, then try again. |
| It cannot connect | Check that the Nexica VPN is on, then click **⟳** to reload the bucket list. |
| You do not see the folder | You probably do not have access. Ask your group's data manager. |
| The label at the top is red or orange (**🔑 Credentials expire in …**) | Your MinIO access pass is about to run out. Click **🔑 Renew credentials** (see [getting-started.md](getting-started.md#renew-your-minio-access-pass-by-hand)). |
