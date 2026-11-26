# Open a MinIO folder as if it were on your computer (Bifrost mount)

## Goal

Make your MinIO data appear on your computer as if it were a local folder, so
you can open its files with your usual programs. This is called **mounting** a
folder: making it available on your computer (or session) as if it were local.
Bifrost mount mounts a whole MinIO server at once: all the buckets you can see
in it appear inside as folders.

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
2. You see one card per **MinIO server** (`minio`, `minio-archive`, `irbminio`).
   Each server is mounted whole: all the buckets you can see appear inside it
   as folders.
3. Click **Mount** on the server's card (or double-click the card). If your
   MinIO access pass needs renewing, BIFROST renews it first and comes back to
   mount (if that renewal fails, see "If something goes wrong"). BIFROST checks
   that the server really answers before it says **Mounted!** and opens it.
4. If the server is already mounted, the button says **Open** and just opens
   it again. If macOS disconnected it (for example, after you clicked
   **Disconnect** when the connection was lost), BIFROST mounts it again.

You can have several servers mounted at the same time.

## Expected result

- The server opens with its buckets as folders:
  - **Windows**: a new drive with a free letter (for example `X:`). A bucket is
    `X:\<bucket>`. The letter can change the next time you mount, so do not rely
    on shortcuts to it.
  - **macOS and Linux**: the folder `~/rclone-mounts/<server>`. A bucket is
    `~/rclone-mounts/<server>/<bucket>`.
- The card shows where the server is mounted (**Mounted at …**).
- You can open and copy files from there.
- **New files take time to appear.** To go faster, BIFROST remembers the
  contents of each folder for up to 12 hours. A file added to MinIO meanwhile
  (for example with Bifrost transfer) may not appear until then. To see it
  now, close the files you have open from that server, click **Unmount** and
  mount it again.
- It is read-only: you can open and copy files, but not change, add or delete
  anything in MinIO. Which buckets you see depends on your permissions (see
  [minio-permissions-and-folders.md](minio-permissions-and-folders.md)).

## Unmount when you finish

Click **Unmount** on the server's card. If it is still in use (a Finder or
Explorer window, or a program with a file open), the app tells you it could not
be unmounted: close what is using it and click **Unmount** again. Closing
Bifrost mount also unmounts the servers it mounted.

## Limits

- Opening very large folders can be slow, because MinIO takes longer to list
  them. If it is too slow, copy the data you need with Bifrost transfer.
- The files you read are kept for a while on your computer to open them
  faster (up to about 10 GB per server; a file you have not read for an hour
  is removed).
- On Windows, mounting depends on WinFsp being installed and working.

## If something goes wrong

| Problem | What to do |
|---|---|
| A window says **Could not mount the server** | Follow what its **What you can do** box says. If the problem continues, click **Export logs…** and send the file to ITS with the error code shown at the bottom of the window (the button next to the code copies it) (see [Error codes](troubleshooting.md#error-codes)). |
| **MinIO access expired** | Click **Renew credentials** and mount again. |
| The renewal screen says it **cannot connect to MinIO** (when you mount, or after **Renew credentials**) | Check that the Nexica VPN is on and click **Try again**. To leave that screen, click **Back to servers** at the top left; you do not need to close the app. |
| Mac: **BIFROST cannot open the mounted folder** | In **System Settings → Privacy & Security → Files and Folders**, allow BIFROST to access network volumes, then mount again. |
| **The folder did not respond** | MinIO did not answer in time. Check that the Nexica VPN is on and try again. |
| **Could not unmount** | Close the windows or programs that are using the folder and click **Unmount** again. |
| **Could not mount the server** with folders "mounted by the previous version of Bifrost mount" | An older version of the app left some buckets mounted and a program still has a file open in them. Close it and click **Mount** again. |
| **No free drive letter** (Windows) | Unmount a server you do not need, or disconnect a drive, and try again. |
| A file you just added to MinIO does not appear | Close the files open from that server, click **Unmount** and mount it again (see "Expected result"). |
| Windows: it does not mount, or a driver error appears | Accept the automatic WinFsp installation offered by the app, or install it from `winfsp.dev`, then try again. |
| It cannot connect | Check that the Nexica VPN is on and mount again. |
| You do not see a bucket inside the server | You probably do not have access. Ask your group's data manager. |
| The label on a server's card is red or orange (**Credentials expire in …**) | Your MinIO access pass for that server is about to run out. Click **Renew credentials** on the card (see [getting-started.md](getting-started.md#renew-your-minio-access-pass-by-hand)). |
