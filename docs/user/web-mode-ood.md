# Use BIFROST on the cluster (Open OnDemand)

## Goal

Use BIFROST on the IRB cluster, through your web browser, with **Open
OnDemand** (the web portal of the cluster). There are two situations:

1. **Read MinIO data from a cluster app** (for example QuPath) → Bifrost mount,
   inside a DCV session.
2. **Copy large amounts of data to MinIO, or copy data from the Z drive** →
   Bifrost transfer, in Open OnDemand.

In both cases the data you copy is **never deleted from where it was**, and
data in MinIO **cannot be deleted** (see
[minio-permissions-and-folders.md](minio-permissions-and-folders.md)).

## Read MinIO data from a cluster app (Bifrost mount)

*Mounting* a folder means making it appear in your session as if it were local.

### Before you start

- You can start a **DCV** session (the remote desktop of the cluster).
- Do **not** run the job on node `ccn01`. Bifrost does not work on that node
  and shows an error straight away. Use another node (for example `sphr`).

### Steps

1. Open a **DCV** session on a node other than `ccn01`.
2. Inside the DCV session, open **Bifrost mount** and sign in.
3. Mount the MinIO folders that contain the data you need
   (see [mount-buckets.md](mount-buckets.md)).
4. From that same DCV session, open the other apps (for example QuPath). They
   can read the MinIO data through the mounted folders.

### Expected result

The mounted MinIO folders appear in your DCV session and the other apps can
open the files in them.

### If something goes wrong

- Bifrost shows an error when it starts → you are probably on `ccn01`. Close
  the session and start a new one on another node.

## Copy data to MinIO (Bifrost transfer)

Use this for large copies, or when you need to copy data from the **Z drive**
(the folder shared with your lab, sometimes called NetApp) to MinIO, which you
cannot do from your own computer.

> The app is called "Bifrost transfer", but it only **copies**: your original
> data stays where it was.

### Steps

1. Launch **Bifrost** from **Sandbox Apps** in Open OnDemand and sign in.
2. Choose the **source** of the data:
   - **The Z drive**: click **⊞ Mount NetApp** and double-click your lab's
     share to make it available first. Once mounted, you find it in
     `~/netapp-mount/<your user>/<share>`. If a share cannot be mounted, a
     window explains why and what to do, and its row shows **⚠️ Error
     (details)** to see it again. The details file is in the `rclone` folder of
     your session (next to `reports`).
   - **SFTP**: click **🌐 SFTP** and enter host and username (password is
     optional).
   - **Scratch or other cluster folders**: type their path.
3. Choose the **destination** in MinIO (see
   [transfer-data.md](transfer-data.md)).
4. Fill in the metadata and start the copy.
5. Remember that the original data is still in its source.

### Expected result

The files appear in the MinIO destination folder, and the log panel ends with a
summary of how the copy went (see
[transfer-data.md](transfer-data.md#what-the-summary-of-a-copy-means)).

## If you close the browser tab

The copy **keeps running on the cluster** even if you close the tab or lose
your connection for a moment. To go back to it:

1. Open BIFROST again from Open OnDemand.
2. Type **only your password** (your username is already filled in). You do not
   have to choose the server again.
3. You return to the copy screen. A banner shows the current state and the
   last lines of the log appear again.
4. If the copy is still running, the **Cancel** button is back. If it already
   finished while you were away, you see its summary and whether it ended
   correctly, with problems or cancelled.

The password is asked again on purpose: BIFROST never saves it.

## Logs and reports

The screen only shows the **last lines** of the log. When each copy or check
finishes, BIFROST saves a **report** with what the screen showed for that
operation in the folder of your Open OnDemand session, inside a folder called `reports` (next
to the `output.log` file of the session). To open it:

1. In Open OnDemand, open **My Interactive Sessions**.
2. On the card of your BIFROST session, click the **Session ID** link. The
   **Files** app opens the folder of the session.
3. Open the `reports` folder.

If the card of the session is no longer there (for example, after you clicked
**Delete**), the folder still exists. In the **Files** app, go to your home
folder and open `ondemand/data/sys/dashboard/batch_connect/sys/bifrost/output/`.
There is one folder per session; the most recent ones have the latest date.

If you need to keep a report, download it or copy it to another folder.

> The reports contain the source and destination folders, the labels you
> filled in and the names of the files with problems. Only share them with ITS.

## Limits

- The browser mode only has **Bifrost transfer**. To mount a folder, use
  Bifrost mount in a DCV session.
- The session lasts as long as the Open OnDemand job. If the job ends or
  restarts, the session and any copy in progress are lost; start again.

## If something goes wrong

| Problem | What to do |
|---|---|
| It takes long or says it is checking for updates | It is probably reconnecting. Wait for the reconnection banner to finish loading. |
| It asks for the password again | It is expected. Type your IRB password. |
| It cannot connect | Check that you are on the cluster network and that the Nexica VPN is on. |
| An error shows a **code** (for example `NET501-1103-141526`) | Follow its "What you can do" line. If it keeps happening, send ITS the code and the `output.log` file of your session (see [Logs and reports](#logs-and-reports) and [Error codes](troubleshooting.md#error-codes)). |
