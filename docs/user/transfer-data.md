# Copy data to MinIO (Bifrost transfer)

## Goal

Copy files or folders from your computer, from the Z drive (the folder shared
with your lab, sometimes called NetApp) or from an SFTP server into MinIO. The
app checks that the copy is identical to the original and attaches labels
(*tags*) that describe the data.

> **The app is called "Bifrost transfer", but it only copies.** Your original
> files are **never deleted** from where they were. In MinIO, the data you copy
> **cannot be changed or deleted afterwards** (see
> [minio-permissions-and-folders.md](minio-permissions-and-folders.md)).

## When to use it

- You want to **put data into MinIO**.
- You want the data to carry **labels** that describe it (project, sample type,
  and so on).
- You want to **check that a copy you already made is complete**.

Use something else if:

- The data is already in MinIO and you only want to add or fix its labels →
  [tag-manager.md](tag-manager.md).
- You want to copy data from the Z drive or a very large amount of data → use
  Bifrost transfer on the cluster through Open OnDemand, see
  [web-mode-ood.md](web-mode-ood.md).

## Before you start

1. The Nexica VPN is on and you have signed in (see
   [getting-started.md](getting-started.md)).
2. You are on the **copy** screen, after choosing your MinIO server.
3. You know three things:
   - the **source**: where the data is now (a folder on your computer, the Z
     drive, or an SFTP server);
   - the **destination**: the MinIO folder where it should go (see
     [minio-permissions-and-folders.md](minio-permissions-and-folders.md));
   - the **metadata profile**: the type of data you are copying (IRB Standard
     or Histopathology).

## Choose the source

You can pick a **folder** or a **single file**.

| Source | How |
|---|---|
| A folder on your computer | Type or browse to its path. |
| The Z drive (folder shared with your lab) | Use Bifrost transfer on the cluster (see [web-mode-ood.md](web-mode-ood.md)). |
| An SFTP server | Click **🌐 SFTP** and fill in the connection window. **Host** and **Username** are required; **Password** is optional (some accounts have none); **Port** is 22 unless you change it. |

> The SFTP connection is temporary. The app removes it when you click
> **Disconnect (✕)**, when you leave the copy screen and each time you sign in
> again, so nothing stays saved on your computer.

## Choose the destination

The destination browser lets you walk through MinIO: first the main folders,
then the folders inside them.

- At the top level, a **Filter by lab…** box lets you type a lab name or
  acronym to show only that lab's folders. It disappears when you enter a
  folder and comes back at the top level.
- The **metadata** section, the **copy buttons** and the **log panel** only
  appear **after you select a destination folder**.

## Choose the metadata profile

In the **METADATA** section, pick the profile from the drop-down list:

- **IRB Standard**: general data: project, machine, sample type, data types,
  requester, research group.
- **Histopathology**: owner, users, date, provider, instrument, species, sample
  type, magnification, channels.

Fill in the fields. The labels are attached to everything you copy.

> If you change the profile, the fields you have filled in are cleared. If any
> field has data, the app asks you to confirm first.

## Copy

1. Choose the **source**.
2. Choose the **destination** folder in MinIO.
3. Choose the **profile** and fill in the fields.
4. Click **Copy**. The log panel shows the progress live.
5. When it finishes, run the **integrity check** to confirm that the original
   and the copy are identical.

## Expected result

- The files appear in the destination folder, with the same folder structure
  as the source.
- They carry the labels of the profile you filled in.
- The log ends with a summary saying it finished correctly or with an error.
- The original files are still where they were.

## Limits

- You cannot delete or replace what you copied.
- Listing large MinIO folders can be slow.

## If something goes wrong

| Problem | What to do |
|---|---|
| Network error or it cannot connect | Check that the Nexica VPN is on. |
| You do not see the destination folder | You probably do not have access yet. Ask your group's data manager. |
| The copy stops halfway | Files already copied stay in MinIO. Start the copy again: files that are already there and identical are not copied again. |
| You lost the log (cluster) | The full log is saved on the cluster server, see [web-mode-ood.md](web-mode-ood.md). |
