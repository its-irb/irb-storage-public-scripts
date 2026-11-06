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

Fill in the fields. The labels are attached to the files copied in this run
(files already in MinIO with the same content keep the labels they had).

> If you change the profile, the fields you have filled in are cleared. If any
> field has data, the app asks you to confirm first.

## Copy

1. Choose the **source**.
2. Choose the **destination** folder in MinIO.
3. Choose the **profile** and fill in the fields.
4. Click **▶ Copy data**. The log panel shows the progress: first BIFROST
   compares your files with what is already in MinIO, then it copies the ones
   that are missing.
5. When it finishes, click **✓ Check data** to confirm that the original and
   the copy are identical.

To stop a copy, click **Cancel**. Files already copied stay in MinIO. If you
copy the same folder again later, the files that are already there are
skipped.

## Expected result

- The files appear in the destination folder, with the same folder structure
  as the source.
- The files copied in this run carry the labels of the profile you filled in.
  Files that were **already in MinIO with the same content are not copied
  again, so their labels do not change**. The summary tells you how many. To
  change their labels, use [Tag Manager](tag-manager.md).
- The log ends with a **summary** of what happened and, if something went
  wrong, **what you can do**.
- The original files are still where they were.

## What the summary of a copy means

| You see | What it means | What to do |
|---|---|---|
| ✅ **Copy finished: N file(s) copied to MinIO (size) in (time)** | Everything was copied. The line below says how many files were already in MinIO, if any. | Run **✓ Check data** to confirm it. |
| ✅ **Nothing new to copy** | All the files were already in MinIO. | Nothing. |
| ⚠️ **Files already in MinIO were not copied again, so their tags were NOT updated** | Those files were not copied again, so **their labels were not updated**: if they had other labels, they still have them. | If you wanted new labels on them, use [Tag Manager](tag-manager.md). |
| ⚠️ **N file(s) replaced a different file with the same name** | A file in MinIO had the same name but different content. It was replaced, and its labels are now the ones you filled in. | If that was not intended, contact ITS. |
| ✅ **Nothing to copy: the source folder is empty…** | There was nothing to copy in the source. | Check that you chose the right source. |
| ⚠️ **Copy finished with problems** | Some files were not copied. The log shows how many and why. | Follow the "What you can do" line, then copy again: files already copied are skipped. |
| ⚠️ **Folders that could not be read** | BIFROST could not open those folders, so **none of their files were copied**. | Check that you have permission to open them, then copy again. |
| ❌ **The copy could not finish** | The copy stopped (for example, no connection or the MinIO access expired). | Follow the "What you can do" line. |
| ⏹ **Copy cancelled** | You clicked **Cancel**. The line says how many files (and how much data) had been copied. | Copy again when you want: files already copied are skipped. |
| 🧪 **Test run** | The advanced options include a test option (`--dry-run`): nothing was copied. | Remove that option to make a real copy. |

## What the summary of a check means

| You see | What it means | What to do |
|---|---|---|
| ✅ **All N file(s) are in MinIO and identical (compared by MD5 checksum)** | The copy is complete and identical: the content of every file was compared, not only its size. | Nothing. |
| **N missing in MinIO** | Some files are in the source but not in MinIO. | Copy the folder again: files already in MinIO are skipped. |
| **N different** | Some files in MinIO are not the same as the original. | **Do not delete the original.** Contact ITS. |
| **N could not be read** | BIFROST could not open some files or folders, so they were not checked. | Check that you have permission to open them, then check again. |
| ⚠️ **…the content could not be compared** | Only the size could be compared for some files, not their content. | If you need to be sure, contact ITS. |
| ❌ **The check could not finish** | The check stopped (for example, no connection). | Follow the "What you can do" line. |

## Where the full report is saved

The log panel shows the **number** of files in each case, not their names (a
copy can include thousands of files). At the end of each copy or check,
BIFROST saves a **report** with what the log panel showed for that operation,
so you still have it after closing the app. If some files had problems (not
copied, different, could not be read, or replaced a file already in MinIO),
the report also lists them with the reason, up to 100 files. The last line of the log says
where: **📄 Report saved: …**

| Where you use BIFROST | Folder of the reports |
|---|---|
| macOS | `~/Library/Logs/bifrost/transfer/reports/`. Finder hides this folder: in Finder, choose **Go → Go to Folder…** and paste the path. |
| Windows | `%LOCALAPPDATA%\bifrost\transfer\reports\`. Paste the path in the address bar of File Explorer. |
| Linux | `~/.local/state/bifrost/transfer/reports/` |
| Cluster (Open OnDemand) | In the folder of your session, see [web-mode-ood.md](web-mode-ood.md#logs-and-reports). |

BIFROST keeps the last 30 reports of each type. **↓ Save log** saves what you
see in the log panel to a file: on your computer you choose where; on the
cluster it goes to the same reports folder.

> The reports contain the source and destination folders, the labels you
> filled in and the names of the files with problems. Only share them with ITS.

## Limits

- You cannot delete or replace what you copied.
- Listing large MinIO folders can be slow.

## If something goes wrong

| Problem | What to do |
|---|---|
| Network error or it cannot connect | Check that the Nexica VPN is on. |
| You do not see the destination folder | You probably do not have access yet. Ask your group's data manager. |
| The copy stops halfway | Files already copied stay in MinIO. Start the copy again: files that are already there and identical are not copied again. |
| You need the full log of a copy or check | Open its report, see [Where the full report is saved](#where-the-full-report-is-saved). |
| The summary shows an **error code** (for example `CPY103-1103-141526`) | Follow its "What you can do" line. If it keeps happening, click **Export logs…** and send the file to ITS with the code (see [Error codes](troubleshooting.md#error-codes)). |
| A window says **Option not allowed** | Some options in **Additional rclone flags (advanced)** cannot be used. Remove them, or put back the default values. |
| The label at the top is red or orange (**🔑 Credentials expire in …**), or you are about to start a long copy | Your MinIO access pass is about to run out. Click **🔑 Renew credentials** before copying (see [getting-started.md](getting-started.md#renew-your-minio-access-pass-by-hand)). |
