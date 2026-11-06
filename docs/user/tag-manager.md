# Add or fix labels on data already in MinIO (Tag Manager)

## Goal

Add or correct the **labels (tags)** of files that are already in MinIO,
without copying the data again.

## When to use it

- The data is already in MinIO but has **no labels**, or its labels are **wrong
  or incomplete**.
- You want to apply the **same labels to a whole folder** at once.
- You do not want to copy large files again.

> The Tag Manager is inside **Bifrost transfer**. It only changes labels; to
> copy, move or rename files, use the copy screen
> ([transfer-data.md](transfer-data.md)).

## Before you start

- The Nexica VPN is on and you have signed in.
- You know the **folder** or **file** you want to label.
- You know which **metadata profile** applies (IRB Standard or Histopathology).

## How to do it

1. Open **Bifrost transfer** and go to the **Tag Manager**.
2. Browse to what you want to label: a single **file**, a **folder**, or a
   whole **folder tree** inside a bucket. At the top level, the **Filter by
   lab…** box helps you find your lab's folders.
3. Choose the **profile** and fill in the fields. All the fields of the
   profile are written on the files, also the empty ones.
4. For a folder, click **Apply tags →**; for a single file, **Save tags**. The
   labels are written on the existing files; the data itself is not touched.

While the labels of a folder are being applied, the line next to the button
shows the progress ("Setting tags: N files done so far"). Click **Cancel** to
stop: the files already done keep the new labels and the rest are not changed.

### The LOGS panel and the report

The **LOGS** panel at the bottom shows what each operation did: the folder or
file, the profile and labels, and the result with the **number** of files in
each case (not their names). At the end of each operation BIFROST saves a
**report** and the last line of the panel gives its full path
(**📄 Report saved: …**):

- saving the labels of a file: the report keeps the labels it had before and
  the new ones, so they can be restored if needed;
- applying to a folder: the report also lists the files that could not be
  changed (up to 100), with the reason.

The reports are in the same folder as the copy reports, see
[Where the full report is saved](transfer-data.md#where-the-full-report-is-saved).

### Automatic pre-fill

When you select a **single file** whose existing labels match a known profile,
the editor switches to that profile and **fills in the current values**. You
can review and correct them with the same drop-down lists and date pickers
used when copying. Click **Show raw tags** to switch to the plain list of
label names and values at any moment.

Under the file name, the editor shows when the file was **uploaded to MinIO**
("Uploaded to MinIO: …", in your local time). Changing labels does not change
this date.

If the current labels of a file **cannot be read** (for example, the
connection was lost), the editor does not open: saving without knowing the
current labels would replace them blindly. A window explains the problem; click
**Try again** when it is solved, or **Cancel**.

## Expected result

- The selected files carry the new labels.
- No data was copied or moved.
- If you labelled a folder, every file inside it received the labels.

## Limits

- Only labels change, never the content of the files.
- Pre-fill only happens when the existing labels match a profile; otherwise the
  form starts empty (or use **Show raw tags**).
- Labelling a large folder can take time; the line next to the button shows the
  progress and **Cancel** stops it.

## If something goes wrong

| Problem | What to do |
|---|---|
| You do not see the folder or file | Check that you signed in with the right user and that you have access to that folder. If the list shows an error, follow what it says. |
| A window says the labels could not be read, saved or applied | Follow the "What you can do" line, then click **Try again**. For a folder, Try again only retries the files that failed (or the whole folder again if the operation stopped). |
| "MinIO access expired" | Go **← Back**, click **🔑 Renew credentials** and open the Tag Manager again. |
| It keeps failing | Click **Export logs…** and send the file to ITS with the error code shown in the window and in the LOGS panel (see [Error codes](troubleshooting.md#error-codes)). |
