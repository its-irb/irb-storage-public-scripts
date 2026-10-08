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
3. Choose the **profile** and fill in the fields.
4. Click apply. The labels are written on the existing files; the data itself is
   not touched.

### Automatic pre-fill

When you select a **single file** whose existing labels match a known profile,
the editor switches to that profile and **fills in the current values**. You
can review and correct them with the same drop-down lists and date pickers
used when copying. Click **Ver tags raw** to switch to the plain list of
label names and values at any moment.

## Expected result

- The selected files carry the new labels.
- No data was copied or moved.
- If you labelled a folder, every file inside it received the labels.

## Limits

- Only labels change, never the content of the files.
- Pre-fill only happens when the existing labels match a profile; otherwise the
  form starts empty (or use **Ver tags raw**).
- Labelling a large folder can take time; the log shows the progress.

## If something goes wrong

| Problem | What to do |
|---|---|
| You do not see the folder or file | Check that you signed in with the right user and that you have access to that folder. |
| The labels are not applied | Read the log for permission or access errors. The app renews its MinIO access automatically; start the operation again. If it persists, see [troubleshooting.md](troubleshooting.md). |
