# Fix common problems

## Error codes

Every error window, every error shown instead of a folder list, and the summary
of a copy, check or Tag Manager operation that failed show an **error code**,
for example `MNT101-1103-141526`:

| Part | Example | Meaning |
|---|---|---|
| Where | `MNT` | `MNT` mounting a folder (Bifrost mount) · `NET` NetApp share (cluster) · `CPY` copy · `CHK` check · `TAG` Tag Manager · `APP` updating BIFROST, or an unexpected error |
| What | `101` | The kind of problem (see the table below). The same problem always has the same number. |
| When | `1103-141526` | Month and day (November 3) and time (14:15:26). |

When you contact ITS, give them the **whole code**: it lets them find that
exact error in your logs (see [Send your logs to ITS](#send-your-logs-to-its)).

### What each number means

| Number | Problem | What to do |
|---|---|---|
| **1xx** | **MinIO** | |
| 101 | MinIO access expired | Click **🔑 Renew credentials** and try again. In the Tag Manager, go **← Back**, renew and open the Tag Manager again. |
| 102 | MinIO access not set up | The same as 101. |
| 103 | No permission in MinIO | Check that you chose the right folder. If you need access, ask your group's data manager. |
| 104 | MinIO folder not found | Choose the folder again from the list. |
| 105 | File no longer in MinIO | It was deleted or moved. Open the folder again to see what it contains now. |
| 106 | File already in MinIO | A file with the same name cannot be replaced (WORM). The file in MinIO is kept; to keep this version too, copy it into a new folder. |
| 107 | Tag not accepted | Shorten the value or remove unusual characters, and try again. |
| 108 | MinIO is busy | Wait a few minutes and try again. |
| 109 | Your computer's clock is wrong | Set the date and time to automatic and try again. |
| **2xx** | **Connection and limits** | |
| 201 | Connection problem | Check that the Nexica VPN is on and try again. |
| 202 | Temporary problem | Try again: files already copied are skipped. |
| 203 | Transfer limit reached (`--max-transfer`) | Copy again to continue: files already copied are skipped. |
| 204 | Time limit reached (`--max-duration`) | Copy again to continue: files already copied are skipped. |
| **3xx** | **Your files** | |
| 301 | Source not found | It may have been moved or renamed. Check the path and try again. |
| 302 | Cannot open a file or folder | Check that you have permission to open it. If not, ask the owner of the folder. |
| 303 | A file changed while it was being copied | Wait until the instrument or program has finished writing it, then copy again. |
| 304 | A file is open in another program | Close that program and copy again. |
| 305 | Not enough space | Free some space and try again. |
| **4xx** | **Mounted folders** | |
| 401 | The folder did not respond | MinIO or the NetApp did not answer in time. Check that the Nexica VPN is on and try again. |
| 402 | Mount folder in use | Click **⊠ Unmount all** and mount again. If it keeps happening, restart the computer. |
| 403 | BIFROST cannot open the mounted folder | On a Mac: **System Settings → Privacy & Security → Files and Folders**, allow BIFROST to access network volumes, then mount again. |
| 404 | Could not unmount | Close the windows or programs that are using the folder and click **⊠ Unmount all** again. |
| 405 | Folder driver missing | On a Mac, reinstall BIFROST. On Linux, install FUSE (`sudo apt install fuse3` or `sudo dnf install fuse3`), or ask ITS. |
| **5xx** | **NetApp** | |
| 501 | NetApp did not accept your password | Sign out and sign in again with your current IRB password. |
| 502 | NetApp share not found | Contact ITS. |
| 503 | No permission on the NetApp share | If you need access, ask your group's data manager. |
| **9xx** | **BIFROST** | |
| 901 | BIFROST is incomplete | Reinstall BIFROST. |
| 902 | Options not valid | Check the options in **Additional rclone flags (advanced)**, or restore the default values. |
| 903 | The operation stopped | [Send your logs to ITS](#send-your-logs-to-its) with the error code. |
| 999 | Something went wrong | Try again. If it keeps happening, [send your logs to ITS](#send-your-logs-to-its) with the error code. |

## Send your logs to ITS

**On your computer:**

1. Click **Export logs…** at the top right of any BIFROST screen.
2. BIFROST tells you what it will save: the logs of your **last 5 sessions** and,
   in Bifrost transfer, the copy, check and Tag Manager **reports** of those
   sessions. Click **Export**.
3. The file `BIFROST-<app>-logs-<date>.zip` is saved in your **Downloads**
   folder, and a window opens with it selected. Send it to ITS with the error
   code.

> The reports in the file contain the names of folders and files and the labels
> you filled in. Only share it with ITS.

If you need the logs folder itself:

| Where you use BIFROST | Logs folder |
|---|---|
| macOS | `~/Library/Logs/BIFROST/<app>/` (`mount` or `transfer`). Finder hides this folder: choose **Go → Go to Folder…** and paste the path. |
| Windows | `%LOCALAPPDATA%\IRB\BIFROST\<app>\`. Paste the path in the address bar of File Explorer. |
| Linux | `~/.local/state/bifrost/<app>/` |

Each session writes one file; BIFROST keeps the last 30. The reports are in the
`reports` folder inside it.

**On the cluster (Open OnDemand)** there is no **Export logs…** button: send ITS
the error code and the `output.log` file of your session folder (see
[web-mode-ood.md](web-mode-ood.md#logs-and-reports)).

## It cannot connect, or shows network errors

**Symptom**: the app does not reach the sign-in screen, or fails when you
choose the MinIO server.

1. Check that the **Nexica VPN (Forticlient)** is switched on and connected.
   BIFROST does not work without it.
2. If you use BIFROST on the cluster, check that you are on the cluster
   network.
3. Close the app and open it again after reconnecting the VPN.

## Sign-in fails

**Symptom**: an error appears when you sign in.

While the app checks your account, the **Authenticate** button and both fields
turn grey and a small spinner appears. This can take up to about 10 seconds;
wait until the spinner disappears.

Find the message you see in red under the password field:

| Message | What it means | What to do |
|---|---|---|
| Username is required. / Password is required. | One of the two fields is empty. | Type the missing field and click **Authenticate** again. |
| Invalid credentials. Please try again. | The username or the password is not correct. | Check your **username and password**: they are the ones you use to sign in to your IRB computer. |
| ⚠️ Cannot reach the IRB network. Are you connected to the VPN? | The app cannot reach the IRB network. | Switch on the **Nexica VPN (Forticlient)** and try again. |
| ⚠️ Could not reach the LDAP server. Try again or contact ITS. | The IRB service that checks your account did not answer. | Wait a moment and try again. If it keeps happening, contact ITS. |
| ⚠️ Unexpected error validating credentials. Contact ITS. | Something unexpected went wrong while checking your account. | Contact ITS and tell them the time it happened. |

- Check your **username and password**: they are the ones you use to sign in
  to your IRB computer.
- **Computers that cannot check your IRB account but can reach MinIO** (for
  example IVIS): an administrator can switch on the system variable
  `BIFROST_NO_LDAP=1` so the app skips the IRB account check. You still type
  your username and password, because the app needs them to get access to
  MinIO. The header then shows `DESKTOP (NO LDAP)`. To set it for all users on
  Windows, an administrator runs this in PowerShell:

  ```powershell
  setx BIFROST_NO_LDAP 1 /M
  ```

  Then close and open the app again.

## You do not see the MinIO server or folder you expect

- You probably do **not have access** yet. Ask your group's data manager to
  give you permission.
- Check that you signed in with the **right username**.

## A folder does not mount, or does not unmount (Bifrost mount)

When mounting fails, a window says why, **what you can do** (for example,
renew your MinIO access or turn on the VPN) and its [error code](#error-codes).
If it keeps happening, [send your logs to ITS](#send-your-logs-to-its) with that
code. See also the table in
[mount-buckets.md](mount-buckets.md#if-something-goes-wrong).

## Bifrost mount does not work on Windows

**Symptom**: when you mount, an error appears or the drive does not show up.

1. Windows needs **WinFsp**. If it is missing, accept the **automatic
   installation** the app offers (it asks for administrator permission), or
   install it from `winfsp.dev`.
2. Try to mount again.

## Bifrost mount shows an error on the cluster

If Bifrost shows an error as soon as it starts in a DCV session, you are
probably on node `ccn01`, where Bifrost does not work. Start a new session on
another node (for example `sphr`).

## The copy or the folder list is slow

- MinIO takes a long time to list large folders. To save time:
  - use the **Filter by lab…** box at the top level to go straight to your lab's
    folder;
  - for large volumes, copy with Bifrost transfer.
- The copy itself is usually faster than the listing; wait for it to finish.

## I need the full log of a copy or check

- The log panel only shows a summary. When each copy or check ends, BIFROST
  saves a **report** with everything that happened; the last line of the log
  says where (**📄 Report saved: …**).
- On your computer, see
  [transfer-data.md](transfer-data.md#where-the-full-report-is-saved).
- On the cluster, the report is in the folder of your Open OnDemand session,
  even if you were disconnected: see
  [web-mode-ood.md](web-mode-ood.md#logs-and-reports).

## The app asks about an update

The app updates itself: if a new version exists on GitHub, it asks if you want
to install it. Accept to get the latest version, or wait; it asks again later.

**Intel Macs:** if you are still on an older version of the app, the in-app
update may offer a build that does not run on your Mac. In that case, download
the file ending in `-macos-intel.dmg` once from
[the releases page](https://github.com/its-irb/irb-storage-public-scripts/releases)
and install it; from then on the app will update itself.

## Errors when applying labels (Tag Manager)

1. Read the window that appears and the **LOGS** panel: they say what happened
   and what you can do.
2. If it says **MinIO access expired**, go **← Back**, click **🔑 Renew
   credentials** and open the Tag Manager again. The app only renews the access
   when you sign in.
3. Click **Try again**. For a folder, only the files that failed are retried.
4. If it persists, ask your group's data manager to check your permissions on
   that folder, or [send your logs to ITS](#send-your-logs-to-its) with the
   [error code](#error-codes).

## It is still not solved

Contact ITS and send:

- the **[error code](#error-codes)** and the exact **error message**;
- your **logs**: on your computer, the file from **Export logs…** (it already
  includes the version of the app and the reports of your copies, checks and
  Tag Manager operations); on the cluster, the `output.log` file of your session
  (see [Send your logs to ITS](#send-your-logs-to-its));
- your **operating system**.
