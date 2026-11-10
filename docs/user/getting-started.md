# Install and sign in

## Goal

Install the BIFROST app you need and sign in for the first time.

## Before you start

- The **Nexica VPN (Forticlient)** must be switched on. Without it, BIFROST
  cannot reach your IRB account or MinIO.
- Your **IRB username and password**: the same you use to sign in to your IRB
  computer.
- **Windows and Bifrost mount only**: the computer needs a helper program
  called **WinFsp**. It is not bundled inside the app because it installs a
  deep system component, so:
  - the app notices when it is missing and **offers to download and install**
    the latest official version (it asks for administrator permission), or
  - you can install it yourself from `winfsp.dev`.

You do **not** need to install anything else: the other tools BIFROST needs
travel inside the app.

## Install the app

New versions are published as *releases* on GitHub, at
https://github.com/its-irb/irb-storage-public-scripts/releases .

1. Open that page and choose the latest release.
2. Download the file for your computer and the app you need:
   - **Windows**: the installer file ending in `.exe` (it is digitally signed).
     Run it and follow the installer.
   - **macOS**: the file ending in `.dmg`. Open it and drag the app to the
     **Applications** folder.
   - **Cluster (Linux)**: nothing to install. Bifrost transfer opens in your
     browser through Open OnDemand (see [web-mode-ood.md](web-mode-ood.md)).

The app **updates itself**: when you open it and a newer version exists, it
asks if you want to update, and downloads it if you accept.

## Sign in

1. Open the app.
2. Type your **IRB username and password**.
3. Choose the **MinIO server** that belongs to your research group.
4. Wait a moment: the app gets a temporary access pass for MinIO by itself. It
   lasts 7 days. Each time you sign in, if it has 3 days or less left (or you
   do not have one yet), the app renews it for 7 days by itself, showing a
   progress bar. You never have to type any keys.
5. You arrive at the main screen of the app:
   - **Bifrost transfer** → the copy screen
     (see [transfer-data.md](transfer-data.md)).
   - **Bifrost mount** → the mount screen
     (see [mount-buckets.md](mount-buckets.md)).

## Expected result

After signing in you see the copy screen (Bifrost transfer) or the mount screen
(Bifrost mount).

## Renew your MinIO access pass by hand

The app only renews the access pass by itself when you sign in. If you keep
the app open for several days, or you are about to start a long copy, renew it
by hand so it does not run out in the middle.

At the top of the mount screen and of the copy screen there is a label that
shows how long your access pass lasts, for example
**🔑 Credentials expire in 6d 23h** (6 days and 23 hours). It turns red when
less than 1 day is left and orange when 3 days or less are left.

1. Click **🔑 Renew credentials** (in the same row as that label, at the right
   end).
2. A small window opens. Next to **Renew for:**, type how many days you want
   (from 1 to 30; it shows 7 by default).
3. Click **🔄 Renew**. To close the window without renewing, click
   **Cancel**.
4. A screen shows the progress of the renewal. When it finishes, you go back to
   the screen where you were.

**Expected result**: the label at the top shows the new time left.

**If something goes wrong**:

- **Enter a value between 1 and 30 days.** or **Invalid number.**: type a whole
  number from 1 to 30 and click **🔄 Renew** again.
- If the renewal screen shows **❌ Connection error.** or **❌ Renewal failed.**,
  check that the Nexica VPN is on, close and open the app, sign in again and
  repeat. If it keeps failing, see [troubleshooting.md](troubleshooting.md).

## If something goes wrong

If you see a network or sign-in error, go to
[troubleshooting.md](troubleshooting.md).
