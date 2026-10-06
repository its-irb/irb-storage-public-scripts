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
   lasts 7 days and renews automatically when it is about to expire, showing a
   progress bar. You never have to type any keys.
5. You arrive at the main screen of the app:
   - **Bifrost transfer** → the copy screen
     (see [transfer-data.md](transfer-data.md)).
   - **Bifrost mount** → the mount screen
     (see [mount-buckets.md](mount-buckets.md)).

## Expected result

After signing in you see the copy screen (Bifrost transfer) or the mount screen
(Bifrost mount).

## If something goes wrong

If you see a network or sign-in error, go to
[troubleshooting.md](troubleshooting.md).
