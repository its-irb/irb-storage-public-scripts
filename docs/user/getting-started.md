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
   - **Windows**: the file ending in `.zip` (your browser will not warn you
     about it). Unzip it and run the `.exe` inside, which is the installer
     (it is digitally signed). Follow the installer.
   - **macOS**: the file ending in `.dmg`. Open it and drag the app to the
     **Applications** folder.
   - **Cluster (Linux)**: nothing to install. Bifrost transfer opens in your
     browser through Open OnDemand (see [web-mode-ood.md](web-mode-ood.md)).

The app **updates itself**: when you open it and a newer version exists, it
asks if you want to update, and downloads it if you accept. On the cluster
(Open OnDemand) it never asks: there ITS keeps the app up to date for you.

## Sign in

1. Open the app.
2. Type your **IRB username and password**.
3. What comes next depends on the app:
   - **Bifrost transfer**: choose the **MinIO server** that belongs to your
     research group. Wait a moment: the app gets a temporary access pass for
     MinIO by itself. It lasts 7 days. Each time you sign in, if it has 3 days
     or less left (or you do not have one yet), the app renews it for 7 days by
     itself, showing a progress bar. Then you arrive at the copy screen (see
     [transfer-data.md](transfer-data.md)).
   - **Bifrost mount**: you arrive at the list of MinIO servers, with one card
     per server (see [mount-buckets.md](mount-buckets.md)). You do not choose a
     server here. Each server has its own access pass: the app gets it, or
     renews it for 7 days if it has 3 days or less left, by itself when you
     mount that server, showing a progress bar.

   You never have to type any keys.

## Expected result

After signing in you see the list of MinIO servers (Bifrost transfer, to choose
one, and then the copy screen; Bifrost mount, one card per server).

At the top of every screen:

- on the right, **Signed in as** and your username;
- on the left, a button to go back to the previous screen. On the list of
  servers it is **Back to login**, which takes you back to the sign-in screen.
  In Bifrost mount, the servers you mounted stay mounted.

## Renew your MinIO access pass by hand

Bifrost transfer only renews the access pass by itself when you sign in, and
Bifrost mount only when you mount a server. If you keep the app open for
several days, or you are about to start a long copy, renew it by hand so it
does not run out in the middle.

A label with a key shows how long your access pass lasts, for example
**Credentials expire in 6d 23h** (6 days and 23 hours). In Bifrost transfer
it is on the card of the server, at the top of the copy screen; in Bifrost
mount there is one on each server's card, because each server has its own
pass. It turns red when less
than 1 day is left and orange when 3 days or less are left.

1. Click **Renew credentials**: in Bifrost transfer, on the card of the server
   at the top of the copy screen, at the right end; in Bifrost mount, on the
   card of the server.
2. A small window opens. Next to **Renew for:**, type how many days you want
   (from 1 to 30; it shows 7 by default).
3. Click **Renew** (or press Enter). To close the window without renewing,
   click **Cancel**.
4. A screen shows the progress of the renewal. When it finishes, you go back to
   the screen where you were (in Bifrost mount, the list of servers; renewing
   does not mount the server). You do not have to wait: **Back to copy**
   (Bifrost transfer) or **Back to servers** (Bifrost mount), at the top left,
   takes you back at any moment.

**Expected result**: the label (at the top of the copy screen, or on the
server's card) shows the new time left.

**If something goes wrong**:

- **Enter a value between 1 and 30 days.** or **Invalid number.**: type a whole
  number from 1 to 30 and click **Renew** again.
- If the renewal fails (for example **Cannot connect to MinIO — Connection
  problem**), the renewal screen says what happened and, in the **What you can
  do** box, what to do (usually: check that the Nexica VPN is on). Then click
  **Try again**. You can also go back with **Back to copy** or **Back to
  servers**: you do not need to close the app. This also applies when the app
  renews the pass by itself (when you choose a server in Bifrost transfer, or
  mount one in Bifrost mount).
- If it says **Wrong username or password**, click **Back to login** and sign in
  again.
- If it keeps failing, send ITS the **error code** shown on that screen (the
  button next to it copies it); see [troubleshooting.md](troubleshooting.md).

## If something goes wrong

If you see a network or sign-in error, go to
[troubleshooting.md](troubleshooting.md).
