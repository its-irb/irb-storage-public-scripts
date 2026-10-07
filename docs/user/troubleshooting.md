# Fix common problems

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

## I lost the log of a copy (cluster)

- In the browser you only see the **last lines**. The **full log** is saved on
  the cluster server, in `~/bifrost-logs/`, when each copy or check ends.
- If you were disconnected, the log is still there.

## The app asks about an update

The app updates itself: if a new version exists on GitHub, it asks if you want
to install it. Accept to get the latest version, or wait; it asks again later.

**Intel Macs:** if you are still on an older version of the app, the in-app
update may offer a build that does not run on your Mac. In that case, download
the file ending in `-macos-intel.dmg` once from
[the releases page](https://github.com/its-irb/irb-storage-public-scripts/releases)
and install it; from then on the app will update itself.

## Errors when applying labels (Tag Manager)

1. Read the **log** on screen: it usually shows permission or access errors.
2. The app renews its MinIO access by itself; start the operation again.
3. If it persists, ask your group's data manager to check your permissions on
   that folder.

## It is still not solved

Contact the team that maintains BIFROST at the IRB and send:

- the **app** (Bifrost transfer or Bifrost mount) and its **version**;
- your **operating system**;
- the exact **error message** and, if you can, a piece of the **log**.
