# Syncing a vault across devices

Kunji never syncs for you. You move one file — `kunji-data.json` — with whatever
tool you already trust.

## What actually moves

Just `kunji-data.json`. It is one AES-256-GCM blob: the transport (Syncthing, a
git repo, an email attachment) only ever sees ciphertext. If two devices both
edited the vault, open one copy on the other device via **Vault → Merge another
copy…** — Kunji shows a one-screen summary (added / updated / deleted here /
deleted there / unchanged) and merges per entry, newest edit winning.

## Recommended: Syncthing

No cloud, no account, direct device-to-device.

1. Install Syncthing on every device (desktop app, or the Android app; **not
   available on iOS** — see below).
2. On one device, put `kunji-data.json` in its own folder and add that folder to
   Syncthing.
3. Share the folder to each other device; accept on each. Set the folder type to
   **Send & Receive** everywhere.
4. Edit the vault on any device; Syncthing propagates the new blob within seconds.

When two devices edit before syncing, Syncthing keeps both and writes a
`kunji-data.sync-conflict-<date>-<device>.json` beside your file. That conflict
file is exactly what **Merge another copy…** is for: open it, review the summary,
apply, save, then delete the conflict file.

**iOS / iPadOS:** there is no Syncthing. Use QR transfer (below) or a private git
client (e.g. Working Copy) instead.

## Private git repo

For the technically inclined: a git repo **separate from the public Kunji repo**,
containing only `kunji-data.json` (and nothing else — never your source).

- Before editing: `git pull`.
- After saving from Kunji: `git add kunji-data.json && git commit -m "vault" && git push`.

If a push is rejected because the remote moved, `git pull` produces a merge
conflict on the blob; discard git's merge, keep either side, then reconcile
inside Kunji with **Merge another copy…** against the other revision.

## Manual: file or QR

No infrastructure at all.

- **File:** email or AirDrop or USB-copy `kunji-data.json` to the other device,
  then open it in Kunji.
- **QR:** on the source device, unlock the vault and choose **Show as QR**; on the
  target device, choose **Scan QR…** and point the camera. Large vaults animate
  across several frames — hold steady until it completes. The target device then
  asks for the passphrase as usual.

## Whichever you pick

- It only ever moves an encrypted blob. A compromised sync channel leaks nothing
  a stolen file wouldn't.
- Losing the sync channel loses convenience, not data — every unlocked device can
  re-export the whole vault.
- Keep one device's copy as the reference in your head, so a merge decision is
  always "does this other copy have anything I want?" rather than "which of these
  is real?".
