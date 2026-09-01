# Kunji — user guide

This is the complete guide to using Kunji. If you just want to make a password
and go, the [README](../README.md#use-it-5-minute-version) has the short version.

- [The idea in one minute](#the-idea-in-one-minute)
- [Generating a password](#generating-a-password)
  - [The fields, one by one](#the-fields-one-by-one)
  - [The key check value (the green dot)](#the-key-check-value-the-green-dot)
  - [Copying, and the 25-second clear](#copying-and-the-25-second-clear)
  - [Changing a password later (the counter)](#changing-a-password-later-the-counter)
- [The vault](#the-vault)
  - [Creating a vault](#creating-a-vault)
  - [Unlocking a vault](#unlocking-a-vault)
  - [Adding and editing entries](#adding-and-editing-entries)
  - [Saving (the unsaved-changes bar)](#saving-the-unsaved-changes-bar)
  - [The account picker on the Generate tab](#the-account-picker-on-the-generate-tab)
- [The decoy vault](#the-decoy-vault)
- [Moving a vault between devices](#moving-a-vault-between-devices)
  - [Merging two copies](#merging-two-copies)
  - [QR transfer](#qr-transfer)
- [Two-factor (TOTP) codes](#two-factor-totp-codes)
- [Passkey unlock (installed app only)](#passkey-unlock-installed-app-only)
- [Backup and recovery](#backup-and-recovery)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)

---

## The idea in one minute

Most password managers **store** your passwords (encrypted) and sync that store
between devices. Kunji **derives** them instead. You give it four things:

```
identity  +  master passphrase  +  site  +  account   ──►   a strong password
```

The same four inputs always give the same output, so there is nothing to store
and nothing to sync. The password for `github.com` is not saved on your disk, in
a cloud, or in Kunji — it is *computed* the moment you ask, and forgotten the
moment you close the tab.

The trade-off: you must type (or let the vault remember) the site and account
names, and you can never "just change one password" without changing an input —
that's what the [counter](#changing-a-password-later-the-counter) is for.

## Generating a password

Open `kunji.html`. You start on the **Generate** tab.

### The fields, one by one

| Field | What to put | Notes |
|---|---|---|
| **Identity** | A fixed string that identifies you — most people use their email address. | This is a *namespace*, not a secret. Its only job is to make sure your derivations never collide with someone else's. Pick one and use it forever. |
| **Master passphrase** | The one strong secret you memorise. | Never stored. Cleared from the input the instant you press Generate. Length beats complexity — a memorable 5–6 word phrase is strong. This is the only thing whose loss loses your passwords. |
| **Site or app** | Where the password is used, e.g. `github.com`, `bank`, `wifi-home`. | Be consistent. `github.com` and `GitHub` derive different passwords. Pick a convention (bare domain is a good one). |
| **Account** | Which login on that site, e.g. `alice@example.com` or `personal`. | Leave blank if the site has only one login for you. Two accounts on the same site → different site... no: same site, different **account** → different password. |
| **Length** | How many characters. Default 20. | Some sites cap length; set it to their maximum. |
| **Rules** | Which character classes are allowed. | `Standard` (letters, digits, symbols) suits most sites. `Letters and digits` for sites that reject symbols. `Maximum symbols` for the paranoid and the permissive. |

Press **Generate**. The password appears in the result box in monospace.

### The key check value (the green dot)

Under the master passphrase field is a small dot and a short label. Once
**Identity** and **Master passphrase** are both filled, it turns green and shows
a few characters — the **key check value (KCV)**.

The KCV is derived from *only* your identity + passphrase. It is not your
password and reveals nothing useful, but it is stable: you will see the same KCV
every single time you type your passphrase correctly.

**Use it as a typo check.** Glance at the KCV before you press Generate. If it
isn't the value you always see, you have a typo in identity or passphrase — fix
it now, because generating with a wrong passphrase gives you a wrong password
with no warning.

(After a while you'll know your KCV by sight. Some people write it on a sticky
note — it's safe to, it can't be reversed into the passphrase.)

### Copying, and the 25-second clear

Press **Copy**. Kunji writes the password to your clipboard and starts a timer;
after **25 seconds** it overwrites the clipboard so a forgotten password doesn't
sit there for the next thing you paste. Copy again any time — the password is
still on screen until you navigate away or regenerate.

### Changing a password later (the counter)

Since the output is fixed by the inputs, "rotate this one password" means
"change one input on purpose". Kunji uses a **counter** for this: an integer,
starting at 1, that is part of the derivation.

- With a **vault**, each entry has a counter field — bump it from 1 to 2 and save.
- Without a vault, append it to the account name yourself, e.g. `alice` → `alice2`.

Bumping the counter gives a brand-new password from the same passphrase. Write
down which sites are past counter 1 (the vault does this for you).

## The vault

The vault is **optional**. It exists so you don't have to remember and retype
site names, account names, counters, lengths, and rules — and so you have a place
for 2FA secrets, recovery codes, and notes.

**The vault never contains a generated password.** It stores the *parameters*
that produce one. Someone who steals your vault file and cracks its encryption
learns your list of sites and your notes — they still cannot produce a password
without your master passphrase, which is not in the file.

The vault file is `kunji-data.json`: a single AES-256-GCM blob. Kunji does not
sync it, watch it, or phone home about it. You move it yourself (see
[Moving a vault between devices](#moving-a-vault-between-devices)).

### Creating a vault

1. Open the **Vault** tab.
2. Choose **Create vault**.
3. Enter your **identity** and **master passphrase** — use the *same* ones that
   drive the Generate tab. The vault is encrypted with a key derived from them.
4. The vault opens, empty. Add an entry (below), then **Save vault** — your
   browser downloads `kunji-data.json`. Put it wherever you keep it.

### Unlocking a vault

1. **Vault** tab → **Open vault file…** → pick your `kunji-data.json`.
2. Enter identity + master passphrase.
3. On success you see your entry list. On failure you get an error and nothing
   else — a wrong passphrase never returns partial or garbage data.

### Adding and editing entries

An entry has: **name** (usually the site), **account**, **counter**, **length**,
**rules**, optional **notes**, optional **TOTP secret**, optional **recovery
codes**.

- **Add entry** → fill the fields → it appears in the list.
- Click an entry to expand its detail view: regenerate its password, copy it,
  edit any field, see its live [TOTP code](#two-factor-totp-codes), or delete it.
- Editing a field that affects derivation (account, counter, length, rules)
  changes the password that entry produces — intentionally.

### Saving (the unsaved-changes bar)

Kunji does **not** auto-save. When you've made changes, a yellow **Unsaved
changes** bar appears. Press **Save vault** (in that bar, or in the footer row)
to download a fresh `kunji-data.json`. Replace your old file with it (or drop it
where your sync tool will pick it up).

If you close the tab with the bar showing, those changes are gone — there is no
background copy.

### The account picker on the Generate tab

When a vault is unlocked and you type a **Site** on the Generate tab that matches
one or more vault entries, Kunji shows a small "which account?" picker. Choose
one and it fills account, counter, length, and rules from that entry. This is the
everyday flow: unlock vault once, then generate by picking.

## The decoy vault

A **decoy vault** is a second, believable vault behind a *different* master
passphrase. It exists for the situation where someone can compel you to unlock
your vault: you give up the decoy passphrase, they see a plausible set of
accounts, and the file gives no indication that a real vault also exists.

- Set it from your **real** unlocked vault: press **Set up decoy…**, then
  **Create decoy** with a different identity/passphrase. Kunji switches you into
  the empty decoy — populate it with entries that look like a real life (a few
  email and shopping accounts), then **Save vault**.
- Switch between the two with the **Real / Decoy** toggle while unlocked. Later
  you can **Change decoy passphrase** or **Remove decoy** from the real vault.
- Opening `kunji-data.json` with the decoy passphrase opens the decoy vault and
  nothing in the file signals that a real vault also exists.
- The two vaults are independent. Changes to one never touch the other.

Notes and limits:

- The protection is *deniability*, not magic. If an adversary knows Kunji
  supports decoys, they know one might exist. It defends against "unlock it or
  else", not against a determined forensic adversary who has already read this
  page.
- Keep the decoy lived-in: log in to a couple of its accounts occasionally so
  timestamps look real.

## Moving a vault between devices

Kunji never syncs for you. You move one file, `kunji-data.json`, with a tool you
already trust. The transport only ever sees ciphertext. Full options and
recommendations are in **[docs/sync.md](sync.md)**; the essentials:

- **Syncthing** (recommended on desktop/Android): direct device-to-device, no
  cloud, no account. Put `kunji-data.json` in a shared folder set to *Send &
  Receive*.
- **A private git repo** containing *only* the vault file — never your source.
- **Manual**: AirDrop / email / USB the file across.
- **[QR transfer](#qr-transfer)** when the two devices share no channel at all.

### Merging two copies

If two devices both edited the vault before syncing, you have two `kunji-data.json`
files that disagree. Don't pick one and lose the other's edits — merge:

1. Unlock one copy in Kunji.
2. **Vault → Merge another copy…** → select the other file.
3. Kunji shows a one-screen summary: *added / updated / deleted here / deleted
   there / unchanged*. Merging is per entry, and the **newest edit wins** (Kunji
   tracks per-entry timestamps and keeps *tombstones* so a delete on one device
   isn't undone by an old copy).
4. Apply, then **Save vault**, then replace both copies with the merged file.

Syncthing writes conflicts as `kunji-data.sync-conflict-…json` next to your file
— that file is exactly what *Merge another copy…* is for.

### QR transfer

For two devices with no shared network or file channel (e.g. moving to a new
phone, or any iOS device where Syncthing doesn't exist):

1. **Source device:** unlock the vault → **Show as QR** (footer row).
2. **Target device:** on the Vault tab press **Scan QR…** (moving a whole vault
   to a fresh device), or, if you already have a vault open and want to fold this
   one in, **Scan QR to merge**. Point the camera at the source screen.
3. Large vaults are split across several animated QR frames — hold the camera
   steady until it reports complete.
4. The target device then asks for identity + passphrase as usual.

Nothing leaves the two screens. The camera never uploads anything.

## Two-factor (TOTP) codes

A vault entry can also hold a site's TOTP (authenticator-app) secret, so Kunji
shows the live 6-digit code next to the password.

1. When a site shows you its 2FA setup, copy the **secret key** (a base32 string)
   or the whole `otpauth://totp/...` URI.
2. In the entry's detail view, paste it into the **TOTP** field. Save.
3. The detail view now shows the current 6-digit code and a countdown bar. It
   updates every 30 seconds, computed locally with HMAC-SHA1 per RFC 6238.

Keeping the TOTP secret in the same vault as the password means one stolen,
cracked vault gives up both factors — that's a real trade-off. Use it when the
convenience matters more than second-factor separation for that account, and
keep truly critical accounts' 2FA in a separate device.

## Passkey unlock (installed app only)

In the **installed PWA** (not the loose HTML file), you can register a **passkey**
so a device unlocks the vault with its fingerprint or PIN instead of you typing
the master passphrase.

- **Enroll:** unlock the vault normally once, then **Vault → add passkey**. Your
  OS prompts for the biometric/PIN and creates a device-bound credential.
- **Use:** on later visits, choose **Unlock with passkey** → biometric → vault
  opens.
- The master passphrase **always still works** — the passkey is an alternative,
  not a replacement.
- The passkey is **per-device and never leaves it**. Enroll separately on each
  device. It is bound to that PWA install; clearing site data removes it.
- It wraps the vault key with a secret held by the authenticator (WebAuthn PRF).
  Kunji never sees your biometric.

## Backup and recovery

- **The real backup is your memory.** If you know your identity, master
  passphrase, and each site's convention (site name, account, counter), you can
  reproduce every `v1` password on a fresh download of Kunji with no vault at
  all. Test this once so you believe it.
- **Back up the vault file** like any important file — it's just ciphertext, so a
  cloud drive or a couple of USB sticks is fine. Losing it loses your *notes and
  convenience*, not your passwords (as long as you remember the counters).
- **Recovery codes** for a site go in that site's vault entry, or on paper. Kunji
  does not treat them specially.
- **There is no "forgot passphrase".** No reset, no recovery email, because there
  is no server and nothing stored. A forgotten master passphrase is unrecoverable
  by design. Choose something you will not forget, and consider a sealed paper
  copy in a safe place.

## FAQ

**Is it safe that the tool is a single downloadable file?**
That's the point. There's no install, no auto-update, no extension permissions.
[Verify the signature](../README.md#verify-what-you-downloaded) once and you know
exactly what you're running. It never changes under you.

**What if two people use the same master passphrase?**
Their **identity** strings differ, so their derived passwords differ. That's what
identity is for. (Also: don't share passphrases.)

**Can I change my identity later?**
You can, but every password re-derives, so you'd have to update every site. Treat
identity as permanent. If you must migrate, do it site-by-site using the vault to
track progress.

**Does the counter start at 0 or 1?**
1. Counter 1 is the original password for an entry. Bump to 2, 3, … to rotate.

**Why did my password come out different today?**
Almost always a typo — check the [KCV](#the-key-check-value-the-green-dot). Or an
input changed: different site spelling, different account, different length or
rules, or the counter moved.

**Can I use it offline / on a plane / air-gapped?**
Yes. That's the default. It makes zero network requests and the CSP forbids them
even if it tried.

**Does it work on iPhone?**
Yes — open `kunji.html` in Safari, or install the PWA. Syncthing isn't available
on iOS, so use QR transfer or a git client to move the vault.

**Is there a browser extension / autofill?**
No. Copy-paste, with the 25-second clipboard clear. An extension would mean
permissions and an attack surface Kunji is built to avoid.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Password is different from what I expect | Typo in passphrase or identity (check KCV); or site/account spelling changed; or length/rules/counter changed. |
| "Failed to unlock vault" | Wrong identity or passphrase for *this* file; or the file was truncated/corrupted in transit. Try your backup copy. |
| Vault changes vanished | You closed the tab without **Save vault** while the yellow "unsaved changes" bar was showing. There is no autosave. |
| QR scan never completes | Poor lighting or camera focus; source screen brightness too low; frames scrolling too fast — keep both still and try again. |
| Passkey option isn't there | You're using the loose HTML file. Passkeys need the installed PWA. |
| TOTP code rejected by the site | Device clock is off — TOTP depends on accurate time. Sync your clock. |
| "which account?" picker doesn't appear | Vault isn't unlocked, or the Site text doesn't match an entry name. |
| PWA still shows an old version | Close all its tabs/windows and reopen, or reinstall — the service worker updates on next launch. |

Still stuck? Open an issue (see [CONTRIBUTING.md](../CONTRIBUTING.md)) — but never
paste your master passphrase, vault file, or a real generated password into it.
