# Changelog

All notable changes to Kunji are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); Kunji is pre-1.0 so the
public surface (the `v1` password output) is stable but the tool around it may
still change shape.

The **`v1` derivation output never changes** — it is frozen by
`tests/vectors/v1.json`. Entries below only ever describe the tool, the vault
format (backward-compatibly), and new opt-in profiles.

## [Unreleased]

### Added
- Open-source documentation set: `LICENSE` (MIT), rewritten `README.md`,
  `docs/USAGE.md`, `docs/BUILD.md`, `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`,
  `SECURITY.md`, this changelog, and GitHub issue/PR templates.
- Header: "Kunji" wordmark as an inline SVG of Hanken Grotesk ExtraBold, and a
  decorative split-flap status readout (`src/readout.js`). Both stay within the
  no-network / single-file constraints. Design study in
  `docs/readout-studies.html`.

## [1.0.0] — 2026-09-01

First tagged release. Single self-contained `kunji.html`.

### Added
- **Deterministic generator**, profile `v1`: `PBKDF2-HMAC-SHA512` @ 600 000
  iterations → `HKDF-SHA256` per-entry seed → rejection-sampled password with
  character-class enforcement. Output frozen by `tests/vectors/v1.json`.
- **Key check value** indicator — a typo check on identity + passphrase.
- **Encrypted vault** (`kunji-data.json`): one AES-256-GCM envelope holding entry
  parameters, notes, TOTP secrets and recovery codes — never a derived password.
- **Account picker** on the Generate tab when a typed site matches vault entries.
- **Decoy vault** behind a second passphrase; file size and structure don't
  reveal that a decoy exists.
- **Sync merge** — tombstone-based, per-entry newest-edit-wins, with a one-screen
  summary. Move `kunji-data.json` with any tool you trust.
- **Whole-vault QR transfer** between devices with no shared channel.
- **Live TOTP** (RFC 6238) in an entry's detail view.
- **Passkey unlock** in the installed PWA — WebAuthn PRF wraps the vault key;
  per-device, never leaves the device; passphrase always still works.
- **Installable PWA build** (`dist/pwa/`) whose CSP still forbids all page
  network access.
- **Release integrity**: SHA-256 checksum + SSH signature per release, plus an
  independent CI rebuild that re-checks both.
- Profile registry in `derive.js` so a future KDF ships as `v2` without touching
  `v1`.

[Unreleased]: https://github.com/girishdighe/kunji/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/girishdighe/kunji/releases/tag/v1.0.0
