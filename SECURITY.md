# Security Policy

These tools handle passwords and keychain material. Treat reports seriously.

## Supported versions

- **`keychain-db`** / **`kc-cli`**: the latest published crates.io release of each
  is supported for security fixes.
- **`apwh`**: the latest commit on `main` in this repository (not published to
  crates.io).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

Use [GitHub private vulnerability reporting](https://github.com/bryanmatteson/keychain-tools/security/advisories/new)
on this repository, and include:

- affected crate/tool and version (or commit)
- a clear description of the issue
- steps to reproduce, or a proof of concept if you have one
- impact (credential disclosure, integrity, local privilege, etc.)

You should receive an acknowledgment within a few days. Once a fix is ready, a
coordinated disclosure timeline can be agreed.

## Scope notes

- **`keychain-db` / `kc`** read and write keychain files directly. Anyone with
  filesystem access to a keychain file and its password can decrypt its contents
  — that is by design, not a vulnerability in the format parser.
- **`apwh`** talks to Apple's Passwords helper. Issues that only reproduce because
  of Apple's launch constraints or helper behavior should be reported to Apple
  unless this crate mishandles the protocol or local secrets.
