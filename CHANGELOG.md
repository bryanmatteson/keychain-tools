# Changelog

## kc-cli 0.4.1

- Accept traditional PKCS#1 RSA private keys in PEM or DER form anywhere an
  identity import accepts a private key, normalizing them to PKCS#8 for storage.

## keychain-rs 0.2.4

- Add `decode_private_key` as the canonical PEM/DER, PKCS#8/PKCS#1 RSA
  normalization entrypoint and use it for combined PEM identities.

## kc-cli 0.4.0

Breaking CLI changes:

- `kc create` now requires an explicit output path or keychain name.
- `-p` / `--password` now requires a value; omit the option to read from stdin
  or prompt.

The spaced and prompt-only forms of `--pkcs12-password`, `--new-password`, and
`--to-password` remain backward compatible. `kc-cli 0.3.3` briefly shipped the
new CLI surface under a patch version and is superseded by this release.

- Add keychain-wide `extended`, `native`, and `hybrid` access-policy primitives.
- Add `kc access set`, `show`, `clear`, `apply`, and `audit`, with explicit
  securityd projection and direct `allow`, `prompt`, or `deny` decisions.
- Add global `--interactive` confirmation for prompt-based direct reads.
- Inherit native/hybrid trusted-application policy when writing password items
  and identities.
- Add public ACL inspection and private-key ACL update entrypoints.
- Add visible uppercase metadata aliases while preserving existing lowercase
  flags and `kc trust -A`.

## keychain-rs 0.2.3

- Add public keychain-wide access-policy primitives.
- Add ACL inspection and private-key ACL update entrypoints.

## keychain-rs 0.2.2 / kc-cli 0.3.2

- Resolve bare keychain names through `~/Library/Keychains` and configured
  search paths, with `system` as a special case.
- Persist the default keychain and search paths in `~/.config/keychain.kdl`.
- Add direct, environment, file, generated, and prompted keychain-password
  sources plus generated-password character policies.
- Require an explicit output path for `kc create`.

## keychain-rs 0.2.1 / kc-cli 0.3.1

- Add first-class combined PEM and PEM/DER PKCS#12 identity import and export.
