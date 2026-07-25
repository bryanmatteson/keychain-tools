# Changelog

## keychain-rs 0.2.3 / kc-cli 0.3.3

- Add keychain-wide `extended`, `native`, and `hybrid` access-policy primitives.
- Add `kc access set`, `show`, `clear`, `apply`, and `audit`, with explicit
  securityd projection and direct `allow`, `prompt`, or `deny` decisions.
- Add global `--interactive` confirmation for prompt-based direct reads.
- Inherit native/hybrid trusted-application policy when writing password items
  and identities.
- Add public ACL inspection and private-key ACL update entrypoints.
- Add visible uppercase metadata aliases while preserving existing lowercase
  flags and `kc trust -A`.

## keychain-rs 0.2.2 / kc-cli 0.3.2

- Resolve bare keychain names through `~/Library/Keychains` and configured
  search paths, with `system` as a special case.
- Persist the default keychain and search paths in `~/.config/keychain.kdl`.
- Add direct, environment, file, generated, and prompted keychain-password
  sources plus generated-password character policies.
- Require an explicit output path for `kc create`.

## keychain-rs 0.2.1 / kc-cli 0.3.1

- Add first-class combined PEM and PEM/DER PKCS#12 identity import and export.
