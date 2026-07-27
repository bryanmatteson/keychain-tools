# Changelog

## Unreleased

## kc-cli 0.6.1

- Switch the published library dependency from `keychain-rs` to
  `keychain-db`. The CLI and its command surface are unchanged.

## keychain-db 0.2.6

- Continue the `keychain-rs 0.2.6` API under its canonical package name,
  `keychain-db`. The Rust library target remains `keychain`, so imports are
  unchanged.

## kc-cli 0.6.0

Breaking CLI changes:

- Replace `show`, `find`, and `ls` with one multi-item `get` command and typed
  ANDed predicates. Add comparisons, SQL-LIKE wildcards, Unicode case and
  diacritic modifiers, ordered `-o` projections, full detail, JSON, and guarded
  secret projections.
- Add `-u, --distinct` for stable, typed deduplication of projected row tuples.
- Replace selector-based item updates with
  `kc set NAME=VALUE... --for EXPRESSION`. Add atomic reference pipelines with
  `kc get -o @ref | kc set ... --for -`; opaque references bind the keychain,
  database revision, record class, and record number.
- Add the canonical assignment form
  `kc add class=generic account=... service=...`, with class-aware validation.
- Add `KC_DEFAULT_KEYCHAIN` between an explicit keychain and the saved default,
  and report the effective default and source from `kc config show`.
- Standardize direct keychain passwords on `-P`; `--port` is no longer
  overloaded with a password short.

## keychain-rs 0.2.6

- Add the public `Expression`, `Predicate`, `Comparison`, and `MatchOptions`
  query model plus `KeychainFile::select`.
- Add opaque, revision-bound `ItemRef` values with encode/decode, inspection
  accessors, and `KeychainFile::item_ref` / `resolve_ref`.
- Add typed dates, numbers, booleans, four-character codes, SQL-LIKE matching,
  and Unicode case/diacritic normalization to library queries.

## kc-cli 0.5.0

Breaking CLI change:

- `kc create` now saves a `hybrid` / `prompt` access policy by default. Direct
  secret reads require `--interactive`, and new native item ACLs pre-authorize
  no application so securityd prompts every caller. Use `--no-access-policy`
  for the previous unmanaged allow-any behavior.

- Add `--access-mode` and `--access-default` to select a keychain's initial
  policy.
- Let prompt policies project to securityd without naming a trusted
  application, matching the ACL Apple writes for `security -T ""`.
- Add `kc trust --prompt` for setting that native ACL on one item.
- Distinguish allow-any, prompt, and trusted-application ACLs during access
  audits and policy inheritance.
- Resolve explicit relative keychain paths to stable absolute selectors and use
  collision-free temporary config files.

## keychain-rs 0.2.5

- Add `ApplicationAccess` and explicit add, edit, and audit entrypoints that
  distinguish allow-any, prompt-every-caller, and trusted-application ACLs.
- Parse and reproduce Apple's zero-subject prompt ACL byte-for-byte.
- Preserve the existing empty-means-allow-any behavior of legacy trust methods.

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
