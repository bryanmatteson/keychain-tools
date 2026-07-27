# kc-cli

`kc` creates, queries, and updates macOS `.keychain-db` files directly. It does
not call the Security framework, require entitlements, or depend on a running
`securityd`. The files remain interoperable with Keychain Access and
`/usr/bin/security`.

The Rust library is [`keychain-db`](../keychain/README.md). This crate provides
the `kc` command.

## Install

```sh
cargo install kc-cli
```

## Keychain selection

Every command that accepts `--keychain` resolves keychains in this order:

1. explicit `--keychain KEYCHAIN` or a command's explicit keychain argument;
2. `KC_DEFAULT_KEYCHAIN`;
3. `keychains.default` in `~/.config/keychain.kdl`;
4. `login`.

Bare names are searched under `~/Library/Keychains` and then under configured
search paths. `machina` therefore resolves to
`~/Library/Keychains/machina.keychain-db`; `system` is the system keychain.
Paths containing `/` are treated as paths.

```sh
kc config set keychains.default machina
kc config set search.paths "path1" "path2"
kc config append search.paths "path3"
kc config prepend search.paths "preferred"
kc config show

export KC_DEFAULT_KEYCHAIN="$PWD/secrets.keychain-db"
```

`config show` reports both the saved default and the effective default with its
source.

## Create and add

Creation always requires an output path or name:

```sh
kc create ./secrets.keychain-db
kc create --password-gen --password-policy secure ./secrets.keychain-db
```

Password items use one assignment grammar:

```sh
kc add \
  class=generic \
  label=machina-vpn-operator \
  account=machina \
  service=cloudflare \
  kind="api key" \
  comment="a vpn operator" \
  --keychain ./secrets.keychain-db

kc add \
  class=internet \
  label="Gmail Account" \
  account=bryan@example.com \
  server=imap.gmail.com \
  port=443 \
  kind=password
```

Supported classes are `generic`, `internet`, and `appleshare`. Friendly field
names and native aliases are interchangeable: `account`/`acct`,
`service`/`svce`, `comment`/`icmt`, and so on. Class-invalid assignments are
errors.

When `-w, --secret` is absent, the item secret is read from stdin or prompted
for on a terminal.

Identities retain a purpose-built form because their inputs are files:

```sh
kc add identity -c certificate.pem -k private-key.der -l "MDM Push" login
kc add identity --pkcs12 identity.p12 login
kc import identity combined.pem login
```

Certificate and private-key inputs accept PEM or DER by content, regardless of
file extension. Private keys may be PKCS#8 or RSA PKCS#1. PKCS#12/PFX accepts
DER or PEM and has independent `--pkcs12-password*` inputs.

## Get

`get` is the only item read command. With no predicates it returns all
queryable password, certificate, public-key, private-key, and item-key records.

```sh
kc get
kc get class:internet label:"Gmail Account" kind:"api key"
kc get \
  'class:internet label:"Gmail Account" kind:"api key" icmt:%2026%'
kc get class:internet label:"Gmail Account" 'icmt:%2026%'
```

Predicates are ANDed. The canonical grammar is:

```text
FIELD:VALUE
FIELD:>=VALUE
FIELD[MODIFIERS]:PATTERN
```

Comparisons are `=`, `!=`, `<`, `<=`, `>`, and `>=`. A value containing `%` or
`_` uses SQL-LIKE semantics: `%` matches any sequence and `_` matches one
character. Backslash escapes a wildcard. `[c]` is case-insensitive, `[d]` is
diacritic-insensitive, and `[cd]` enables both.

Examples:

```sh
kc get \
  'cdat:<20260515074219Z' \
  'mdat:>=20250515074219Z' \
  'icmt:%2026%' \
  'label[cd]:com.%'
```

Dates accept Keychain UTC timestamps (`YYYYMMDDhhmmssZ`) and RFC 3339 UTC
timestamps. Numeric and boolean fields are compared as their actual types.
Unknown modifiers, malformed comparisons, invalid typed values, and unknown
exact class names are errors.

### Projection

`-o, --output` selects ordered fields:

```sh
kc get \
  class:generic account:machina service:vpn \
  -o label,kind,account,service

kc get class:internet -o '*'
kc --json get class:internet -o account,server,port
```

`-u, --distinct` emits each projected tuple once while preserving first-seen
order. Deduplication uses typed projected values before text or JSON rendering:

```sh
# Unique non-empty service values
kc get 'service:_%' -o service --distinct

# Unique account/service pairs
kc get 'service:_%' -o account,service -u
```

`service:%` also matches an empty service; `service:_%` requires at least one
character. The query language intentionally uses `%` rather than shell-glob
`*`.

`*` emits full record detail. `secret` decrypts the selected item. More than
one secret requires `--all`; non-secret queries intentionally allow multiple
rows.

```sh
kc get class:generic account:machina -o secret
kc --format secret get class:generic account:machina
kc get class:generic -o secret --all
```

`@ref` emits opaque, revision-bound item references for mutation pipelines:

```sh
kc get class:internet 'account[c]:bryan%' -o @ref |
  kc set label=updated --for -
```

References carry their keychain and database revision. `set` validates the
complete stream before changing memory and saves once. A malformed, duplicate,
wrong-keychain, missing, or stale reference aborts the operation without
writing. Human-readable and JSON output are never reparsed as selectors.

## Set

`set` applies assignments to every item matched by `--for`:

```sh
kc set label=updated comment="rotated in 2026" \
  --for 'class:internet account[c]:bryan%'
```

The query must be non-empty. `class`, `record`, `secret`, creation time, and
modification time cannot be changed. Attributes that define a relation's unique
identity are rejected by the library; replacing those means deleting and
adding an item.

Updates are collected first, applied in memory, and saved once. A failure
before the save leaves the file unchanged.

## Password input

All keychain-password consumers use the same sources:

```text
-E, --password-env [ENV_VAR]       default ENV_VAR: KC_PASSWORD
-F, --password-file FILE           use - for stdin
    --password-gen[=TEMPLATE]       creation/change only; default: sha1
-P, --password PASSWORD
    --password-policy POLICY        alphanumeric|mixed-case|symbol|secure
```

When no source is set, `kc` reads the password from stdin or prompts on a
terminal. Environment variables and files avoid exposing secrets in process
arguments. If `-P` is useful for shell composition, prefer a shell expression:

```sh
kc get class:generic account:alice -o secret \
  -P "$(secret-tool lookup kc login)"
```

## Access policy and native ACLs

New keychains default to a saved `hybrid` policy whose direct and native
decision is `prompt`. Direct secret access therefore requires `--interactive`;
native ACLs pre-authorize no caller, allowing `securityd` to show its normal
authorization UI.

```sh
kc access show machina
kc access set --mode hybrid --default prompt machina
kc access apply --to securityd machina
kc access audit --against securityd machina
```

`extended` enforces the `kc` policy only, `native` delegates to item ACLs, and
`hybrid` does both. Keychain-wide policy is projected onto items when they are
written and can be reapplied to existing items. Native Keychain ACLs are still
item-level data; the saved keychain policy is the template and enforcement
model for all items.

For individual legacy operations, `kc trust` supports:

```sh
kc trust -a alice -T /Applications/MyApp.app login
kc trust -a alice --trust-requirement \
  /Applications/MyApp.app=requirement.bin login
kc trust -a alice --prompt login
kc trust -a alice -A login
```

`--trust-requirement PATH=FILE` stores the compiled code requirement while the
legacy cdhash remains optional. This preserves Security.framework
interoperability while allowing stronger application identity.

## Identity import and export

```sh
kc export cert -l "MDM Push" -o certificate.pem login
kc export key -l "MDM Push" -o private-key.pem login
kc export identity -l "MDM Push" -o identity.pem login
kc export identity -l "MDM Push" --pkcs12 -o identity.p12 login
kc export identity -l "MDM Push" --pkcs12 --pem -o identity.p12.pem login
```

An explicit output path is recommended for exported secret material. PKCS#12
exports are encrypted with the selected PKCS#12 password.

## Other commands

```text
kc info [KEYCHAIN]
kc verify [KEYCHAIN]
kc rm item SELECTOR [--all] [KEYCHAIN]
kc rm identity [-l LABEL | --hash HEX] [KEYCHAIN]
kc cp SELECTOR SOURCE DESTINATION
kc passwd [KEYCHAIN]
kc settings [OPTIONS] [KEYCHAIN]
kc completions SHELL
```

`show`, `find`, and `ls` were removed in 0.6.0. Their behavior is represented
by `get`, projections, and an empty query.

## Output and exit status

Text is the default. `--json` is shorthand for `--format json`;
`--format secret` emits only secret bytes suitable for a pipeline.

Common exit statuses are stable:

```text
0   success
44  no item matched
45  incorrect keychain password
46  duplicate item
2   command-line or other operational error
```

## Development

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
mise run verify
```

The release order is `keychain-db` first, then `kc-cli`.

## License

MIT
