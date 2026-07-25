# kc-cli — `kc` for macOS keychain files

The `kc` binary (crate [`kc-cli`](https://crates.io/crates/kc-cli)) creates, reads, and updates macOS `.keychain-db` databases without using the
Security framework or `securityd`. The file format implementation lives in
[`keychain-rs`](https://crates.io/crates/keychain-rs); this crate is the CLI.

It works in environments where the system APIs are unavailable or
impractical—for example, over SSH, in CI, or with a keychain copied from
another Mac.

The implementation is interoperable with Apple's tooling:

- Keychains created by `kc` can be unlocked, searched, read, and updated with
  `security`.
- Keychains created by `security` can be read and updated with `kc`, and remain
  usable with `security` afterward.

```console
$ kc create ~/demo.keychain
Keychain password: ····
Confirm: ····
created /Users/you/demo.keychain

$ kc add generic -a alice -s github.com -D token ~/demo.keychain
Keychain password: ····
Secret: ····
Confirm: ····
stored

$ security find-generic-password -a alice -s github.com -w ~/demo.keychain
gh-token-abc
```

The final command uses Apple's `security` tool to read an item written by
`kc`.

## Commands

```text
kc create [--idle-timeout SECS] [--no-lock-on-sleep] FILE
kc info FILE
kc show [-d] [--all] FILE
kc ls FILE
kc verify FILE

kc add generic     -a ACCOUNT -s SERVICE [-w SECRET] [-l LABEL] [-D KIND]
                   [-j COMMENT] [-G GENERIC] [-T APP]... FILE
kc add internet    -a ACCOUNT -s SERVER [-w SECRET] [-l LABEL] [-D KIND]
                   [-j COMMENT] [-S DOMAIN] [--path PATH] [-P PORT]
                   [-r PROTOCOL] [-t AUTHTYPE] [-T APP]... FILE
kc add appleshare  -a ACCOUNT -v VOLUME [-w SECRET] [-l LABEL] [-D KIND]
                   [-j COMMENT] [-s SERVER] [--address ADDR]
                   [--signature SIG] [-T APP]... FILE
kc add identity    -c CERT -k KEY [-l LABEL] [-T APP]... FILE

kc find generic    [-a ACCOUNT] [-s SERVICE] [-l LABEL] [-D KIND]
                   [-j COMMENT] [-G GENERIC] [--attr NAME=VALUE]... [-w] FILE
kc find internet   [-a ACCOUNT] [-s SERVER] [-S DOMAIN] [--path PATH]
                   [-P PORT] [-l LABEL] [-D KIND] [-j COMMENT]
                   [--attr NAME=VALUE]... [-w] FILE
kc find appleshare [-a ACCOUNT] [-v VOLUME] [-s SERVER] [--address ADDR]
                   [--signature SIG] [-l LABEL] [-D KIND] [-j COMMENT]
                   [--attr NAME=VALUE]... [-w] FILE
kc find identity   [-l LABEL] FILE

kc set             SELECTOR [-w [SECRET]] [--set-label NAME] [--set-kind KIND]
                   [--set-comment TEXT] [--set-generic BYTES]
                   [--set NAME=VALUE]... FILE
kc rm item         SELECTOR [--all] FILE
kc rm identity     [-l LABEL] [--hash HEX] FILE
kc rm cert         [-l LABEL] [--hash HEX] FILE
kc trust           SELECTOR (-T APP... | --trust-requirement PATH=FILE... | -A) FILE
kc cp              SELECTOR [--to-password-env NAME] [--to-password-file FILE]
                   [-T APP]... SOURCE DESTINATION
kc export cert     [-l LABEL] [--der] [-o FILE] KEYCHAIN
kc export key      [-l LABEL] [--der] [-o FILE] KEYCHAIN
kc export identity [-l LABEL] [-o FILE] KEYCHAIN
kc passwd          [--new-password-env NAME] [--new-password-file FILE] FILE
kc settings        [-t SECONDS | --no-timeout] [-l | --no-lock-on-sleep] FILE

kc completions SHELL
```

`SELECTOR` is the same set of flags for every mutating command — the way `find`
names an item, in one place:

```text
[-c generic|internet|appleshare] [-a ACCOUNT] [-s SERVICE] [--server HOST]
[--security-domain REALM] [--path PATH] [-P PORT] [-v VOLUME] [--label NAME]
[--kind KIND] [--comment TEXT] [--generic BYTES] [--attr NAME=VALUE]...
```

A mutation with no selector is refused rather than applied to whatever happens
to be first, and one that matches more than one item is refused unless the
command takes `--all`.

### Changing what is already there

```bash
kc set -a alice -w                      ~/demo.keychain   # prompt for a new secret
kc set -a alice --set-comment "rotated" ~/demo.keychain   # attributes only, no password needed
kc rm item -a alice                     ~/demo.keychain
kc trust -a alice -T /usr/bin/security  ~/demo.keychain   # restrict, or -A for any application
kc cp -a alice ~/demo.keychain ~/other.keychain
kc passwd ~/demo.keychain
kc settings -t 900 ~/demo.keychain
```

An update keeps the item's record, its record number and its item key, preserves
`cdat`, and moves `mdat`; only the payload is re-sealed, under a fresh IV.
Attributes that identify the item — the ones in its relation's unique index,
such as `acct` and `svce` — are refused: changing one makes it a different item,
which is a delete and an add.

`kc rm item` deletes the item **and** the key record that protects it, exactly as
macOS does; `kc rm cert` deletes a certificate and leaves its private key behind,
the way `security delete-certificate` does, while `kc rm identity` removes both.

`kc passwd` keeps the database's master keys and re-seals them under the new
password with a fresh salt and IV, so every existing item stays readable. It
refuses before writing anything if the old password is wrong.

### Supplying the keychain password

Commands that decrypt or modify data accept the keychain password from one of
three mutually exclusive sources:

```bash
kc find generic -a alice -w -e KC_PASSWORD ~/demo.keychain
kc find generic -a alice -w -f ~/.kc-pw    ~/demo.keychain
kc find generic -a alice -w -f -           ~/demo.keychain
```

- `-e NAME` reads the password from an environment variable.
- `-f FILE` reads the first line of a file.
- `-f -` reads the password from standard input.

Without either option, `kc` reads from standard input when it is connected to a
pipe and prompts when it is connected to a terminal.

There is no option that places the keychain password directly in the process
arguments. Command arguments are visible to other processes and are often
retained in shell history. The optional `-w SECRET` form for an item secret has
the same exposure; omit it to read the secret interactively or from standard
input.

### Querying attributes

`--attr NAME=VALUE` filters on any attribute printed by `kc show`. Attribute
names and rendered values use the same representation in both commands, so a
filter such as `--attr ptcl=htps` works even though the protocol is stored as
an integer. Repeat the option to require multiple attributes.

### Adding identities

`kc add identity` accepts a certificate and an unencrypted PKCS#8 private key
in PEM or DER form. It does not parse PKCS#12 bundles directly. A bundle can be
split first:

```bash
openssl pkcs12 -in bundle.p12 -nokeys -out cert.pem
openssl pkcs12 -in bundle.p12 -nocerts -nodes |
  openssl pkcs8 -topk8 -nocrypt -out key.pem

kc add identity -c cert.pem -k key.pem ~/demo.keychain
```

### Output formats

`--format` controls command output:

- `text` prints aligned field lists and is the default.
- `json` prints a stable JSON envelope.
- `secret` prints only the decrypted secret.

`--json` is shorthand for `--format json`. On `find`, `-w` is shorthand for
secret-only output. On `show`, `--format secret` prints one secret per item and
implies `-d`.

```bash
kc find generic -a alice --format secret ~/demo.keychain | pbcopy
kc --format json find internet -s example.com ~/demo.keychain |
  jq .item.port
```

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `44` | No item matched |
| `45` | Wrong password or locked keychain |
| `46` | Duplicate item |
| `1` | Other error |

Item attributes are not encrypted and can be read without the password.
Decrypting secrets requires it:

```bash
kc show ~/demo.keychain
kc show -d ~/demo.keychain
```

### Verification

`kc verify` checks the parts of the database that can be validated by a reader:

- the database blob signature;
- every key blob signature;
- the presence and successful unwrapping of each item's key; and
- complete understanding of every index region.

```console
$ kc verify ~/demo.keychain
database signature   ok
key signatures       2/2 verified
items readable       2/2
index regions        11/11 understood
```

## File format

The container format is documented in
[dtformats: MacOS keychain database file format](https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20keychain%20database%20file%20format.asciidoc).
Multibyte values are big-endian.

```text
file header (20 bytes: "kych", version, tables offset)
tables array: size, count, count × offset
  table: header (28 bytes), record-slot array, records, index region
    record: header (24 bytes), attribute offsets, key data, attributes
commit counter (u32 following the tables array)
```

A keychain is a CSSM database with a self-describing schema. Four schema tables
define the attributes of the remaining relations. `kc` reads that schema rather
than hard-coding password and key-record layouts.

Several format details are particularly important:

| Detail | Representation |
| --- | --- |
| Attribute order | The attribute-offset array follows schema-table order, not attribute-ID order. |
| Attribute names | Password relations generally use four-character codes such as `acct`, `svce`, and `srvr`; `PrintName` and `Alias` use string names. |
| Offsets | Attribute offsets are relative to the record and have their low bit set. Index offsets are relative to the table. |

Integers are stored as four raw bytes. Dates use the fixed 16-byte form
`YYYYMMDDhhmmssZ`, followed by a NUL and no length prefix. Other values use a
four-byte length followed by data padded to a four-byte boundary.

### Record slots and free lists

A table's slot array is indexed by record number — a record's number *is* the
slot it occupies:

| Slot value | Meaning |
| --- | --- |
| Even and nonzero | Record offset relative to the table |
| Odd | Free-list link: `(28 + 4 × slot) | 1`, pointing at the next free slot |
| `0` | Free, and the end of the free-list chain |

The table header's sixth word is the head of that chain. It points at the
**highest** free slot, which links down to the next, and so on to a slot holding
`0`; a table with no free slots carries `0`. A freshly created table carries
`0x1d`, which is simply the link to its single free slot 0. The chain is a
function of which slots are free, not of the order they were freed in: two
keychains that reach the same state by opposite deletion orders are byte-identical.

Deleting a record frees its slot and leaves the array length alone, unless the
freed slot is the last one — then that entry is removed and the count drops by
one, never cascading past other trailing free slots and never below a single
slot. Inserting takes the head of the chain and reuses that slot's record
number, and the new record's bytes go at the *end* of the records region even
when the slot reused is a low-numbered one. `kc` reproduces all of this: a
`kc rm item` produces a file byte-identical to what
`security delete-generic-password` produces from the same input.

### Blob versions and signatures

Apple keychains use more than one blob version. Keychains written by Apple's
tools commonly use `0x100` for legacy files and `0x200` for partition-aware
files. The blob version determines the signature algorithm:

| Version | Signature |
| --- | --- |
| `0x100` | Legacy BSafe-compatible HMAC behavior |
| `0x101`, `0x200` | HMAC-SHA1 |

Apple's `dbcrypto.cpp` selects the legacy algorithm only for `0x100`. A blob
must therefore be signed according to its declared version.

### Encryption

The container specification does not describe all cryptographic details. The
implementation follows Apple's published `ssblob.h`, `dbcrypto.cpp`, and
`HmacSha1Legacy.c` sources and is checked against keychains produced by macOS.

```text
password
  └─ PBKDF2-HMAC-SHA1(salt, 1000 iterations, 24 bytes) → master key

master key
  └─ 3DES-EDE3-CBC(DbBlob.iv) → encryption key (24) + signing key (20)

encryption key
  └─ unwrap(KeyBlob) → item key (24)

item key
  └─ 3DES-EDE3-CBC(ssgp.iv) → item secret
```

Each item stores its encrypted secret in an `ssgp` payload containing a
four-byte magic value, a 16-byte label, an eight-byte IV, and ciphertext. The
label identifies the symmetric-key record containing that item's wrapped key.

Apple's custom key wrapping uses two CBC passes with a byte reversal between
them:

```text
inner = 3DES-CBC(db key, iv, descriptive_data_length(0) || item key)
blob  = 3DES-CBC(db key, MAGIC_CMS_IV, reverse(iv || inner))
```

The `ssgp` payload carries its own IV. Its label matches the `Label` attribute
of the key record that protects it, forming the link between the item and its
key.

Version `0x100` blobs use Apple's legacy HMAC behavior for compatibility. The
implementation reproduces that behavior when the version requires it; later
blob versions use standard HMAC-SHA1.

### Indexes

Each table ends with an index region:

```text
region := size, count, count × index offset
index  := size, id, kind, attribute count, attribute ids,
          entry count, entry offsets, record numbers, entries
entry  := payload size, key values
```

Offsets are relative to the table. Entries are sorted by key, and the
record-number array follows the same order. Because inserting a record changes
table-relative offsets, `kc` rebuilds index regions from records whenever it
writes the database.

Unique-index attributes must be present even when their values are empty. For
example, an internet-password item without a port stores `port = 0` and an
empty path. This matches the records written by macOS and keeps the item
represented in the relation's unique index.

## Evidence and interoperability testing

The implementation combines three sources of evidence:

- the dtformats container specification;
- Apple's published source and CSSM/CDSA headers; and
- byte-level comparison with keychains written by macOS.

The test suite checks, among other things:

- byte-identical parsing and serialization of existing keychains;
- preservation of record slots, free-list links, unknown fields, and ACLs;
- signature selection by blob version;
- schema-defined attribute order and naming;
- key derivation, wrapping, and secret decryption;
- index reconstruction and ordering;
- duplicate detection through relation unique indexes;
- identity records and on-demand relation creation;
- byte-identical agreement with `security delete-generic-password` for deletes
  at the first, middle, and last slot;
- in-place updates, password changes, settings changes, ACL rewrites, copies,
  and certificate and identity deletion, each read back with Apple's tool; and
- interoperability in both directions with Apple's `security` tool.

Unknown values are named accordingly—for example, `free_list_head` and
`AclEntry::subject_words`—and preserved rather than inferred.

### Running the tests

```bash
cargo test -p kc-cli
cargo test -p kc-cli --features trust-apps
cargo test -p keychain-rs
```

The suite covers keychains created by both `kc` and `security`. System-generated
fixtures are created during the test run instead of being committed as binary
files. Tests that require `security` skip when it is unavailable.

`tests/keychain_interop.rs` provides the principal end-to-end check: it creates
and updates keychains with `kc`, then requires Apple's tool to unlock, search,
read, and update them.

To extract the schema from another macOS version:

```bash
security create-keychain -p x /tmp/fresh.keychain
python3 ../keychain/xtask/extract-schema.py /tmp/fresh.keychain > ../keychain/src/apple_schema.rs
```

## Security considerations

The legacy keychain format uses cryptography that is weak by current standards:
PBKDF2-HMAC-SHA1 with 1,000 iterations protects 3DES key material. Anyone who
obtains a keychain file can attempt password guesses offline. Use a strong,
random password and protect the file as secret material.

Additional considerations:

- `kc` creates files with mode `0600` and preserves the mode of existing files.
- 3DES and SHA-1 are properties of the format and are retained for
  interoperability.
- Secret buffers are cleared when dropped where supported by the implementation.
- Passing an item secret with `-w` exposes it through process arguments; prefer
  an interactive prompt or standard input.
- `kc` preserves ACL forms it does not model instead of rewriting them, and
  `kc trust` refuses to rewrite an ACL it could not parse rather than replacing
  it with a canonical one.
- `kc export key` and `kc export identity` write private key material; the file
  they create is mode `0600`, and an existing file's mode is taken down to
  `0600` rather than inherited.
- Direct file access bypasses `securityd` and therefore bypasses its ACL
  enforcement. Anyone with both the file and its password can decrypt its
  secrets.

## A running `securityd` caches what it has opened

`kc` replaces a keychain by writing a temporary file and renaming it, which is
atomic but changes the file's inode. A `securityd` that already has that path
open keeps serving the version it read: after `kc passwd`, `security` may still
unlock with the *old* password, and after `kc rm` it may still return a deleted
item — until something makes it re-open the file.

```bash
security lock-keychain ~/demo.keychain     # before the change, if it may be cached
kc passwd ~/demo.keychain
security unlock-keychain ~/demo.keychain   # after
```

Two related macOS behaviours are worth knowing, both established by experiment:
`security unlock-keychain` on an **already unlocked** keychain returns success
without checking the password at all, so verifying a rotation means locking
first; and `security show-keychain-info` prints to standard error, not standard
output.

## Access control

An item's key blob contains an owner entry and authorization entries. `kc`
supports both unrestricted and application-restricted forms:

```bash
kc add generic -a u -s svc ~/k.keychain
kc add generic -a u -s svc -T /usr/bin/security ~/k.keychain
kc add generic -a u -s svc \
  -T /usr/bin/security \
  -T /bin/ls \
  ~/k.keychain
```

A restricted entry stores one subject block per application:

```text
subject type 116, then for each application:
  20-byte legacy CDSA code hash
  binary path
  designated requirement
```

When built with `--features trust-apps`, `-T` obtains the application's
designated requirement with
[`macho-codesign`](https://github.com/bryanmatteson/macho). A requirement can
also be supplied explicitly:

```bash
csreq -r='identifier "com.example.app" and anchor apple' -b /tmp/req.bin
kc add generic -a u -s svc \
  --trust-requirement '/Applications/App.app=/tmp/req.bin' \
  ~/k.keychain
```

The requirement stored in the ACL matches the application's signed designated
requirement. The accompanying 20-byte value is a legacy CDSA code hash rather
than the modern `cdhash`. Testing confirms that macOS accepts a zero value on
the allowed access path, so `kc` uses zeros instead of synthesizing an
unsupported value.

macOS applies the application restriction to the six-tag authorization entry
(`24, 28, 37, 38, 59, 115`) while leaving the single-tag entry (`35`)
unrestricted. `kc` follows that structure when generating restricted ACLs.

These ACLs govern access through `securityd`. They do not restrict `kc`
itself, because `kc` decrypts the database directly.

## Source layout

```text
src/bin/kc.rs          command-line interface (uses keychain-rs)
```

Format internals live in [`keychain-rs`](../keychain/README.md).


## License

MIT. The format documentation draws on the GFDL-licensed dtformats
specification and Apple's APSL-licensed source. No code from either is included.
