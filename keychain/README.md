# keychain-db — macOS keychain files without the Security framework

Rust library for reading and writing macOS `.keychain` / `.keychain-db`
databases directly: no `securityd`, no Security framework, no entitlements.

The package is published as `keychain-db`; its Rust library target remains
`keychain`, so existing `use keychain::...` imports do not change. Versions
through 0.2.6 were also published under the former package name `keychain-rs`;
future releases use `keychain-db`.

The companion CLI is [`kc-cli`](https://crates.io/crates/kc-cli) (binary `kc`).

```toml
[dependencies]
keychain-db = "0.2"
# optional: resolve ACL trusted apps from code signatures
# keychain-db = { version = "0.2", features = ["trust-apps"] }
```

```rust
use keychain::{create, CreateOptions, Expression, ItemRef, KeychainFile, NewItem, RecordType};

let mut file = create(b"password", &CreateOptions::default())?;
file.add_password(
    RecordType::GENERIC_PASSWORD,
    &NewItem {
        account: Some("alice".into()),
        service: Some("github.com".into()),
        ..NewItem::default()
    },
    b"gh-token-abc",
    "20260725123456Z",
)?;
file.save("demo.keychain")?;

let mut file = KeychainFile::open("demo.keychain")?;
file.unlock(b"password")?;
let query = Expression::parse("class:generic account:alice service:github.com")?;
let item = file.select(&query)?.remove(0);
assert_eq!(file.secret(&item)?.as_slice(), b"gh-token-abc");

// References are opaque and bound to this exact database revision.
let encoded = file.item_ref(&item)?.encode();
let reference = ItemRef::decode(&encoded)?;
assert_eq!(file.resolve_ref(&reference)?.number(), item.number());
# Ok::<(), keychain::Error>(())
```

`Expression`, `Predicate`, `Comparison`, and `MatchOptions` are the public query
model. `Expression::parse` accepts the same typed predicates as `kc get`;
`Expression::new` supports programmatic construction. `KeychainFile::select`
queries password, certificate, private-key, public-key, and item-key records.
`ItemRef` deliberately exposes accessors rather than writable fields so callers
cannot accidentally manufacture mutation identities.

Identity import/export uses one high-level type for combined PEM and PKCS#12.
Combined PEM accepts unencrypted PKCS#8 `PRIVATE KEY` and traditional PKCS#1
`RSA PRIVATE KEY` blocks:

```rust
use keychain::{Pkcs12Identity, decode_identity};

// Auto-detect combined PEM or PEM/DER PKCS#12.
let identity = decode_identity(&std::fs::read("identity.p12")?, Some("bundle-password"))?;
let combined_pem = identity.to_pem();
let pfx_der = identity.to_pkcs12("new-password")?;
let pfx_pem = identity.to_pkcs12_pem("new-password")?;
# let _: (String, Vec<u8>, String) = (combined_pem, pfx_der, pfx_pem);
# let _: Option<Pkcs12Identity> = None;
# Ok::<(), keychain::Error>(())
```

Keychain-wide policy is separate from Apple's per-item ACL representation:

```rust
use keychain::{
    AccessDefault, AccessMode, AccessPolicy, ApplicationAccess, TrustedApplication,
};

let policy = AccessPolicy {
    mode: AccessMode::Hybrid,
    default: AccessDefault::Prompt,
    trusted_applications: Vec::<TrustedApplication>::new(),
};
assert!(policy.mode.enforces_direct());
assert!(policy.mode.projects_native());
assert_eq!(policy.native_application_access(), ApplicationAccess::Prompt);
```

The library returns an `AccessDecision`; it never owns terminal interaction.
Use `KeychainFile::set_item_access` and `set_private_key_access` to project a
policy to native ACLs, and `item_application_access` /
`private_key_application_access` to distinguish allow-any, prompt, and trusted
applications when auditing. The older `*_trust` methods retain their
empty-means-allow-any behavior.

`KeychainLocator` supplies the CLI-compatible bare-name contract without
implicitly reading CLI configuration:

```rust
use keychain::KeychainLocator;

let locator = KeychainLocator::new([std::path::PathBuf::from(
    "/Users/alice/Library/Keychains",
)])?;
assert_eq!(
    locator.resolve("machina"),
    std::path::PathBuf::from("/Users/alice/Library/Keychains/machina.keychain-db")
);
# Ok::<(), keychain::Error>(())
```

Interoperable with Apple's `security` tool in both directions. For the `kc`
command reference, see [`kc-cli`](../kc-cli/README.md).

Beyond creating and reading, the library changes keychains in place — updating
an item, deleting one, rewriting its access control, changing the keychain's
password and its lock settings:

```rust
use keychain::edit::{ItemChanges, Settings};
use keychain::{KeychainFile, RecordType};

let mut file = KeychainFile::open("demo.keychain")?;
file.unlock(b"password")?;

let number = file.items()[0].number();
file.update_item(
    RecordType::GENERIC_PASSWORD,
    number,
    &ItemChanges {
        comment: Some("rotated".into()),
        ..ItemChanges::default()
    },
    Some(b"a new secret"),
    "20260725123456Z",
)?;

file.set_settings(&Settings { idle_timeout: 900, lock_on_sleep: true })?;
file.change_password(b"password", b"a new password")?;
file.save("demo.keychain")?;
# Ok::<(), keychain::Error>(())
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

The table header's sixth word (`Table::free_list_head`) is the head of that
chain. It points at the **highest** free slot, which links down to the next, and
so on to a slot holding `0`; a table with no free slot carries `0`. A freshly
created table carries `0x1d` — the link to its single free slot 0.

Deleting frees a slot without shortening the array, unless the freed slot is the
last one, in which case that entry is dropped and the count falls by one — never
cascading past other trailing free slots, and never below one slot. Inserting
takes the head of the chain, reuses that slot's record number, and appends the
record's bytes at the end of the records region. `Table` maintains all of this,
including the record layout order, so a keychain that macOS has deleted from and
re-added to re-serializes byte for byte.

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
- identity records and on-demand relation creation; and
- interoperability in both directions with Apple's `security` tool.

Values that remain unknown are named accordingly — for example
`AclEntry::subject_words` — and preserved rather than inferred.

### Running the tests

```bash
cargo test -p keychain-db
cargo test -p keychain-db --features trust-apps
```

The suite covers keychains created by both `kc` and `security`. System-generated
fixtures are created during the test run instead of being committed as binary
files. Tests that require `security` skip when it is unavailable.

End-to-end CLI interop lives in the `kc-cli` crate's `tests/keychain_interop.rs`.

To extract the schema from another macOS version:

```bash
security create-keychain -p x /tmp/fresh.keychain
python3 keychain/xtask/extract-schema.py /tmp/fresh.keychain > keychain/src/apple_schema.rs
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
- `kc` preserves ACL forms it does not model instead of rewriting them.
- Direct file access bypasses `securityd` and therefore bypasses its ACL
  enforcement. Anyone with both the file and its password can decrypt its
  secrets.

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
src/format.rs          kych tables, records, and attribute values
src/schema.rs          relations and attributes read from the file
src/index.rs           index parsing, rebuilding, and sorting
src/crypto.rs          key derivation, signatures, and key wrapping
src/cssm.rs            typed CSSM key headers, GUIDs, and dates
src/acl.rs             ACL blob structures
src/records.rs         typed item, key, and certificate attributes
src/requirement.rs     designated requirements for trusted applications
src/der.rs             certificate DER field location
src/db.rs              open, unlock, query, and decrypt operations
src/write.rs           keychain creation and item insertion
src/edit.rs            update, delete, re-key, re-seal, and ACL rewriting
src/secret.rs          cleared key material and CSPRNG support
src/output.rs          text and JSON helpers
src/apple_schema.rs    generated Apple schema data
xtask/extract-schema.py schema extraction from a macOS keychain
```

## License

MIT. The format documentation draws on the GFDL-licensed dtformats
specification and Apple's APSL-licensed source. No code from either is included.
