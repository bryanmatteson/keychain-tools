# keychain-tools

Rust tools for macOS passwords and keychain files. They share a repository;
`apwh` shares no code with the keychain crates.

| | |
| --- | --- |
| [**`keychain-db`**](keychain/README.md) | Library for the on-disk `.keychain` format: no `securityd`, no Security framework, no entitlements. Published to crates.io. |
| [**`kc-cli`**](kc-cli/README.md) | CLI (`kc`) built on `keychain-db`. Creates, reads, and writes keychains Apple's `security` accepts. Published to crates.io. |
| [**`apwh`**](apwh/README.md) | Apple Passwords (iCloud Keychain) via the native-messaging helper discovered from Chrome/Firefox's manifest and launched over stdio. GitHub only — not on crates.io. Blocked on macOS 26 by Apple's parent launch constraint. |

`keychain-db` supersedes the former crates.io package name `keychain-rs`.
The Rust library target is still named `keychain`.

## Install

```bash
cargo add keychain-db          # library
cargo install kc-cli           # installs the `kc` binary
```

**`apwh`** from this repository:

```bash
cargo install --git https://github.com/bryanmatteson/keychain-tools --bin apwh
# or from a checkout:
cargo install --path apwh --bin apwh
```

From a checkout:

```bash
cargo build --workspace
cargo test  --workspace
cargo install --path kc-cli --bin kc
cargo install --path apwh --bin apwh
```

MSRV is Rust **1.87** (edition 2024). macOS only for runtime use; the crates
build as libraries elsewhere, but the CLIs and integration tests expect macOS.

## Verify

Before packaging a release:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build --workspace --release --all-features --locked
cargo package -p keychain-db --allow-dirty
cargo package -p kc-cli --allow-dirty
```

If you use [mise](https://mise.jdx.dev/), the same gate is `mise run verify`.

## License

MIT. See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.
