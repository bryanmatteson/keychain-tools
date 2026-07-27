# apwh

A Rust CLI and background service for Apple Passwords (iCloud Keychain) on macOS,
built on the same native-messaging helper that browser extensions use.

This is one of three crates in the repository. The other two are
[`keychain-db`](../keychain/README.md) and [`kc-cli`](../kc-cli/README.md),
which read and write `.keychain` files directly and share no code with this
one.

Protocol reconstructed from [`apw`](https://github.com/bendews/apw) (Deno/TypeScript)
and [`icloud-passwords-firefox`](https://github.com/au2001/icloud-passwords-firefox).
The SRP and AES-GCM implementations here are verified byte-for-byte against
`apw`'s own code — see [Verification](#verification).

> [!IMPORTANT]
> **On macOS 26 this cannot work, and the reason is not fixable in this code.**
> Apple added a *parent launch constraint* to the helper: only an allowlisted,
> signed browser may launch it. A CLI that spawns it gets the helper `SIGKILL`ed
> at `exec`. Run `apwh doctor` for a verdict on your Mac, and read
> [macOS 26 and parent launch constraints](#macos-26-and-parent-launch-constraints)
> for the evidence and the options.

---

## What this is

macOS 14 and later ship `PasswordManagerBrowserExtensionHelper`, a
native-messaging host that answers questions about iCloud Keychain items:
which logins exist for a site, what a password is, what the current one-time
code is, and it can store a new login. It speaks Chrome/Firefox native messaging
over stdio, which has two consequences that shape everything here:

- **One owner.** Whoever spawns it holds its stdin/stdout. A short-lived CLI
  cannot both own the helper and be short-lived.
- **A session that dies with the process.** The SRP handshake — including the
  six-digit PIN macOS puts on screen — is per helper process.

`apwh` reads `/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json`
(or Firefox's equivalent), launches its `path` directly, and exchanges
length-prefixed JSON over the helper's stdin/stdout. Chrome itself—headless or
otherwise—is not part of the protocol.

So `apwh` is split in two:

- **`apwh serve`** — the service. Owns the helper process and relays framed JSON
  between it and any number of clients over a Unix socket.
- **`apwh <anything else>`** — the client. Runs the SRP handshake, stores the
  derived key, and encrypts every request end-to-end. The service only ever sees
  ciphertext; it holds no key and can decrypt nothing.

## Install

```bash
cargo build --release
```

The binary is `target/release/apwh`. Copy it wherever you like, then optionally
run it at login:

```bash
apwh service install
```

That writes `~/Library/LaunchAgents/dev.matteson.apwh.plist` (a LaunchAgent, not a
daemon — the helper needs the logged-in user's session and screen) and loads it
with `launchctl bootstrap gui/$UID`. Undo with `apwh service uninstall`.

## Use

```bash
apwh doctor                        # can this Mac run the service at all?
apwh serve                         # run the service in the foreground
apwh auth                          # handshake; enter the PIN macOS displays
apwh status                        # service, session, helper, agent

apwh list example.com              # logins for a site (no secrets)
apwh get example.com ada@example.com
apwh get example.com ada@example.com --copy
apwh add example.com carol         # prompts, or reads a piped password
apwh otp get example.com           # current one-time code
apwh otp list example.com

apwh logout                        # forget the stored key
apwh completions fish > ~/.config/fish/completions/apwh.fish
```

`apwh auth` is needed **every time the service restarts** — the helper's session
does not outlive its process.

Global flags: `--json` for a stable envelope, `--raw` to print the helper's
decrypted reply verbatim (useful when a field here does not match what your macOS
version sends), `--socket PATH`, `--timeout SECONDS`.

Non-interactive handshake, for scripts and GUI front ends:

```bash
apwh auth begin --json             # returns the pending-handshake path
apwh auth complete --pin 123456
```

Exit codes are the helper's own status codes: `3` no results, `9` session
invalid or absent, `1` everything else. Passwords print bare on stdout so they
pipe; everything advisory goes to stderr.

### Environment

| Variable | Meaning | Default |
| --- | --- | --- |
| `APWH_HOME` | State directory | `~/.apwh` |
| `APWH_SOCKET` | Service socket | `$APWH_HOME/service.sock` |

## Protocol

Every message is a JSON object with a numeric `cmd`, length-prefixed with a
32-bit native-endian header (Chrome/Firefox native messaging framing). The same
framing carries CLI↔service traffic.

### Commands

| `cmd` | Name | Used for |
| --- | --- | --- |
| 2 | `HANDSHAKE` | SRP key exchange (`QID` `m0`) and verification (`m2`) |
| 4 | `GET_LOGIN_NAMES_FOR_URL` | `apwh list` |
| 5 | `GET_PASSWORD_FOR_LOGIN_NAME` | `apwh get` |
| 7 | `NEW_ACCOUNT_FOR_URL` | `apwh add` |
| 14 | `GET_CAPABILITIES` | `apwh capabilities` (no session needed) |
| 16 | `GET_ONE_TIME_CODES` | `apwh otp list` |
| 17 | `DID_FILL_ONE_TIME_CODE` | `apwh otp get` |

The helper also sends messages nobody asked for — `TAB_EVENT` (8),
`PASSWORDS_DISABLED` (9), `RELOGIN_NEEDED` (10),
`ICLOUD_PASSWORDS_STATE_CHANGE` (12), `ONE_TIME_CODE_AVAILABLE` (15). The service
logs and skips them; treating one as a reply would put every later
request/response pair off by one.

### Handshake

SRP-6a, RFC 5054 group `G_3072` (`g = 5`), SHA-256, RFC 2945 verification:

```text
x    = H(s | H(I | ":" | PIN))
u    = H(PAD(A) | PAD(B))
k    = H(N | PAD(g))
S    = (B - k * g^x) ^ (a + u * x) mod N
K    = H(S)
M    = H(H(N) XOR H(PAD(g)) | H(I) | s | A | B | K)
HAMK = H(A | M | K)
```

`I` is not a user name: it is 16 random bytes per session, base64-encoded, sent
as `TID`. The PIN is the six digits macOS displays when `m0` arrives.

Two details are easy to get wrong and change every hash downstream:

- Integers travel as **minimal-length** big-endian bytes (no leading zeros)
  everywhere *except* inside `u` and `k`, where `PAD()` widens to the 384-byte
  group size. `N` inside `k` is not padded — it is already 384 bytes.
- `M` uses **unpadded** `A` and `B`.

### Payload encryption

AES-128-GCM. The key is the **first 16 bytes** of `K`'s minimal big-endian form.
The IV is **16 bytes**, not GCM's usual 12.

The framing is asymmetric, and this is not a transcription error:

| Direction | Layout |
| --- | --- |
| Client → helper | `ciphertext ‖ tag ‖ iv` |
| Helper → client | `iv ‖ ciphertext ‖ tag` |

Both reference implementations do exactly this, independently, and both
interoperate with the shipping helper. `tests/reference_vectors.rs` pins it.

Plaintext bodies are JSON: `{"ACT": 5, "URL": "example.com"}` for a metadata
lookup (`GHOST_SEARCH`), `ACT: 2` (`SEARCH`) to get secrets, `ACT: 4`
(`MAYBE_ADD`) with `NURL`/`NUSR`/`NPWD` to store a new login. The sealed body
goes in `payload`, which is itself a JSON **string**:
`{"QID": "...", "SMSG": {"TID": ..., "SDATA": ...}}`.

## Differences from `apw`

The protocol against Apple's helper is identical; the local parts are not.

| | `apw` | `apwh` |
| --- | --- | --- |
| CLI↔service transport | UDP on `127.0.0.1`, port in the config file | Unix socket, `0600` in a `0700` directory |
| Socket binding | `bind(port)` — all interfaces | not applicable |
| Reading helper replies | accumulate stdout until `JSON.parse` succeeds | exact length-prefixed frames |
| Unsolicited helper messages | can be returned as a reply | logged and skipped |
| Concurrency | one datagram at a time | connection per client, helper access serialized |
| Reply size limit | one UDP datagram (~64 KB) | none |
| Secrets on the command line | `auth response --ck <private key>` | state file, `0600` |
| Startup diagnosis | none | `apwh doctor`, and `serve` refuses with a reason |

The UDP change is the one that breaks compatibility: anything written against
`apw`'s daemon port will not talk to this service. It buys a transport that is
local by construction (no port any process or host can reach), permission-gated
by the filesystem, and free of the datagram size limit.

## Security notes

- **The session key is the whole ballgame.** With it, any process can read every
  password the helper will hand out. It lives in `~/.apwh/config.json`, mode
  `0600`, in a `0700` directory — the same trust model as an SSH private key
  without a passphrase, and the same as `apw`. It is *not* in the login keychain,
  because the service has to work unattended after login. If that trade-off is
  wrong for you, do not install the LaunchAgent, and run `apwh logout` when done.
- **The service is a relay, not an oracle.** Payloads are encrypted end-to-end
  between the client's SRP session and the helper. A process that can reach the
  socket can make the helper *see* traffic but cannot read a password without the
  key. The socket mode is the access boundary.
- **Secrets stay out of `argv`.** `apwh add --password` warns for that reason;
  prefer the prompt or a pipe. The two-step handshake writes its ephemeral state
  to a `0600` file instead of passing a private key as a flag.
- **A restarted service drops the stored key**, because the helper's session died
  with it. That prevents a confusing decryption failure later.
- On the way out (`SIGINT`/`SIGTERM`/`SIGHUP`) the service kills its helper and
  unlinks the socket, so nothing is orphaned and the next start is clean.

## macOS 26 and parent launch constraints

On macOS 26.5 (build 25F84), launching the helper from anything but an
allowlisted browser fails, immediately and silently:

```console
$ apwh doctor
socket path                /Users/you/.apwh/service.sock (ok)
manifest                   /Library/Application Support/Mozilla/NativeMessagingHosts/com.apple.passwordmanager.json
helper                     /System/Cryptexes/App/.../PasswordManagerBrowserExtensionHelper
parent launch constraint   yes — only allowlisted browsers may launch it
helper launches            no
problem                    macOS killed the Passwords helper immediately (SIGKILL at launch).
```

The helper exits with `SIGKILL`, no output, no log entry, in milliseconds. The
cause is in its code signature:

```console
$ codesign -dvvv /System/Cryptexes/App/.../PasswordManagerBrowserExtensionHelper
...
Launch Constraints:
	Has Parent Launch Constraints
```

Decoding that constraint blob (`LWCR`, code-directory slot 9) gives an `$or` over
an allowlist. The parent process must either hold the
`com.apple.developer.web-browser.public-key-credential` entitlement, or match a
signing-identifier **and** team-identifier pair from a fixed list of browsers:
Chrome, Edge, Firefox, Arc, Brave, Vivaldi, Opera, Zen, Orion-likes, and a few
dozen more. There is no entry for a user-built binary, and the entitlement is one
Apple grants to browser vendors — self-signing it does not work.

So on this OS:

- No CLI can be the helper's parent. Not with `sudo`, not from a LaunchAgent
  (parent would be `launchd`), not by disabling the sandbox.
- `apw` is affected identically. This is not a difference between the two tools.

**What is left, if you want this working on macOS 26:**

1. **Browser-hosted bridge.** Install a native-messaging manifest for a browser
   extension you control (`/Library/Google/Chrome/NativeMessagingHosts/`, needs
   `sudo`) pointing at the helper, plus a small extension that relays frames
   between the helper and this service's socket. The browser is an allowlisted
   parent, so the constraint is satisfied. Every line of protocol code here keeps
   working — only the hop that spawns the helper changes. Costs: a browser must be
   running, an extension must be loaded, and a manifest must be installed with
   root.
2. **Wait or downgrade.** The constraint is a signing-time decision by Apple; on
   macOS 14/15 the direct-spawn path in this repo should work as-is. That path
   is not re-verified on every release once a machine moves to macOS 26+.
3. **A different data source entirely** (Security framework, an export). Not
   equivalent: no ghost search, no one-time codes, different access prompts.

A browser-bridge path is not implemented here; it would be a real addition, not
a flag flip.

## Verification

```bash
cargo test            # 199 tests across both binaries
```

- **`tests/reference_vectors.rs`** — vectors generated by running `apw`'s own
  `src/srp.ts` under Node with fixed inputs, then pinned here. Covers `A`, `K`,
  `M`, `HAMK`, the AES key, and both ciphertext framings. A padding or
  byte-order mistake fails these.
- **`tests/end_to_end.rs`** — real CLI processes against a real service process
  over a real socket, with `examples/fake_helper` playing the helper: full
  handshake, wrong-PIN rejection, list/get/otp/add, two-process handshake,
  unsolicited-message handling, helper timeout, helper death, `SIGTERM` cleanup,
  stale-session clearing, and file permissions.
- **Unit tests** cover the SRP steps against a server peer (`srp::SrpServer`),
  framing, tolerant payload parsing, config permissions, and output formatting.

`examples/fake_helper` exists because the real helper only reveals its PIN on
screen; it is built by `cargo test`.

What is **not** verified: a live handshake against Apple's helper on this
machine, because the OS will not let the helper start (above). Everything up to
that boundary is exercised — including the exact bytes the reference
implementation puts on the wire.

## Layout

```
src/srp.rs        SRP-6a client and server sides, shared hash steps
src/crypto.rs     SHA-256, big-endian conventions, AES-GCM sealing
src/protocol.rs   message structs, command codes, response parsing
src/client.rs     handshake, encrypted requests, transport
src/service.rs    helper process, framing relay, signal cleanup
src/config.rs     state directory, key storage, pending handshakes
src/entries.rs    decrypted payloads and records
src/output.rs     text/JSON rendering, PIN validation
src/launchd.rs    LaunchAgent install/uninstall/status
src/main.rs       CLI
```

## License

MIT.
