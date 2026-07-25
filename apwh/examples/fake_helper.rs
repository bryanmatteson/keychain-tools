//! A stand-in for `PasswordManagerBrowserExtensionHelper`, for tests.
//!
//! It speaks the same native-messaging protocol over stdio: SRP-6a handshake,
//! then AES-GCM payloads. Because the real helper only reveals its PIN on the
//! user's screen, this is the only way to exercise the client, the service, and
//! the CLI together in an automated test.
//!
//! Behaviour is set by the environment:
//!
//! * `FAKE_HELPER_PIN` — the PIN to accept (default `482915`)
//! * `FAKE_HELPER_MODE` — `normal`, `silent` (never reply), `exit` (die on the
//!   first request), or `push` (send an unsolicited message before each reply)

use base64::Engine as _;
use serde_json::{Value, json};
use std::io;

use apwh::crypto;
use apwh::frame::{read_frame, write_frame};
use apwh::srp::{Encoding, SrpServer};

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn main() {
    let pin = std::env::var("FAKE_HELPER_PIN").unwrap_or_else(|_| "482915".to_string());
    let mode = std::env::var("FAKE_HELPER_MODE").unwrap_or_else(|_| "normal".to_string());

    // Lets a test confirm the service really killed its helper on the way out.
    if let Ok(path) = std::env::var("FAKE_HELPER_PIDFILE") {
        std::fs::write(path, std::process::id().to_string()).expect("write pid file");
    }

    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut server: Option<SrpServer> = None;

    while let Ok(Some(request)) = read_frame(&mut stdin) {
        if mode == "exit" {
            return;
        }
        let request: Value = match serde_json::from_slice(&request) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if mode == "silent" {
            continue;
        }
        if mode == "push" {
            // A message the helper sends on its own; the service must not
            // mistake it for this request's reply.
            let push = json!({ "cmd": 15, "setUpTOTPPageURL": "https://example.com" });
            write_frame(&mut stdout, push.to_string().as_bytes()).unwrap();
        }

        let reply = handle(&request, &pin, &mut server);
        write_frame(&mut stdout, reply.to_string().as_bytes()).unwrap();
    }
}

fn handle(request: &Value, pin: &str, server: &mut Option<SrpServer>) -> Value {
    match request["cmd"].as_i64().unwrap_or(-1) {
        14 => json!({
            "cmd": 14,
            "capabilities": {
                "canFillOneTimeCodes": true,
                "scanForOTPURI": true,
                "shouldUseBase64": true,
                "operatingSystem": { "name": "macOS", "majorVersion": 26, "minorVersion": 5 },
            }
        }),
        2 => handshake(request, pin, server),
        command => match server.as_ref() {
            Some(session) => data_command(command, request, session),
            None => json!({ "error": "no session" }),
        },
    }
}

fn handshake(request: &Value, pin: &str, server: &mut Option<SrpServer>) -> Value {
    let pake: Value = serde_json::from_slice(
        &BASE64
            .decode(request["msg"]["PAKE"].as_str().unwrap_or_default())
            .unwrap_or_default(),
    )
    .unwrap_or(Value::Null);
    let tid = pake["TID"].as_str().unwrap_or_default().to_string();

    match pake["MSG"].as_i64().unwrap_or(-1) {
        // Client key exchange: create the challenge and answer with B and s.
        0 => {
            let mut session = SrpServer::new(Encoding::Base64, &tid, pin);
            let client_public =
                crypto::from_bytes_be(&BASE64.decode(pake["A"].as_str().unwrap()).unwrap());
            session
                .derive_shared_key(&client_public)
                .expect("client public key");

            let body = json!({
                "TID": tid,
                "MSG": 1,
                "PROTO": 1,
                "VER": "1.0",
                "B": session.encode(&crypto::to_bytes_be(&session.server_public()), true),
                "s": session.encode(&crypto::to_bytes_be(session.salt()), true),
            });
            let reply = json!({ "cmd": 2, "payload": { "PAKE": encode_pake(&body) } });
            *server = Some(session);
            reply
        }

        // Client verification: check M, answer with HAMK or an error code.
        2 => {
            let Some(session) = server.as_ref() else {
                return json!({ "error": "no handshake in progress" });
            };
            let m = BASE64
                .decode(pake["M"].as_str().unwrap_or_default())
                .unwrap_or_default();

            match session.verify_client(&m) {
                Ok(hamk) => {
                    let body = json!({
                        "TID": pake["TID"],
                        "MSG": 3,
                        "ErrCode": 0,
                        "HAMK": session.encode(&hamk, true),
                    });
                    json!({ "cmd": 2, "payload": { "PAKE": encode_pake(&body) } })
                }
                Err(_) => {
                    let body = json!({ "TID": pake["TID"], "MSG": 3, "ErrCode": 1 });
                    json!({ "cmd": 2, "payload": { "PAKE": encode_pake(&body) } })
                }
            }
        }

        _ => json!({ "error": "unexpected handshake stage" }),
    }
}

fn data_command(command: i64, request: &Value, session: &SrpServer) -> Value {
    let payload: Value = request["payload"]
        .as_str()
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null);
    let sealed = session
        .decode(payload["SMSG"]["SDATA"].as_str().unwrap_or_default())
        .expect("SDATA is encoded correctly");
    let plaintext: Value =
        serde_json::from_slice(&session.open_request(&sealed).expect("SDATA decrypts"))
            .expect("SDATA holds JSON");

    let body = match command {
        // Login names: metadata only.
        4 => json!({
            "STATUS": 0,
            "Entries": [
                { "USR": "ada@example.com", "sites": ["example.com"] },
                { "USR": "grace@example.com", "sites": ["example.com"] },
            ]
        }),

        // Password for one login. An empty USR means "the caller did not choose",
        // which is how a site with two logins produces an ambiguous reply.
        5 => {
            let requested = plaintext["USR"].as_str().unwrap_or_default();
            let entries: Vec<Value> = [("ada@example.com", "hunter2"), ("grace@example.com", "s3cr3t")]
                .iter()
                .filter(|(user, _)| requested.is_empty() || *user == requested)
                .map(|(user, password)| {
                    json!({ "USR": user, "sites": ["example.com"], "PWD": password })
                })
                .collect();
            if entries.is_empty() {
                json!({ "STATUS": 3 })
            } else {
                json!({ "STATUS": 0, "Entries": entries })
            }
        }

        // New account.
        7 => json!({ "STATUS": 0 }),

        // One-time codes: listed without codes, fetched with them.
        16 => json!({
            "STATUS": 0,
            "Entries": [{ "username": "ada@example.com", "domain": "example.com" }]
        }),
        17 => json!({
            "STATUS": 0,
            "Entries": [{
                "username": "ada@example.com",
                "domain": "example.com",
                "source": "example.com",
                "code": "246810",
            }]
        }),

        _ => json!({ "STATUS": 8 }),
    };

    let sealed = session.seal_reply(&body).expect("reply seals");
    json!({
        "cmd": command,
        "payload": {
            "SMSG": {
                "TID": payload["SMSG"]["TID"],
                "SDATA": session.encode(&sealed, true),
            }
        }
    })
}

fn encode_pake(body: &Value) -> String {
    BASE64.encode(body.to_string().as_bytes())
}
