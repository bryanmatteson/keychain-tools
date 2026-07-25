//! Wire format for the `com.apple.passwordmanager` native-messaging helper.
//!
//! Every message is a JSON object with a numeric `cmd`. Handshake traffic rides
//! in `msg.PAKE` (base64-encoded JSON); everything else rides in `payload`, a
//! JSON *string* whose `SMSG.SDATA` holds the AES-GCM ciphertext.
//!
//! Request structs are serialized field-by-field in declaration order so the
//! bytes on the wire match the reference implementations.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::srp::SrpSession;

/// Protocol version advertised in the client key exchange.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Browser name sent as `HSTBRSR`. The helper shows it to the user while the PIN
/// dialog is up. `apw` sends "Arc" and the helper accepts it, so an arbitrary
/// string appears to be fine; this stays on the proven value by default and is
/// overridable through config.
pub const DEFAULT_BROWSER_NAME: &str = "Arc";

/// Commands understood by the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    End = 0,
    Unused = 1,
    Handshake = 2,
    SetIconAndTitle = 3,
    GetLoginNamesForUrl = 4,
    GetPasswordForLoginName = 5,
    SetPasswordForLoginNameAndUrl = 6,
    NewAccountForUrl = 7,
    TabEvent = 8,
    PasswordsDisabled = 9,
    ReloginNeeded = 10,
    LaunchICloudPasswords = 11,
    ICloudPasswordsStateChange = 12,
    LaunchPasswordsApp = 13,
    GetCapabilities = 14,
    OneTimeCodeAvailable = 15,
    GetOneTimeCodes = 16,
    DidFillOneTimeCode = 17,
    OpenUrlInSafari = 1984,
}

impl Command {
    pub fn code(self) -> u16 {
        self as u16
    }

    /// True for messages the helper sends on its own, without a request.
    ///
    /// The relay must not mistake one of these for the answer to a pending
    /// request, or every later request/response pair would be off by one.
    pub fn is_unsolicited(code: i64) -> bool {
        matches!(
            code,
            code if code == Self::TabEvent as i64
                || code == Self::PasswordsDisabled as i64
                || code == Self::ReloginNeeded as i64
                || code == Self::ICloudPasswordsStateChange as i64
                || code == Self::OneTimeCodeAvailable as i64
                || code == Self::SetIconAndTitle as i64
                || code == Self::LaunchICloudPasswords as i64
                || code == Self::LaunchPasswordsApp as i64
                || code == Self::OpenUrlInSafari as i64
        )
    }

    pub fn describe(code: i64) -> String {
        let name = match code {
            0 => "END",
            1 => "UNUSED",
            2 => "HANDSHAKE",
            3 => "SET_ICON_AND_TITLE",
            4 => "GET_LOGIN_NAMES_FOR_URL",
            5 => "GET_PASSWORD_FOR_LOGIN_NAME",
            6 => "SET_PASSWORD_FOR_LOGIN_NAME_AND_URL",
            7 => "NEW_ACCOUNT_FOR_URL",
            8 => "TAB_EVENT",
            9 => "PASSWORDS_DISABLED",
            10 => "RELOGIN_NEEDED",
            11 => "LAUNCH_ICLOUD_PASSWORDS",
            12 => "ICLOUD_PASSWORDS_STATE_CHANGE",
            13 => "LAUNCH_PASSWORDS_APP",
            14 => "GET_CAPABILITIES",
            15 => "ONE_TIME_CODE_AVAILABLE",
            16 => "GET_ONE_TIME_CODES",
            17 => "DID_FILL_ONE_TIME_CODE",
            1984 => "OPEN_URL_IN_SAFARI",
            _ => return format!("cmd {code}"),
        };
        format!("{name} ({code})")
    }
}

/// SRP handshake stage, the `MSG` field of a PAKE message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    ClientKeyExchange = 0,
    ServerKeyExchange = 1,
    ClientVerification = 2,
    ServerVerification = 3,
}

/// Secret-session protocol variant. Only RFC verification is used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecretSessionVersion {
    SrpWithOldVerification = 0,
    SrpWithRfcVerification = 1,
}

/// What a request asks the helper to do with the item it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum Action {
    Unknown = -1,
    Delete = 0,
    Update = 1,
    /// Returns secrets; may prompt for local authentication.
    Search = 2,
    AddNew = 3,
    MaybeAdd = 4,
    /// Metadata only: user names and sites, never secrets.
    GhostSearch = 5,
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Top-level request envelope.
#[derive(Debug, Serialize)]
pub struct Request {
    pub cmd: u16,
    #[serde(rename = "tabId", skip_serializing_if = "Option::is_none")]
    pub tab_id: Option<u32>,
    #[serde(rename = "frameId", skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<HandshakeBody>,
    /// A JSON document, embedded as a string; the helper expects it that way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

impl Request {
    fn bare(cmd: Command) -> Self {
        Self {
            cmd: cmd.code(),
            tab_id: None,
            frame_id: None,
            url: None,
            msg: None,
            payload: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HandshakeBody {
    #[serde(rename = "QID")]
    pub qid: &'static str,
    #[serde(rename = "PAKE")]
    pub pake: String,
    #[serde(rename = "HSTBRSR")]
    pub browser: String,
}

#[derive(Debug, Serialize)]
struct ClientKeyExchange {
    #[serde(rename = "TID")]
    tid: String,
    #[serde(rename = "MSG")]
    msg: u8,
    #[serde(rename = "A")]
    a: String,
    #[serde(rename = "VER")]
    ver: &'static str,
    #[serde(rename = "PROTO")]
    proto: [u8; 1],
}

#[derive(Debug, Serialize)]
struct ClientVerification {
    #[serde(rename = "TID")]
    tid: String,
    #[serde(rename = "MSG")]
    msg: u8,
    #[serde(rename = "M")]
    m: String,
}

#[derive(Debug, Serialize)]
struct SecureEnvelope<'a> {
    #[serde(rename = "QID")]
    qid: &'static str,
    #[serde(rename = "SMSG")]
    smsg: SecureMessage<'a>,
}

#[derive(Debug, Serialize)]
struct SecureMessage<'a> {
    #[serde(rename = "TID")]
    tid: &'a str,
    #[serde(rename = "SDATA")]
    sdata: String,
}

/// `ACT: GHOST_SEARCH` for a URL: user names and sites, no secrets.
#[derive(Debug, Serialize)]
struct GhostSearchUrl<'a> {
    #[serde(rename = "ACT")]
    act: i8,
    #[serde(rename = "URL")]
    url: &'a str,
}

/// `ACT: SEARCH` for one login: returns the password.
#[derive(Debug, Serialize)]
struct SearchLogin<'a> {
    #[serde(rename = "ACT")]
    act: i8,
    #[serde(rename = "URL")]
    url: &'a str,
    #[serde(rename = "USR")]
    usr: &'a str,
}

/// One-time-code lookup, keyed by frame URL rather than `URL`.
#[derive(Debug, Serialize)]
struct OneTimeCodes<'a> {
    #[serde(rename = "ACT")]
    act: i8,
    #[serde(rename = "TYPE")]
    kind: &'static str,
    #[serde(rename = "frameURLs")]
    frame_urls: [&'a str; 1],
}

/// New-item request. The empty `URL`/`USR`/`PWD` fields are required: the helper
/// treats the `N`-prefixed fields as the replacement for the named item, and an
/// empty triple means "there is no existing item".
#[derive(Debug, Serialize)]
struct MaybeAddAccount<'a> {
    #[serde(rename = "ACT")]
    act: i8,
    #[serde(rename = "URL")]
    url: &'static str,
    #[serde(rename = "USR")]
    usr: &'static str,
    #[serde(rename = "PWD")]
    pwd: &'static str,
    #[serde(rename = "NURL")]
    new_url: &'a str,
    #[serde(rename = "NUSR")]
    new_usr: &'a str,
    #[serde(rename = "NPWD")]
    new_pwd: &'a str,
}

/// Builders for every request this client sends.
pub struct Messages;

impl Messages {
    pub fn get_capabilities() -> Request {
        Request::bare(Command::GetCapabilities)
    }

    /// Handshake `m0`: send `A` and ask for the server hello.
    pub fn request_challenge(session: &SrpSession, browser: &str) -> Result<Request> {
        let pake = ClientKeyExchange {
            tid: session.username().to_string(),
            msg: MsgType::ClientKeyExchange as u8,
            a: session.encode(&crate::crypto::to_bytes_be(&session.client_public()), true),
            ver: PROTOCOL_VERSION,
            proto: [SecretSessionVersion::SrpWithRfcVerification as u8],
        };
        Ok(Request {
            msg: Some(HandshakeBody {
                qid: "m0",
                pake: base64_json(&pake)?,
                browser: browser.to_string(),
            }),
            ..Request::bare(Command::Handshake)
        })
    }

    /// Handshake `m2`: prove we know the PIN.
    pub fn verify_challenge(session: &SrpSession, m: &[u8], browser: &str) -> Result<Request> {
        let pake = ClientVerification {
            tid: session.username().to_string(),
            msg: MsgType::ClientVerification as u8,
            m: session.encode(m, false),
        };
        Ok(Request {
            msg: Some(HandshakeBody {
                qid: "m2",
                pake: base64_json(&pake)?,
                browser: browser.to_string(),
            }),
            ..Request::bare(Command::Handshake)
        })
    }

    pub fn login_names_for_url(session: &SrpSession, url: &str) -> Result<Request> {
        let sdata = GhostSearchUrl {
            act: Action::GhostSearch as i8,
            url,
        };
        Ok(Request {
            tab_id: Some(1),
            frame_id: Some(1),
            url: Some(url.to_string()),
            payload: Some(secure_payload(session, "CmdGetLoginNames4URL", &sdata)?),
            ..Request::bare(Command::GetLoginNamesForUrl)
        })
    }

    pub fn password_for_url(session: &SrpSession, url: &str, login_name: &str) -> Result<Request> {
        let sdata = SearchLogin {
            act: Action::Search as i8,
            url,
            usr: login_name,
        };
        Ok(Request {
            tab_id: Some(0),
            frame_id: Some(0),
            url: Some(url.to_string()),
            payload: Some(secure_payload(session, "CmdGetPassword4LoginName", &sdata)?),
            ..Request::bare(Command::GetPasswordForLoginName)
        })
    }

    /// List one-time-code items for a URL without revealing codes.
    pub fn list_one_time_codes(session: &SrpSession, url: &str) -> Result<Request> {
        let sdata = OneTimeCodes {
            act: Action::GhostSearch as i8,
            kind: "oneTimeCodes",
            frame_urls: [url],
        };
        Ok(Request {
            tab_id: Some(0),
            frame_id: Some(0),
            payload: Some(secure_payload(session, "CmdDidFillOneTimeCode", &sdata)?),
            ..Request::bare(Command::GetOneTimeCodes)
        })
    }

    /// Fetch the current one-time code for a URL.
    pub fn get_one_time_code(session: &SrpSession, url: &str) -> Result<Request> {
        let sdata = OneTimeCodes {
            act: Action::Search as i8,
            kind: "oneTimeCodes",
            frame_urls: [url],
        };
        Ok(Request {
            tab_id: Some(0),
            frame_id: Some(0),
            payload: Some(secure_payload(session, "CmdDidFillOneTimeCode", &sdata)?),
            ..Request::bare(Command::DidFillOneTimeCode)
        })
    }

    pub fn new_account_for_url(
        session: &SrpSession,
        url: &str,
        login_name: &str,
        password: &str,
    ) -> Result<Request> {
        let sdata = MaybeAddAccount {
            act: Action::MaybeAdd as i8,
            url: "",
            usr: "",
            pwd: "",
            new_url: url,
            new_usr: login_name,
            new_pwd: password,
        };
        Ok(Request {
            tab_id: Some(0),
            frame_id: Some(0),
            payload: Some(secure_payload(session, "CmdNewAccount4URL", &sdata)?),
            ..Request::bare(Command::NewAccountForUrl)
        })
    }
}

fn base64_json(value: &impl Serialize) -> Result<String> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(value)?))
}

fn secure_payload(
    session: &SrpSession,
    qid: &'static str,
    sdata: &impl Serialize,
) -> Result<String> {
    let sealed = session.seal(sdata)?;
    let envelope = SecureEnvelope {
        qid,
        smsg: SecureMessage {
            tid: session.username(),
            sdata: session.encode(&sealed, true),
        },
    };
    Ok(serde_json::to_string(&envelope)?)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Reply envelope, as returned by the helper or synthesized by the service.
#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub cmd: Option<i64>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub msg: Option<Value>,
    /// Set by the service when it cannot get an answer from the helper.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
}

impl Response {
    /// The handshake body, from `payload` or `msg`, whichever the helper used.
    pub fn handshake(&self) -> Result<ServerPake> {
        let body = self
            .payload
            .as_ref()
            .or(self.msg.as_ref())
            .ok_or_else(|| Error::protocol("handshake reply has no payload"))?;
        let body = as_object(body)?;
        let pake = body
            .get("PAKE")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::protocol("handshake reply has no PAKE field"))?;

        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(pake)
            .map_err(|_| Error::protocol("PAKE field is not valid base64"))?;
        serde_json::from_slice(&decoded)
            .map_err(|error| Error::protocol(format!("malformed PAKE body: {error}")))
    }

    /// The `SMSG` block carrying an encrypted payload.
    pub fn secure_message(&self) -> Result<SecureMessageBody> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| Error::protocol("reply has no payload"))?;
        let payload = as_object(payload)?;
        let smsg = payload
            .get("SMSG")
            .ok_or_else(|| Error::protocol("reply has no SMSG field"))?;
        let smsg = as_object(smsg)?;

        let tid = smsg
            .get("TID")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::protocol("SMSG has no TID field"))?;
        let sdata = smsg
            .get("SDATA")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::protocol("SMSG has no SDATA field"))?;

        Ok(SecureMessageBody {
            tid: tid.to_string(),
            sdata: sdata.to_string(),
        })
    }
}

/// Server side of the SRP handshake.
#[derive(Debug, Deserialize)]
pub struct ServerPake {
    #[serde(rename = "TID")]
    pub tid: String,
    /// macOS sends a number here, iCloud for Windows a string.
    #[serde(rename = "MSG")]
    pub msg: Value,
    #[serde(rename = "ErrCode", default)]
    pub err_code: Option<i64>,
    #[serde(rename = "PROTO", default)]
    pub proto: Option<i64>,
    #[serde(rename = "VER", default)]
    pub version: Option<String>,
    /// Server public key `B`.
    #[serde(rename = "B", default)]
    pub server_public: Option<String>,
    /// Salt `s`.
    #[serde(rename = "s", default)]
    pub salt: Option<String>,
    /// Server proof, in the verification reply.
    #[serde(rename = "HAMK", default)]
    pub hamk: Option<String>,
}

impl ServerPake {
    /// Compare `MSG` against an expected stage, tolerating string or number.
    pub fn is_stage(&self, expected: MsgType) -> bool {
        let expected = expected as u8 as i64;
        match &self.msg {
            Value::Number(number) => number.as_i64() == Some(expected),
            Value::String(text) => text.trim().parse::<i64>() == Ok(expected),
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct SecureMessageBody {
    pub tid: String,
    pub sdata: String,
}

/// Helper capabilities, from `GET_CAPABILITIES`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Capabilities {
    #[serde(rename = "canFillOneTimeCodes", default)]
    pub can_fill_one_time_codes: Option<bool>,
    #[serde(rename = "scanForOTPURI", default)]
    pub scan_for_otp_uri: Option<bool>,
    #[serde(rename = "shouldUseBase64", default)]
    pub should_use_base64: Option<bool>,
    #[serde(rename = "operatingSystem", default)]
    pub operating_system: Option<OperatingSystem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperatingSystem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "majorVersion", default)]
    pub major_version: Option<i64>,
    #[serde(rename = "minorVersion", default)]
    pub minor_version: Option<i64>,
}

/// Read a JSON object that may arrive either inline or as an embedded string.
fn as_object(value: &Value) -> Result<Map<String, Value>> {
    match value {
        Value::Object(map) => Ok(map.clone()),
        Value::String(text) => match serde_json::from_str(text)? {
            Value::Object(map) => Ok(map),
            _ => Err(Error::protocol("embedded JSON is not an object")),
        },
        _ => Err(Error::protocol("expected a JSON object")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srp::Encoding;

    fn authenticated_session() -> SrpSession {
        SrpSession::restore(
            Encoding::Base64,
            "dGVzdC1pZGVudGl0eS0xMg==".to_string(),
            crate::crypto::from_bytes_be(&[0x5a; 32]),
        )
    }

    #[test]
    fn capabilities_request_is_just_a_command() {
        let json = serde_json::to_string(&Messages::get_capabilities()).unwrap();
        assert_eq!(json, r#"{"cmd":14}"#);
    }

    #[test]
    fn handshake_request_has_the_expected_shape() {
        let session = SrpSession::new(Encoding::Base64);
        let request = Messages::request_challenge(&session, "Arc").unwrap();
        let json: Value = serde_json::to_value(&request).unwrap();

        assert_eq!(json["cmd"], 2);
        assert!(json.get("payload").is_none());
        assert_eq!(json["msg"]["QID"], "m0");
        assert_eq!(json["msg"]["HSTBRSR"], "Arc");

        use base64::Engine as _;
        let pake = base64::engine::general_purpose::STANDARD
            .decode(json["msg"]["PAKE"].as_str().unwrap())
            .unwrap();
        let pake: Value = serde_json::from_slice(&pake).unwrap();
        assert_eq!(pake["TID"], session.username());
        assert_eq!(pake["MSG"], 0);
        assert_eq!(pake["VER"], "1.0");
        assert_eq!(pake["PROTO"], serde_json::json!([1]));
        // A is base64 of the minimal-length 3072-bit public key.
        let a = Encoding::Base64
            .decode(pake["A"].as_str().unwrap())
            .unwrap();
        assert!(a.len() <= 384 && a.len() >= 380);
    }

    #[test]
    fn data_request_embeds_payload_as_a_json_string() {
        let session = authenticated_session();
        let request = Messages::login_names_for_url(&session, "example.com").unwrap();
        let json: Value = serde_json::to_value(&request).unwrap();

        assert_eq!(json["cmd"], 4);
        assert_eq!(json["tabId"], 1);
        assert_eq!(json["frameId"], 1);
        assert_eq!(json["url"], "example.com");

        let payload: Value = serde_json::from_str(json["payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["QID"], "CmdGetLoginNames4URL");
        assert_eq!(payload["SMSG"]["TID"], session.username());
        // SDATA is ciphertext || tag || iv, base64-encoded.
        let sdata = Encoding::Base64
            .decode(payload["SMSG"]["SDATA"].as_str().unwrap())
            .unwrap();
        assert!(sdata.len() > crate::crypto::IV_LEN + 16);
    }

    #[test]
    fn each_command_uses_the_documented_code() {
        let session = authenticated_session();
        let code = |request: Request| serde_json::to_value(&request).unwrap()["cmd"].clone();

        assert_eq!(
            code(Messages::login_names_for_url(&session, "a").unwrap()),
            4
        );
        assert_eq!(
            code(Messages::password_for_url(&session, "a", "u").unwrap()),
            5
        );
        assert_eq!(
            code(Messages::new_account_for_url(&session, "a", "u", "p").unwrap()),
            7
        );
        assert_eq!(
            code(Messages::list_one_time_codes(&session, "a").unwrap()),
            16
        );
        assert_eq!(
            code(Messages::get_one_time_code(&session, "a").unwrap()),
            17
        );
    }

    #[test]
    fn new_account_request_sends_empty_current_item_fields() {
        let session = authenticated_session();
        let request = Messages::new_account_for_url(&session, "site", "user", "pw").unwrap();
        let json: Value = serde_json::to_value(&request).unwrap();
        let payload: Value = serde_json::from_str(json["payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["QID"], "CmdNewAccount4URL");

        // Decrypting proves the plaintext shape, since the body is sealed.
        let sdata = Encoding::Base64
            .decode(payload["SMSG"]["SDATA"].as_str().unwrap())
            .unwrap();
        let (body, iv) = sdata.split_at(sdata.len() - crate::crypto::IV_LEN);
        let mut reordered = iv.to_vec();
        reordered.extend_from_slice(body);
        let plaintext: Value = serde_json::from_slice(&session.open(&reordered).unwrap()).unwrap();

        assert_eq!(plaintext["ACT"], 4);
        assert_eq!(plaintext["URL"], "");
        assert_eq!(plaintext["USR"], "");
        assert_eq!(plaintext["PWD"], "");
        assert_eq!(plaintext["NURL"], "site");
        assert_eq!(plaintext["NUSR"], "user");
        assert_eq!(plaintext["NPWD"], "pw");
    }

    #[test]
    fn one_time_code_requests_use_frame_urls() {
        let session = authenticated_session();
        let request = Messages::list_one_time_codes(&session, "http://example.com").unwrap();
        let json: Value = serde_json::to_value(&request).unwrap();
        assert!(
            json.get("url").is_none(),
            "OTP commands carry the URL only in frameURLs"
        );

        let payload: Value = serde_json::from_str(json["payload"].as_str().unwrap()).unwrap();
        let sdata = Encoding::Base64
            .decode(payload["SMSG"]["SDATA"].as_str().unwrap())
            .unwrap();
        let (body, iv) = sdata.split_at(sdata.len() - crate::crypto::IV_LEN);
        let mut reordered = iv.to_vec();
        reordered.extend_from_slice(body);
        let plaintext: Value = serde_json::from_slice(&session.open(&reordered).unwrap()).unwrap();

        assert_eq!(plaintext["ACT"], 5);
        assert_eq!(plaintext["TYPE"], "oneTimeCodes");
        assert_eq!(
            plaintext["frameURLs"],
            serde_json::json!(["http://example.com"])
        );
    }

    #[test]
    fn handshake_reply_parses_from_payload_or_msg() {
        use base64::Engine as _;
        let pake = base64::engine::general_purpose::STANDARD
            .encode(br#"{"TID":"abc","MSG":1,"PROTO":1,"VER":"1.0","B":"Qg==","s":"Uw=="}"#);

        for field in ["payload", "msg"] {
            let raw = serde_json::json!({ "cmd": 2, field: { "PAKE": pake } });
            let response: Response = serde_json::from_value(raw).unwrap();
            let handshake = response.handshake().unwrap();
            assert_eq!(handshake.tid, "abc");
            assert!(handshake.is_stage(MsgType::ServerKeyExchange));
            assert_eq!(handshake.server_public.as_deref(), Some("Qg=="));
            assert_eq!(handshake.salt.as_deref(), Some("Uw=="));
        }
    }

    #[test]
    fn stage_comparison_tolerates_stringly_typed_msg() {
        let mut pake: ServerPake = serde_json::from_str(r#"{"TID":"a","MSG":"3"}"#).unwrap();
        assert!(pake.is_stage(MsgType::ServerVerification));
        assert!(!pake.is_stage(MsgType::ServerKeyExchange));

        pake.msg = Value::from(3);
        assert!(pake.is_stage(MsgType::ServerVerification));

        pake.msg = Value::Null;
        assert!(!pake.is_stage(MsgType::ServerVerification));
    }

    #[test]
    fn secure_message_accepts_smsg_as_object_or_string() {
        let inline = serde_json::json!({
            "payload": { "SMSG": { "TID": "t", "SDATA": "AA==" } }
        });
        let embedded = serde_json::json!({
            "payload": { "SMSG": r#"{"TID":"t","SDATA":"AA=="}"# }
        });
        let stringly = serde_json::json!({
            "payload": r#"{"SMSG":{"TID":"t","SDATA":"AA=="}}"#
        });

        for raw in [inline, embedded, stringly] {
            let response: Response = serde_json::from_value(raw).unwrap();
            let smsg = response.secure_message().unwrap();
            assert_eq!(smsg.tid, "t");
            assert_eq!(smsg.sdata, "AA==");
        }
    }

    #[test]
    fn unsolicited_commands_are_recognized() {
        for code in [3, 8, 9, 10, 11, 12, 13, 15, 1984] {
            assert!(
                Command::is_unsolicited(code),
                "{code} should be a push message"
            );
        }
        for code in [2, 4, 5, 7, 14, 16, 17] {
            assert!(
                !Command::is_unsolicited(code),
                "{code} is a reply, not a push"
            );
        }
    }

    #[test]
    fn command_descriptions_name_known_codes() {
        assert_eq!(Command::describe(2), "HANDSHAKE (2)");
        assert_eq!(Command::describe(4711), "cmd 4711");
    }
}
