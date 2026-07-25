//! Decrypted payloads and the records inside them.
//!
//! Field names in the helper's replies are terse and not fully documented
//! (`USR`, `PWD`, `sites`), and they differ between password and one-time-code
//! items. Parsing is therefore deliberately tolerant: known spellings are
//! mapped, unknown fields are ignored, and [`Payload::raw`] keeps the original
//! document so `--raw` can show exactly what arrived.

use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result, Status};

/// A decrypted reply body.
#[derive(Debug, Clone)]
pub struct Payload {
    pub status: Status,
    /// Set when the item can only be filled after a local (Touch ID) prompt.
    pub requires_local_authentication: bool,
    pub entries: Vec<Value>,
    /// The decrypted document, verbatim.
    pub raw: Value,
}

impl Payload {
    pub fn parse(json: &[u8]) -> Result<Self> {
        let raw: Value = serde_json::from_slice(json)?;

        let status = raw
            .get("STATUS")
            .and_then(Value::as_i64)
            .map(Status::from_code)
            // A reply with no STATUS at all is not something to guess about.
            .ok_or_else(|| Error::protocol("decrypted payload has no STATUS field"))?;

        let entries = match raw.get("Entries") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };

        Ok(Self {
            status,
            requires_local_authentication: raw
                .get("RequiresUserAuthenticationToFill")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            entries,
            raw,
        })
    }

    /// Turn a non-success status into an error.
    pub fn ensure_success(&self) -> Result<()> {
        if self.status.is_success() {
            Ok(())
        } else {
            Err(Error::Status(self.status))
        }
    }

    pub fn passwords(&self) -> Vec<PasswordRecord> {
        self.entries
            .iter()
            .map(PasswordRecord::from_value)
            .collect()
    }

    pub fn one_time_codes(&self) -> Vec<OtpRecord> {
        self.entries.iter().map(OtpRecord::from_value).collect()
    }
}

/// A login item: user name, the sites it applies to, and the secret when the
/// request asked for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasswordRecord {
    pub username: String,
    pub sites: Vec<String>,
    /// `None` for metadata-only replies (`ACT: GHOST_SEARCH`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl PasswordRecord {
    fn from_value(entry: &Value) -> Self {
        let username = first_string(entry, &["USR", "username", "user"]).unwrap_or_default();

        let mut sites = match entry.get("sites") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        if sites.is_empty()
            && let Some(site) = first_string(entry, &["URL", "url", "domain", "site"])
        {
            sites.push(site);
        }

        Self {
            username,
            sites,
            password: first_string(entry, &["PWD", "password"]),
        }
    }

    /// Primary site, for single-line display.
    pub fn site(&self) -> &str {
        self.sites.first().map(String::as_str).unwrap_or("")
    }
}

/// A one-time-code item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OtpRecord {
    pub username: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `None` when the reply only listed the item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl OtpRecord {
    fn from_value(entry: &Value) -> Self {
        Self {
            username: first_string(entry, &["username", "USR", "user"]).unwrap_or_default(),
            domain: first_string(entry, &["domain", "URL", "url", "site"]).unwrap_or_default(),
            source: first_string(entry, &["source"]),
            code: first_string(entry, &["code", "OTP", "otp"]),
        }
    }
}

/// First key that holds a non-empty string.
fn first_string(entry: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| entry.get(*key))
        .filter_map(Value::as_str)
        .find(|text| !text.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload(value: Value) -> Payload {
        Payload::parse(value.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn parses_a_login_name_listing() {
        let parsed = payload(json!({
            "STATUS": 0,
            "Entries": [
                { "USR": "ada@example.com", "sites": ["example.com", "www.example.com"] },
                { "USR": "grace@example.com", "sites": ["example.com"], "PWD": "hunter2" },
            ]
        }));

        parsed.ensure_success().unwrap();
        let records = parsed.passwords();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].username, "ada@example.com");
        assert_eq!(records[0].sites, vec!["example.com", "www.example.com"]);
        assert_eq!(records[0].site(), "example.com");
        assert_eq!(records[0].password, None);
        assert_eq!(records[1].password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn non_success_status_becomes_an_error() {
        let parsed = payload(json!({ "STATUS": 3 }));
        assert_eq!(parsed.status, Status::NoResults);
        assert!(parsed.entries.is_empty());
        assert!(matches!(
            parsed.ensure_success(),
            Err(Error::Status(Status::NoResults))
        ));
    }

    #[test]
    fn missing_status_is_a_protocol_error() {
        assert!(Payload::parse(br#"{"Entries":[]}"#).is_err());
        assert!(Payload::parse(b"not json").is_err());
    }

    #[test]
    fn local_authentication_flag_is_surfaced() {
        assert!(
            payload(json!({ "STATUS": 0, "RequiresUserAuthenticationToFill": true }))
                .requires_local_authentication
        );
        assert!(!payload(json!({ "STATUS": 0 })).requires_local_authentication);
    }

    #[test]
    fn parses_one_time_codes() {
        let parsed = payload(json!({
            "STATUS": 0,
            "Entries": [
                { "username": "ada", "domain": "example.com", "source": "example.com", "code": "123456" },
                { "username": "grace", "domain": "example.com" },
            ]
        }));

        let records = parsed.one_time_codes();
        assert_eq!(records[0].code.as_deref(), Some("123456"));
        assert_eq!(records[0].source.as_deref(), Some("example.com"));
        assert_eq!(records[1].code, None);
        assert_eq!(records[1].username, "grace");
    }

    #[test]
    fn tolerates_alternate_spellings_and_missing_fields() {
        let parsed = payload(json!({
            "STATUS": 0,
            "Entries": [
                { "username": "ada", "URL": "example.com", "password": "pw" },
                { },
                { "USR": "", "sites": [], "PWD": "" },
            ]
        }));

        let records = parsed.passwords();
        assert_eq!(records[0].username, "ada");
        assert_eq!(records[0].sites, vec!["example.com"]);
        assert_eq!(records[0].password.as_deref(), Some("pw"));

        // Unknown shapes degrade to empty rather than dropping the row.
        assert_eq!(records[1].username, "");
        assert_eq!(records[1].site(), "");
        assert_eq!(records[1].password, None);
        // Empty strings are treated as absent.
        assert_eq!(records[2].password, None);
    }

    #[test]
    fn entries_that_are_not_an_array_are_ignored() {
        let parsed = payload(json!({ "STATUS": 0, "Entries": "unexpected" }));
        assert!(parsed.entries.is_empty());
        assert!(parsed.passwords().is_empty());
    }

    #[test]
    fn raw_document_is_preserved_for_inspection() {
        let parsed = payload(json!({ "STATUS": 0, "SomethingNew": [1, 2, 3] }));
        assert_eq!(parsed.raw["SomethingNew"], json!([1, 2, 3]));
    }

    #[test]
    fn records_serialize_without_absent_fields() {
        let record = PasswordRecord {
            username: "ada".into(),
            sites: vec!["a.com".into()],
            password: None,
        };
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            r#"{"username":"ada","sites":["a.com"]}"#
        );
    }
}
