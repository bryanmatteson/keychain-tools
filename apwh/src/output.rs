//! Rendering and input validation for the CLI.
//!
//! Kept out of `main.rs` so the formatting rules and the PIN check are unit
//! testable. Two output modes: aligned text for people, and a stable JSON
//! envelope for scripts.

use serde::Serialize;
use serde_json::{Value, json};

use crate::entries::{OtpRecord, PasswordRecord};
use crate::error::Error;

/// Which representation the caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Aligned columns and bare values.
    Text,
    /// `{"ok": ..., ...}` envelope.
    Json,
    /// The decrypted payload exactly as the helper sent it.
    Raw,
}

impl Format {
    pub fn select(json: bool, raw: bool) -> Self {
        match (raw, json) {
            (true, _) => Self::Raw,
            (false, true) => Self::Json,
            (false, false) => Self::Text,
        }
    }
}

/// Successful JSON envelope.
pub fn ok_envelope(results: impl Serialize) -> Value {
    json!({ "ok": true, "results": results })
}

/// Failure JSON envelope, carrying the same status the exit code reports.
pub fn error_envelope(error: &Error) -> Value {
    json!({
        "ok": false,
        "error": { "code": error.status().code(), "message": error.to_string() },
    })
}

pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Aligned `USERNAME  SITE` table, with the password column when present.
pub fn password_table(records: &[PasswordRecord]) -> String {
    if records.is_empty() {
        return String::new();
    }
    let show_password = records.iter().any(|record| record.password.is_some());

    let mut rows: Vec<Vec<String>> = vec![if show_password {
        vec!["USERNAME".into(), "SITE".into(), "PASSWORD".into()]
    } else {
        vec!["USERNAME".into(), "SITE".into()]
    }];
    for record in records {
        let mut row = vec![
            dash_if_empty(&record.username),
            dash_if_empty(record.site()),
        ];
        if show_password {
            row.push(record.password.clone().unwrap_or_else(|| "-".into()));
        }
        rows.push(row);
    }
    align(&rows)
}

/// Aligned table of one-time-code items.
pub fn otp_table(records: &[OtpRecord]) -> String {
    if records.is_empty() {
        return String::new();
    }
    let show_code = records.iter().any(|record| record.code.is_some());

    let mut rows: Vec<Vec<String>> = vec![if show_code {
        vec!["USERNAME".into(), "DOMAIN".into(), "CODE".into()]
    } else {
        vec!["USERNAME".into(), "DOMAIN".into()]
    }];
    for record in records {
        let mut row = vec![
            dash_if_empty(&record.username),
            dash_if_empty(&record.domain),
        ];
        if show_code {
            row.push(record.code.clone().unwrap_or_else(|| "-".into()));
        }
        rows.push(row);
    }
    align(&rows)
}

/// Two-column `key: value` block, for `apwh status`.
pub fn field_list(fields: &[(&str, String)]) -> String {
    let width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    fields
        .iter()
        .map(|(label, value)| format!("{label:<width$}  {value}", width = width + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Check a PIN before spending a round trip on it.
///
/// macOS shows six digits. Length is bounded rather than fixed at six so a
/// future dialog with a different length is not blocked by this check, but a
/// non-numeric entry (a password typed by mistake) is rejected outright.
pub fn validate_pin(pin: &str) -> crate::error::Result<String> {
    let pin = pin.trim().to_string();
    if pin.is_empty() {
        return Err(Error::other("no PIN entered"));
    }
    if !pin.chars().all(|character| character.is_ascii_digit()) {
        return Err(Error::other("the PIN macOS displays is all digits"));
    }
    if !(4..=12).contains(&pin.chars().count()) {
        return Err(Error::other(format!(
            "expected a 6-digit PIN, got {} characters",
            pin.chars().count()
        )));
    }
    Ok(pin)
}

fn dash_if_empty(text: &str) -> String {
    if text.is_empty() {
        "-".to_string()
    } else {
        text.to_string()
    }
}

/// Left-align every column to the widest cell, in display characters.
fn align(rows: &[Vec<String>]) -> String {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0usize; columns];
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    rows.iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(index, cell)| {
                    // No trailing padding on the last column.
                    if index + 1 == row.len() {
                        cell.clone()
                    } else {
                        let pad = widths[index] - cell.chars().count();
                        format!("{cell}{}", " ".repeat(pad))
                    }
                })
                .collect::<Vec<_>>()
                .join("  ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Status;

    fn record(username: &str, site: &str, password: Option<&str>) -> PasswordRecord {
        PasswordRecord {
            username: username.into(),
            sites: vec![site.into()],
            password: password.map(str::to_string),
        }
    }

    #[test]
    fn format_selection_prefers_raw_then_json() {
        assert_eq!(Format::select(false, false), Format::Text);
        assert_eq!(Format::select(true, false), Format::Json);
        assert_eq!(Format::select(false, true), Format::Raw);
        assert_eq!(Format::select(true, true), Format::Raw);
    }

    #[test]
    fn password_table_omits_the_password_column_when_no_secrets_came_back() {
        let table = password_table(&[
            record("ada@example.com", "example.com", None),
            record("bo", "b.example.com", None),
        ]);
        let lines: Vec<&str> = table.lines().collect();

        assert_eq!(lines[0], "USERNAME         SITE");
        assert_eq!(lines[1], "ada@example.com  example.com");
        assert_eq!(lines[2], "bo               b.example.com");
        assert!(!table.contains("PASSWORD"));
    }

    #[test]
    fn password_table_shows_secrets_and_marks_missing_cells() {
        let table = password_table(&[
            record("ada", "a.com", Some("hunter2")),
            record("", "", None),
        ]);
        let lines: Vec<&str> = table.lines().collect();

        assert_eq!(lines[0], "USERNAME  SITE   PASSWORD");
        assert_eq!(lines[1], "ada       a.com  hunter2");
        assert_eq!(lines[2], "-         -      -");
    }

    #[test]
    fn empty_results_render_as_nothing() {
        assert_eq!(password_table(&[]), "");
        assert_eq!(otp_table(&[]), "");
    }

    #[test]
    fn otp_table_hides_the_code_column_when_listing() {
        let listed = otp_table(&[OtpRecord {
            username: "ada".into(),
            domain: "example.com".into(),
            source: None,
            code: None,
        }]);
        assert_eq!(listed.lines().next().unwrap(), "USERNAME  DOMAIN");

        let fetched = otp_table(&[OtpRecord {
            username: "ada".into(),
            domain: "example.com".into(),
            source: Some("example.com".into()),
            code: Some("123456".into()),
        }]);
        assert!(fetched.lines().next().unwrap().ends_with("CODE"));
        assert!(fetched.lines().nth(1).unwrap().ends_with("123456"));
    }

    #[test]
    fn no_row_has_trailing_whitespace() {
        let table = password_table(&[record("a-very-long-username", "x.com", Some("p"))]);
        for line in table.lines() {
            assert_eq!(line, line.trim_end(), "trailing space in {line:?}");
        }
    }

    #[test]
    fn field_list_aligns_labels() {
        let rendered = field_list(&[
            ("service", "running".to_string()),
            ("session", "authenticated".to_string()),
        ]);
        assert_eq!(rendered, "service   running\nsession   authenticated");
    }

    #[test]
    fn json_envelopes_carry_status_codes() {
        let ok = ok_envelope(vec![record("ada", "a.com", None)]);
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["results"][0]["username"], "ada");

        let failure = error_envelope(&Error::Status(Status::NoResults));
        assert_eq!(failure["ok"], false);
        assert_eq!(failure["error"]["code"], 3);
        assert_eq!(failure["error"]["message"], "no matching items");
    }

    #[test]
    fn pin_validation_accepts_digits_and_rejects_everything_else() {
        assert_eq!(validate_pin(" 482915\n").unwrap(), "482915");
        assert_eq!(validate_pin("1234").unwrap(), "1234");

        assert!(validate_pin("").is_err());
        assert!(validate_pin("   ").is_err());
        assert!(validate_pin("12a456").is_err());
        assert!(validate_pin("hunter2").is_err());
        assert!(validate_pin("123").is_err());
        assert!(validate_pin("1234567890123").is_err());
    }
}
