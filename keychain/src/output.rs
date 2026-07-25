//! Shared text/JSON rendering helpers for callers (including the `kc` CLI): the two shapes its output takes.

use serde_json::Value;

/// A JSON envelope, indented, so it reads in a terminal and pipes into `jq`.
pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Two-column `key  value` block, with the keys padded to a common width.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_list_pads_to_the_widest_key() {
        let rendered = field_list(&[("keychain", "demo".to_string()), ("iv", "0011".to_string())]);
        assert_eq!(rendered, "keychain   demo\niv         0011");
    }

    #[test]
    fn json_is_pretty_printed() {
        let rendered = pretty(&serde_json::json!({ "ok": true }));
        assert_eq!(rendered, "{\n  \"ok\": true\n}");
    }
}
