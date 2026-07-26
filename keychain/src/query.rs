//! Typed item predicates shared by the library and `kc get`.
//!
//! The surface grammar is deliberately small:
//!
//! ```text
//! field:value
//! field[cd]:pattern
//! field:>=value
//! ```
//!
//! Predicates in an [`Expression`] are ANDed. `%` and `_` use SQL-LIKE
//! semantics; `c` and `d` request case- and diacritic-insensitive text
//! matching.

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

use crate::db::Item;
use crate::error::{Error, Result};
use crate::format::Value;
use crate::schema::RecordType;

/// A conjunction of item predicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expression {
    pub predicates: Vec<Predicate>,
}

impl Expression {
    pub fn new(predicates: Vec<Predicate>) -> Self {
        Self { predicates }
    }

    /// Parse shell-tokenized predicates.
    pub fn parse_predicates(predicates: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self> {
        predicates
            .into_iter()
            .map(|predicate| Predicate::parse(predicate.as_ref()))
            .collect::<Result<Vec<_>>>()
            .map(Self::new)
    }

    /// Parse one explicitly quoted expression, including its inner quotes.
    pub fn parse(expression: &str) -> Result<Self> {
        Self::parse_predicates(tokenize(expression)?)
    }

    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    pub fn matches(&self, item: &Item<'_>) -> Result<bool> {
        for predicate in &self.predicates {
            if !predicate.matches(item)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// One typed comparison against an item field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    pub field: String,
    pub comparison: Comparison,
    pub value: String,
    pub options: MatchOptions,
}

impl Predicate {
    pub fn parse(input: &str) -> Result<Self> {
        let (field_and_options, raw_value) = input.split_once(':').ok_or_else(|| {
            Error::other(format!("expected FIELD:VALUE predicate, got {input:?}"))
        })?;
        let (field, options) = parse_field(field_and_options)?;
        let (comparison, value) = parse_comparison(raw_value);
        if field.is_empty() {
            return Err(Error::other("a query field cannot be empty"));
        }
        if options != MatchOptions::default() && comparison.is_ordering() {
            return Err(Error::other(format!(
                "[c] and [d] cannot modify an ordering comparison in {input:?}"
            )));
        }
        if canonical_field(&field) == "class"
            && comparison == Comparison::Equal
            && options == MatchOptions::default()
            && record_type(value).is_none()
        {
            return Err(Error::other(format!(
                "unknown item class {value:?}; expected generic, internet, appleshare, \
                 certificate, private-key, public-key, or item-key"
            )));
        }
        Ok(Self {
            field: canonical_field(&field).to_string(),
            comparison,
            value: value.to_string(),
            options,
        })
    }

    pub fn matches(&self, item: &Item<'_>) -> Result<bool> {
        let Some(actual) = field_value(item, &self.field) else {
            return Ok(false);
        };
        match actual {
            FieldValue::Text(actual) => self.compare_text(&actual),
            FieldValue::Date(actual) => self.compare_date(&actual),
            FieldValue::Number(actual) => self.compare_number(actual),
            FieldValue::Boolean(actual) => self.compare_boolean(actual),
        }
    }

    fn compare_text(&self, actual: &str) -> Result<bool> {
        let actual = normalize(actual, self.options);
        let wanted = normalize(&self.value, self.options);
        Ok(match self.comparison {
            Comparison::Equal => actual == wanted,
            Comparison::NotEqual => actual != wanted,
            Comparison::Less => actual < wanted,
            Comparison::LessEqual => actual <= wanted,
            Comparison::Greater => actual > wanted,
            Comparison::GreaterEqual => actual >= wanted,
            Comparison::Like => like(&actual, &wanted),
        })
    }

    fn compare_date(&self, actual: &str) -> Result<bool> {
        if self.comparison == Comparison::Like {
            return Err(Error::other(format!(
                "{} is a date field and cannot use wildcards",
                self.field
            )));
        }
        let actual = normalize_timestamp(actual)?;
        let wanted = normalize_timestamp(&self.value)?;
        Ok(compare_ordered(&actual, &wanted, self.comparison))
    }

    fn compare_number(&self, actual: i64) -> Result<bool> {
        if self.comparison == Comparison::Like {
            return Err(Error::other(format!(
                "{} is a number field and cannot use wildcards",
                self.field
            )));
        }
        let wanted: i64 = self.value.parse().map_err(|_| {
            Error::other(format!(
                "{} is a number field; {:?} is not a number",
                self.field, self.value
            ))
        })?;
        Ok(compare_ordered(&actual, &wanted, self.comparison))
    }

    fn compare_boolean(&self, actual: bool) -> Result<bool> {
        let wanted = match self.value.as_str() {
            "true" | "yes" | "1" => true,
            "false" | "no" | "0" => false,
            _ => {
                return Err(Error::other(format!(
                    "{} is a boolean field; expected true or false",
                    self.field
                )));
            }
        };
        match self.comparison {
            Comparison::Equal => Ok(actual == wanted),
            Comparison::NotEqual => Ok(actual != wanted),
            _ => Err(Error::other(format!(
                "{} is a boolean field and only supports = and !=",
                self.field
            ))),
        }
    }
}

/// The operation applied by a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Like,
}

impl Comparison {
    fn is_ordering(self) -> bool {
        matches!(
            self,
            Self::Less | Self::LessEqual | Self::Greater | Self::GreaterEqual
        )
    }
}

/// Unicode matching modifiers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MatchOptions {
    pub case_insensitive: bool,
    pub diacritic_insensitive: bool,
}

enum FieldValue {
    Text(String),
    Date(String),
    Number(i64),
    Boolean(bool),
}

/// Stable public name for a queryable record relation.
pub fn class_name(record_type: RecordType) -> Option<&'static str> {
    match record_type {
        RecordType::GENERIC_PASSWORD => Some("generic"),
        RecordType::INTERNET_PASSWORD => Some("internet"),
        RecordType::APPLESHARE_PASSWORD => Some("appleshare"),
        RecordType::X509_CERTIFICATE | RecordType::CERT => Some("certificate"),
        RecordType::PRIVATE_KEY => Some("private-key"),
        RecordType::PUBLIC_KEY => Some("public-key"),
        RecordType::SYMMETRIC_KEY => Some("item-key"),
        _ => None,
    }
}

/// Resolve a class name accepted by the query language.
pub fn record_type(name: &str) -> Option<RecordType> {
    match name.to_ascii_lowercase().as_str() {
        "generic" => Some(RecordType::GENERIC_PASSWORD),
        "internet" => Some(RecordType::INTERNET_PASSWORD),
        "appleshare" => Some(RecordType::APPLESHARE_PASSWORD),
        "certificate" | "cert" => Some(RecordType::X509_CERTIFICATE),
        "private-key" => Some(RecordType::PRIVATE_KEY),
        "public-key" => Some(RecordType::PUBLIC_KEY),
        "item-key" | "symmetric-key" => Some(RecordType::SYMMETRIC_KEY),
        _ => None,
    }
}

/// Friendly names and native Keychain attribute names share one namespace.
pub fn canonical_field(field: &str) -> &str {
    match field.to_ascii_lowercase().as_str() {
        "class" => "class",
        "record" => "record",
        "label" | "printname" => "PrintName",
        "kind" | "description" | "desc" => "desc",
        "account" | "acct" => "acct",
        "service" | "svce" => "svce",
        "server" | "srvr" => "srvr",
        "security-domain" | "domain" | "sdmn" => "sdmn",
        "path" => "path",
        "port" => "port",
        "protocol" | "ptcl" => "ptcl",
        "auth-type" | "atyp" => "atyp",
        "volume" | "vlme" => "vlme",
        "address" | "addr" => "addr",
        "signature" | "ssig" => "ssig",
        "comment" | "icmt" => "icmt",
        "generic" | "gena" => "gena",
        "created" | "cdat" => "cdat",
        "modified" | "mdat" => "mdat",
        "has-secret" => "has-secret",
        _ => field,
    }
}

fn field_value(item: &Item<'_>, field: &str) -> Option<FieldValue> {
    match field {
        "class" => class_name(item.record_type).map(|value| FieldValue::Text(value.to_string())),
        "record" => Some(FieldValue::Number(i64::from(item.number()))),
        "has-secret" => Some(FieldValue::Boolean(item.has_secret())),
        _ => {
            let value = item.attribute(field)?;
            if crate::db::FOUR_CHAR_CODE_ATTRIBUTES.contains(&field) {
                return item.display_attribute(field).map(FieldValue::Text);
            }
            match value {
                Value::Uint32(value) => Some(FieldValue::Number(i64::from(*value))),
                Value::Sint32(value) => Some(FieldValue::Number(i64::from(*value))),
                Value::Date(bytes) => Some(FieldValue::Date(
                    String::from_utf8_lossy(crate::format::trim_nul(bytes)).into_owned(),
                )),
                _ => item.display_attribute(field).map(FieldValue::Text),
            }
        }
    }
}

fn parse_field(input: &str) -> Result<(String, MatchOptions)> {
    let Some(open) = input.rfind('[') else {
        return Ok((input.to_string(), MatchOptions::default()));
    };
    if !input.ends_with(']') {
        return Err(Error::other(format!(
            "query modifiers must end with ], got {input:?}"
        )));
    }
    let mut options = MatchOptions::default();
    for modifier in input[open + 1..input.len() - 1].chars() {
        match modifier {
            'c' => options.case_insensitive = true,
            'd' => options.diacritic_insensitive = true,
            _ => {
                return Err(Error::other(format!(
                    "unknown query modifier {modifier:?}; expected c or d"
                )));
            }
        }
    }
    Ok((input[..open].to_string(), options))
}

fn parse_comparison(input: &str) -> (Comparison, &str) {
    for (prefix, comparison) in [
        (">=", Comparison::GreaterEqual),
        ("<=", Comparison::LessEqual),
        ("!=", Comparison::NotEqual),
        (">", Comparison::Greater),
        ("<", Comparison::Less),
        ("=", Comparison::Equal),
    ] {
        if let Some(value) = input.strip_prefix(prefix) {
            return (comparison, value);
        }
    }
    if has_wildcards(input) {
        (Comparison::Like, input)
    } else {
        (Comparison::Equal, input)
    }
}

fn has_wildcards(input: &str) -> bool {
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '%' | '_') {
            return true;
        }
    }
    false
}

fn normalize(input: &str, options: MatchOptions) -> String {
    let decomposed = input.nfkd();
    let mut output = String::new();
    for character in decomposed {
        if options.diacritic_insensitive && is_combining_mark(character) {
            continue;
        }
        if options.case_insensitive {
            output.extend(character.to_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn normalize_timestamp(input: &str) -> Result<String> {
    let input = input.trim_end_matches('\0');
    let compact = if input.len() == 15 && input.ends_with('Z') {
        input.to_string()
    } else if input.len() == 20
        && input.as_bytes()[4] == b'-'
        && input.as_bytes()[7] == b'-'
        && input.as_bytes()[10] == b'T'
        && input.as_bytes()[13] == b':'
        && input.as_bytes()[16] == b':'
        && input.ends_with('Z')
    {
        format!(
            "{}{}{}{}{}{}Z",
            &input[0..4],
            &input[5..7],
            &input[8..10],
            &input[11..13],
            &input[14..16],
            &input[17..19]
        )
    } else {
        return Err(Error::other(format!(
            "expected YYYYMMDDhhmmssZ or RFC 3339 UTC timestamp, got {input:?}"
        )));
    };
    if !compact[..14].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::other(format!("invalid timestamp {input:?}")));
    }
    Ok(compact)
}

fn compare_ordered<T: Ord>(actual: &T, wanted: &T, comparison: Comparison) -> bool {
    match comparison {
        Comparison::Equal => actual == wanted,
        Comparison::NotEqual => actual != wanted,
        Comparison::Less => actual < wanted,
        Comparison::LessEqual => actual <= wanted,
        Comparison::Greater => actual > wanted,
        Comparison::GreaterEqual => actual >= wanted,
        Comparison::Like => false,
    }
}

fn like(actual: &str, pattern: &str) -> bool {
    let actual = actual.chars().collect::<Vec<_>>();
    let pattern = like_tokens(pattern);
    let mut previous = vec![false; actual.len() + 1];
    previous[0] = true;

    for token in pattern {
        let mut current = vec![false; actual.len() + 1];
        match token {
            LikeToken::Many => {
                current[0] = previous[0];
                for index in 1..=actual.len() {
                    current[index] = previous[index] || current[index - 1];
                }
            }
            LikeToken::One => {
                current[1..].copy_from_slice(&previous[..actual.len()]);
            }
            LikeToken::Literal(wanted) => {
                for index in 1..=actual.len() {
                    current[index] = previous[index - 1] && actual[index - 1] == wanted;
                }
            }
        }
        previous = current;
    }
    previous[actual.len()]
}

enum LikeToken {
    Many,
    One,
    Literal(char),
}

fn like_tokens(pattern: &str) -> Vec<LikeToken> {
    let mut tokens = Vec::new();
    let mut escaped = false;
    for character in pattern.chars() {
        if escaped {
            tokens.push(LikeToken::Literal(character));
            escaped = false;
        } else {
            match character {
                '\\' => escaped = true,
                '%' => tokens.push(LikeToken::Many),
                '_' => tokens.push(LikeToken::One),
                literal => tokens.push(LikeToken::Literal(literal)),
            }
        }
    }
    if escaped {
        tokens.push(LikeToken::Literal('\\'));
    }
    tokens
}

fn tokenize(input: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') if character == '\'' => quote = None,
            Some('"') if character == '"' => quote = None,
            Some('"') if character == '\\' => escaped = true,
            Some(_) => current.push(character),
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character == '\\' => escaped = true,
            None if character.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(character),
        }
    }
    if quote.is_some() {
        return Err(Error::other("unterminated quote in query expression"));
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comparisons_wildcards_and_modifiers() {
        let expression = Expression::parse(
            r#"class:internet label:"Gmail Account" cdat:<20260515074219Z icmt:%2026% label[cd]:com.%"#,
        )
        .unwrap();
        assert_eq!(expression.predicates.len(), 5);
        assert_eq!(expression.predicates[1].value, "Gmail Account");
        assert_eq!(expression.predicates[2].comparison, Comparison::Less);
        assert_eq!(expression.predicates[3].comparison, Comparison::Like);
        assert!(expression.predicates[4].options.case_insensitive);
        assert!(expression.predicates[4].options.diacritic_insensitive);
    }

    #[test]
    fn like_honors_sql_wildcards_and_escapes() {
        assert!(like("a 2026 note", "%2026%"));
        assert!(like("com.example", "com.%"));
        assert!(like("100%", r"100\%"));
        assert!(!like("1000", r"100\%"));
        assert!(like("abc", "a_c"));
    }

    #[test]
    fn unicode_options_fold_case_and_diacritics() {
        let options = MatchOptions {
            case_insensitive: true,
            diacritic_insensitive: true,
        };
        assert_eq!(normalize("Café", options), normalize("CAFE", options));
    }

    #[test]
    fn timestamps_accept_keychain_and_rfc3339_forms() {
        assert_eq!(
            normalize_timestamp("2026-05-15T07:42:19Z").unwrap(),
            "20260515074219Z"
        );
        assert_eq!(
            normalize_timestamp("20260515074219Z").unwrap(),
            "20260515074219Z"
        );
    }
}
