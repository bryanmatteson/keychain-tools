//! Public ACL blobs, parsed and produced as structures.
//!
//! Every key blob carries a public ACL between its fixed header and its
//! encrypted region. Apple's serialization of `AclEntryPrototype` is not
//! published in a form this could be built from, so the layout here was
//! recovered from keychains written by `security add-generic-password -A`.
//!
//! What is established, by parsing samples whose item names are 1, 4, 5, 8, 9,
//! 11 and 12 bytes long and re-serializing them byte for byte, is the *shape*:
//!
//! ```text
//! blob  := owner entry, entry count, count x entry
//! entry := kind word, subject words, name, authorization group
//! name  := bytes, NUL terminator, padding to a 4-byte boundary
//! ```
//!
//! The owner entry has one fewer subject word than the others and no
//! authorization group. Field *meanings* are not guessed at: the words whose
//! purpose is unknown are carried in [`Subject::Unknown`] and reproduced as
//! they were read, and the constants this code writes are the ones macOS writes.
//! `Authorization` names only the two tag sets that appear.

use crate::error::{Error, Result};

/// Word that opens every entry. Constant in every sample.
const ENTRY_LEAD: u32 = 0x0000_0000;

/// Second word of every entry. Constant in every sample; purpose unknown.
const SUBJECT_TAG: u32 = 0x0000_007b;

/// Word that opens every subject, before its type. Constant in every sample.
const SUBJECT_LEAD: u32 = 0x0000_0001;

/// Two words that close every subject, before the item name. Constant in every
/// sample; purpose unknown.
const SUBJECT_TRAILER: [u32; 2] = [0x0101_0000, 0x0101_0000];

/// Subject type granting any application.
const SUBJECT_ANY: u32 = 0x0000_0001;

/// Subject type naming one trusted application.
const SUBJECT_TRUSTED_APPLICATION: u32 = 0x0000_0074;

/// Word that follows the trusted-application type. Constant in every sample.
const TRUSTED_APPLICATION_LEAD: u32 = 0x0000_0001;

/// Length of the legacy code hash in a trusted-application block.
const LEGACY_HASH_LEN: usize = 20;

/// Which of the two roles an entry plays in the blob.
///
/// This is *not* a stored field. The word at that position counts the elements
/// in the entry's subject, plus one; the owner entry has no subject and so stores
/// `1`. Reading it as a two-valued kind happens to work for an owner entry and
/// for a subject with one element, and silently mis-encodes a subject with two —
/// which is how a two-application ACL came out malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// The first entry in the blob: no subject, no authorization group.
    Owner,
    /// A subsequent entry: a subject and an authorization group.
    Authorization,
}

/// The authorization tag sets that appear in keychain item ACLs.
///
/// These are `CSSM_ACL_AUTHORIZATION_TAG` values, and the CSSM headers that name
/// them are no longer shipped, so the variants are named for what macOS is
/// *observed* to do with them rather than decoded tag by tag. The distinction
/// matters: when an item names trusted applications, macOS restricts
/// [`Self::ItemAccess`] and leaves [`Self::Tag35`] open, so it is `ItemAccess`
/// that gates use of the item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// Tag `35` alone. Left open to any application even on a restricted item.
    Tag35,
    /// Tags `24, 28, 37, 38, 59, 115` — the set macOS restricts to the trusted
    /// applications, and therefore the entry that governs the item.
    ItemAccess,
    /// Any other tag set, kept as read.
    Tags(Vec<u32>),
}

impl Authorization {
    const TAG_35: [u32; 1] = [35];
    const ITEM_ACCESS: [u32; 6] = [24, 28, 37, 38, 59, 115];

    pub fn from_tags(tags: Vec<u32>) -> Self {
        if tags == Self::TAG_35 {
            Self::Tag35
        } else if tags == Self::ITEM_ACCESS {
            Self::ItemAccess
        } else {
            Self::Tags(tags)
        }
    }

    pub fn tags(&self) -> &[u32] {
        match self {
            Self::Tag35 => &Self::TAG_35,
            Self::ItemAccess => &Self::ITEM_ACCESS,
            Self::Tags(tags) => tags,
        }
    }
}

/// One application an ACL entry trusts.
///
/// The three fields are what macOS stores per trusted application. Only the
/// requirement is evaluated on current systems: zeroing `legacy_hash` and
/// re-signing the key blob leaves `security` reading the item, so an ACL written
/// here supplies zeros for it rather than inventing a value it cannot compute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedApplication {
    /// The application's path, as macOS records it.
    pub path: String,
    /// Legacy CDSA code hash. Not the modern cdhash, and not derivable from it.
    pub legacy_hash: [u8; LEGACY_HASH_LEN],
    /// The application's designated requirement, magic and length header
    /// included — byte-identical to the blob in its own code signature.
    pub requirement: Vec<u8>,
}

impl TrustedApplication {
    /// A trusted application identified by its designated requirement, with the
    /// legacy hash left zeroed.
    pub fn new(path: impl Into<String>, requirement: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            legacy_hash: [0u8; LEGACY_HASH_LEN],
            requirement,
        }
    }

    /// Length of the second length-prefixed field: the path and the requirement.
    fn comment_len(&self) -> usize {
        name_field_len(&self.path) + self.requirement.len()
    }

    fn encoded_len(&self) -> usize {
        // type, lead, hash length, hash, comment length, comment. Blocks abut
        // directly: there is no separator between them.
        4 * 3 + LEGACY_HASH_LEN + 4 + self.comment_len()
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_words(
            out,
            &[SUBJECT_TRUSTED_APPLICATION, TRUSTED_APPLICATION_LEAD],
        );
        push_words(out, &[LEGACY_HASH_LEN as u32]);
        out.extend_from_slice(&self.legacy_hash);
        push_words(out, &[self.comment_len() as u32]);
        out.extend_from_slice(&name_field(&self.path));
        out.extend_from_slice(&self.requirement);
    }
}

/// Who an ACL entry grants access to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// Any application. What `security add-generic-password -A` writes, and what
    /// the owner entry always carries.
    Any,
    /// Only these applications.
    TrustedApplications(Vec<TrustedApplication>),
    /// A shape this build does not model, preserved word for word.
    Unknown(Vec<u32>),
}

impl Subject {
    /// Number of elements the subject contributes to the entry's element count.
    fn element_count(&self) -> usize {
        match self {
            Self::Any => 1,
            Self::TrustedApplications(apps) => apps.len(),
            // An unmodelled subject is reproduced as read, so its count came
            // from the file.
            Self::Unknown(_) => 1,
        }
    }

    /// The words between the subject lead and the trailer.
    fn encoded_len(&self) -> usize {
        match self {
            Self::Any => 4,
            Self::TrustedApplications(apps) => {
                apps.iter().map(TrustedApplication::encoded_len).sum()
            }
            Self::Unknown(words) => 4 * words.len(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Any => push_words(out, &[SUBJECT_ANY]),
            Self::TrustedApplications(apps) => {
                for app in apps {
                    app.write(out);
                }
            }
            Self::Unknown(words) => push_words(out, words),
        }
    }

    /// Paths of the applications this subject trusts.
    pub fn trusted_paths(&self) -> Vec<&str> {
        match self {
            Self::TrustedApplications(apps) => apps.iter().map(|app| app.path.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// One ACL entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    pub kind: EntryKind,
    /// Who the entry grants access to. The owner entry carries no subject type
    /// at all, which is represented as `None`.
    pub subject: Option<Subject>,
    /// The item name the entry names.
    pub name: String,
    /// Present on [`EntryKind::Authorization`] entries.
    pub authorization: Option<Authorization>,
    /// Two words that precede the authorization group; `0` in every sample.
    pub authorization_prefix: [u32; 2],
}

impl AclEntry {
    /// The stored count word: one more than the subject's element count.
    fn element_word(&self) -> u32 {
        1 + self.subject.as_ref().map_or(0, Subject::element_count) as u32
    }

    fn encoded_len(&self) -> usize {
        // lead, tag, kind, subject lead, [subject], trailer, name
        let mut len = 4 * 4 + 4 * SUBJECT_TRAILER.len() + name_field_len(&self.name);
        if let Some(subject) = &self.subject {
            len += subject.encoded_len();
        }
        if let Some(authorization) = &self.authorization {
            len += 4 * (2 + 1 + authorization.tags().len());
        }
        len
    }
}

/// A public ACL blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclBlob {
    /// The first entry, followed by a count of the entries after it.
    pub owner: AclEntry,
    pub entries: Vec<AclEntry>,
}

impl AclBlob {
    /// The ACL macOS writes for an item created with "allow all applications":
    /// an owner entry plus a decrypt entry and an item-operations entry.
    pub fn for_item(name: &str) -> Self {
        Self::for_item_with_subject(name, Subject::Any)
    }

    /// The same three entries, restricted to specific applications.
    ///
    /// macOS restricts the [`Authorization::ItemAccess`] entry and leaves the
    /// other open, which is what `security add-generic-password -T` writes.
    /// Putting the applications on the wrong entry yields an ACL that parses and
    /// looks restricted while granting the item to everyone.
    pub fn for_item_trusting(name: &str, applications: Vec<TrustedApplication>) -> Self {
        Self::for_item_with_subject(name, Subject::TrustedApplications(applications))
    }

    /// Build the standard three entries with `subject` on the entry that governs
    /// use of the item.
    pub fn for_item_with_subject(name: &str, subject: Subject) -> Self {
        Self {
            owner: AclEntry {
                kind: EntryKind::Owner,
                subject: None,
                name: name.to_string(),
                authorization: None,
                authorization_prefix: [0, 0],
            },
            entries: vec![
                AclEntry {
                    kind: EntryKind::Authorization,
                    subject: Some(Subject::Any),
                    name: name.to_string(),
                    authorization: Some(Authorization::Tag35),
                    authorization_prefix: [0, 0],
                },
                AclEntry {
                    kind: EntryKind::Authorization,
                    subject: Some(subject),
                    name: name.to_string(),
                    authorization: Some(Authorization::ItemAccess),
                    authorization_prefix: [0, 0],
                },
            ],
        }
    }

    /// Applications this ACL restricts the item to, across all of its entries.
    pub fn trusted_paths(&self) -> Vec<&str> {
        self.entries
            .iter()
            .flat_map(|entry| entry.subject.iter().flat_map(Subject::trusted_paths))
            .collect()
    }

    /// Trusted applications from the entry that governs item use.
    ///
    /// `None` means the ACL does not have the canonical item-access entry this
    /// library understands. `Some([])` means any application.
    pub fn trusted_applications(&self) -> Option<&[TrustedApplication]> {
        self.entries.iter().find_map(|entry| {
            if entry.authorization.as_ref() != Some(&Authorization::ItemAccess) {
                return None;
            }
            match entry.subject.as_ref()? {
                Subject::Any => Some(&[][..]),
                Subject::TrustedApplications(applications) => Some(applications.as_slice()),
                Subject::Unknown(_) => None,
            }
        })
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = WordReader { data, at: 0 };
        let owner = reader.entry(EntryKind::Owner)?;
        let count = reader.u32()? as usize;
        if count > 64 {
            return Err(Error::format(format!("ACL claims {count} entries")));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(reader.entry(EntryKind::Authorization)?);
        }
        if reader.at != data.len() {
            return Err(Error::format(format!(
                "ACL has {} trailing bytes",
                data.len() - reader.at
            )));
        }
        Ok(Self { owner, entries })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        write_entry(&mut out, &self.owner);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            write_entry(&mut out, entry);
        }
        out
    }

    pub fn encoded_len(&self) -> usize {
        self.owner.encoded_len()
            + 4
            + self
                .entries
                .iter()
                .map(AclEntry::encoded_len)
                .sum::<usize>()
    }

    /// The name every entry refers to, when they agree.
    pub fn item_name(&self) -> Option<&str> {
        let name = self.owner.name.as_str();
        self.entries
            .iter()
            .all(|entry| entry.name == name)
            .then_some(name)
    }
}

fn write_entry(out: &mut Vec<u8>, entry: &AclEntry) {
    push_words(
        out,
        &[ENTRY_LEAD, SUBJECT_TAG, entry.element_word(), SUBJECT_LEAD],
    );
    if let Some(subject) = &entry.subject {
        subject.write(out);
    }
    push_words(out, &SUBJECT_TRAILER);
    out.extend_from_slice(&name_field(&entry.name));
    if let Some(authorization) = &entry.authorization {
        for word in entry.authorization_prefix {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(&(authorization.tags().len() as u32).to_be_bytes());
        for tag in authorization.tags() {
            out.extend_from_slice(&tag.to_be_bytes());
        }
    }
}

struct WordReader<'a> {
    data: &'a [u8],
    at: usize,
}

impl WordReader<'_> {
    fn u32(&mut self) -> Result<u32> {
        let bytes = self
            .data
            .get(self.at..self.at + 4)
            .ok_or_else(|| Error::format("ACL ends mid-word"))?;
        self.at += 4;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn entry(&mut self, kind: EntryKind) -> Result<AclEntry> {
        let lead = self.u32()?;
        if lead != ENTRY_LEAD {
            return Err(Error::format(format!("ACL entry starts with 0x{lead:08x}")));
        }
        let tag = self.u32()?;
        if tag != SUBJECT_TAG {
            return Err(Error::format(format!("ACL subject tag is 0x{tag:08x}")));
        }

        // One more than the number of subject elements that follow.
        let element_word = self.u32()? as usize;
        let elements = element_word
            .checked_sub(1)
            .ok_or_else(|| Error::format("ACL entry claims zero elements"))?;
        if elements > 64 {
            return Err(Error::format(format!(
                "ACL entry claims {elements} subject elements"
            )));
        }
        match kind {
            EntryKind::Owner if elements != 0 => {
                return Err(Error::format(format!(
                    "the owner entry carries {elements} subject elements"
                )));
            }
            EntryKind::Authorization if elements == 0 => {
                return Err(Error::format("an authorization entry carries no subject"));
            }
            _ => {}
        }

        let subject_lead = self.u32()?;
        if subject_lead != SUBJECT_LEAD {
            return Err(Error::format(format!(
                "ACL subject lead is 0x{subject_lead:08x}"
            )));
        }

        // The owner entry carries no subject; the others name one, made of
        // exactly `elements` parts.
        let subject = match kind {
            EntryKind::Owner => None,
            EntryKind::Authorization => Some(self.subject(elements)?),
        };

        for word in SUBJECT_TRAILER {
            let found = self.u32()?;
            if found != word {
                return Err(Error::format(format!(
                    "ACL subject trailer is 0x{found:08x}, expected 0x{word:08x}"
                )));
            }
        }

        let name = self.name()?;
        let (authorization, authorization_prefix) = match kind {
            EntryKind::Owner => (None, [0, 0]),
            EntryKind::Authorization => {
                let prefix = [self.u32()?, self.u32()?];
                let count = self.u32()? as usize;
                if count > 64 {
                    return Err(Error::format(format!("ACL entry claims {count} tags")));
                }
                let mut tags = Vec::with_capacity(count);
                for _ in 0..count {
                    tags.push(self.u32()?);
                }
                (Some(Authorization::from_tags(tags)), prefix)
            }
        };

        Ok(AclEntry {
            kind,
            subject,
            name,
            authorization,
            authorization_prefix,
        })
    }

    /// The subject, made of `elements` parts: either the "any" marker, or one
    /// block per trusted application.
    fn subject(&mut self, elements: usize) -> Result<Subject> {
        match self.peek()? {
            SUBJECT_ANY if elements == 1 => {
                self.u32()?;
                Ok(Subject::Any)
            }
            SUBJECT_TRUSTED_APPLICATION => {
                let mut applications = Vec::with_capacity(elements);
                for _ in 0..elements {
                    applications.push(self.trusted_application()?);
                }
                Ok(Subject::TrustedApplications(applications))
            }
            other => Err(Error::format(format!(
                "unknown ACL subject type 0x{other:08x} with {elements} elements"
            ))),
        }
    }

    fn trusted_application(&mut self) -> Result<TrustedApplication> {
        self.u32()?; // the subject type, already peeked
        let lead = self.u32()?;
        if lead != TRUSTED_APPLICATION_LEAD {
            return Err(Error::format(format!(
                "trusted-application lead is 0x{lead:08x}"
            )));
        }

        let hash_len = self.u32()? as usize;
        if hash_len != LEGACY_HASH_LEN {
            return Err(Error::format(format!(
                "trusted-application hash is {hash_len} bytes, expected {LEGACY_HASH_LEN}"
            )));
        }
        let hash = self.bytes(LEGACY_HASH_LEN)?;

        // One length-prefixed field holds the path and then the requirement.
        let comment_len = self.u32()? as usize;
        let comment = self.bytes(comment_len)?;
        let path_end = comment
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Error::format("trusted-application path is not terminated"))?;
        let path = String::from_utf8_lossy(&comment[..path_end]).into_owned();
        let requirement = comment[name_field_len(&path)..].to_vec();

        Ok(TrustedApplication {
            path,
            legacy_hash: hash.try_into().expect("checked length"),
            requirement,
        })
    }

    fn peek(&self) -> Result<u32> {
        let bytes = self
            .data
            .get(self.at..self.at + 4)
            .ok_or_else(|| Error::format("ACL ends mid-word"))?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let bytes = self
            .data
            .get(self.at..self.at + len)
            .ok_or_else(|| Error::format("ACL field runs past the blob"))?
            .to_vec();
        self.at += len;
        Ok(bytes)
    }

    /// A NUL-terminated name, padded to a 4-byte boundary.
    fn name(&mut self) -> Result<String> {
        let rest = self
            .data
            .get(self.at..)
            .ok_or_else(|| Error::format("ACL ends at a name"))?;
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Error::format("ACL name is not terminated"))?;
        let name = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.at += name_field_len(&name);
        Ok(name)
    }
}

/// Encoded length of a name: the bytes, a NUL, then padding to 4 bytes. A name
/// whose length is already a multiple of 4 still gains a whole word.
fn name_field_len(name: &str) -> usize {
    (name.len() + 1 + 3) & !3
}

fn push_words(out: &mut Vec<u8>, words: &[u32]) {
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
}

fn name_field(name: &str) -> Vec<u8> {
    let mut field = vec![0u8; name_field_len(name)];
    field[..name.len()].copy_from_slice(name.as_bytes());
    field
}

/// The public ACL for an item's key, naming the item.
pub fn item_public_acl(item_name: &str) -> Vec<u8> {
    AclBlob::for_item(item_name).to_bytes()
}

/// The public ACL of the database blob itself, which is the same in every
/// keychain macOS writes and does not follow the entry layout above.
pub fn database_public_acl() -> Vec<u8> {
    DATABASE_PUBLIC_ACL.to_vec()
}

const DATABASE_PUBLIC_ACL: [u8; 28] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_field_is_nul_terminated_and_padded() {
        assert_eq!(name_field("a"), b"a\0\0\0");
        assert_eq!(name_field("abcd"), b"abcd\0\0\0\0");
        assert_eq!(name_field("abcdefgh"), b"abcdefgh\0\0\0\0");
        assert_eq!(name_field("abcdefghi"), b"abcdefghi\0\0\0");
        assert_eq!(name_field("example.com"), b"example.com\0");
        assert_eq!(name_field(""), b"\0\0\0\0");
    }

    #[test]
    fn built_acl_round_trips_through_its_own_parser() {
        for name in ["a", "abcd", "myservice", "example.com", "abcdefghijkl", ""] {
            let blob = AclBlob::for_item(name);
            let bytes = blob.to_bytes();
            assert_eq!(
                bytes.len(),
                blob.encoded_len(),
                "length agrees for {name:?}"
            );

            let parsed = AclBlob::parse(&bytes).unwrap();
            assert_eq!(parsed, blob, "structure survives a round trip for {name:?}");
            assert_eq!(parsed.to_bytes(), bytes);
            assert_eq!(parsed.item_name(), Some(name));
        }
    }

    #[test]
    fn built_acl_has_the_expected_structure() {
        let blob = AclBlob::for_item("myservice");
        assert_eq!(blob.owner.kind, EntryKind::Owner);
        assert!(blob.owner.authorization.is_none());
        assert_eq!(blob.entries.len(), 2);
        assert_eq!(blob.entries[0].authorization, Some(Authorization::Tag35));
        assert_eq!(
            blob.entries[1].authorization,
            Some(Authorization::ItemAccess)
        );
        // The owner entry carries no subject type at all.
        assert!(blob.owner.subject.is_none());
        assert_eq!(blob.entries[0].subject, Some(Subject::Any));
    }

    /// Lengths observed in keychains written by macOS.
    #[test]
    fn acl_lengths_match_the_observed_samples() {
        for (name, expected) in [
            ("a", 148),
            ("abcd", 160),
            ("abcdefgh", 172),
            ("abcdefghijkl", 184),
            ("abcdefghi", 172),
            ("myservice", 172),
            ("other", 160),
            ("example.com", 172),
        ] {
            assert_eq!(item_public_acl(name).len(), expected, "name {name:?}");
        }
    }

    /// The full byte pattern for the one-character sample, transcribed from a
    /// keychain written by `security add-generic-password -A`.
    #[test]
    fn acl_bytes_match_the_observed_sample() {
        let expected = concat!(
            "00000000", "0000007b", "00000001", "00000001", "01010000", "01010000", "61000000",
            "00000002", //
            "00000000", "0000007b", "00000002", "00000001", "00000001", "01010000", "01010000",
            "61000000", "00000000", "00000000", "00000001", "00000023", //
            "00000000", "0000007b", "00000002", "00000001", "00000001", "01010000", "01010000",
            "61000000", "00000000", "00000000", "00000006", "00000018", "0000001c", "00000025",
            "00000026", "0000003b", "00000073",
        );
        // macOS writes the two authorization entries in either order, so the
        // sample is compared as a structure with them sorted.
        let parsed = AclBlob::parse(&hex::decode(expected).unwrap()).unwrap();
        let generated = AclBlob::for_item("a");
        assert_eq!(parsed.owner, generated.owner);
        assert_eq!(sorted_entries(&parsed), sorted_entries(&generated));
        assert_eq!(parsed.encoded_len(), generated.encoded_len());
    }

    /// Entries ordered by their tag sets, for comparing ACLs that macOS may have
    /// written in either order.
    fn sorted_entries(blob: &AclBlob) -> Vec<AclEntry> {
        let mut entries = blob.entries.clone();
        entries.sort_by_key(|entry| {
            entry
                .authorization
                .as_ref()
                .map(|authorization| authorization.tags().to_vec())
        });
        entries
    }

    #[test]
    fn parser_rejects_malformed_blobs() {
        assert!(AclBlob::parse(&[]).is_err());
        assert!(AclBlob::parse(&[0u8; 8]).is_err(), "no subject tag");

        // Trailing bytes mean the layout was misread, so they are an error
        // rather than something to ignore.
        let mut bytes = item_public_acl("a");
        bytes.push(0);
        assert!(AclBlob::parse(&bytes).is_err());

        // An unterminated name.
        let mut bytes = item_public_acl("a");
        let len = bytes.len();
        bytes[24..len.min(28)].fill(0x41);
        assert!(AclBlob::parse(&bytes).is_err());
    }

    #[test]
    fn authorization_tag_sets_are_recognized_and_preserved() {
        assert_eq!(Authorization::from_tags(vec![35]), Authorization::Tag35);
        assert_eq!(
            Authorization::from_tags(vec![24, 28, 37, 38, 59, 115]),
            Authorization::ItemAccess
        );
        let other = Authorization::from_tags(vec![1, 2]);
        assert_eq!(other, Authorization::Tags(vec![1, 2]));
        assert_eq!(other.tags(), &[1, 2]);
    }

    /// The exact bytes macOS wrote for an item created with
    /// `-T /usr/bin/security`, from the subject type onward. Transcribed from a
    /// keychain this machine produced.
    const TRUSTED_SUBJECT_SAMPLE: &str = concat!(
        "00000074", // subject type: trusted application
        "00000001", // lead
        "00000014", // legacy hash length: 20
        "014b034370a7a0b4b319a58e182cc37a320784e2",
        "00000044", // comment length: 68 = path field (20) + requirement (48)
        "2f7573722f62696e2f7365637572697479000000", // "/usr/bin/security" + NUL, padded to 20
        // the binary's designated requirement, magic and all
        // the binary's designated requirement, which itself ends in 00000003
        "fade0c000000003000000001000000060000000200000012",
        "636f6d2e6170706c652e7365637572697479000000000003",
    );

    fn sample_application() -> TrustedApplication {
        TrustedApplication {
            path: "/usr/bin/security".to_string(),
            legacy_hash: hex::decode("014b034370a7a0b4b319a58e182cc37a320784e2")
                .unwrap()
                .try_into()
                .unwrap(),
            requirement: hex::decode(concat!(
                "fade0c000000003000000001000000060000000200000012",
                "636f6d2e6170706c652e7365637572697479000000000003",
            ))
            .unwrap(),
        }
    }

    #[test]
    fn a_trusted_application_block_matches_the_bytes_macos_wrote() {
        let mut out = Vec::new();
        sample_application().write(&mut out);
        assert_eq!(hex::encode(&out), TRUSTED_SUBJECT_SAMPLE.replace(' ', ""));
    }

    #[test]
    fn trusted_application_acls_round_trip() {
        for applications in [
            vec![sample_application()],
            vec![
                sample_application(),
                TrustedApplication::new("/bin/ls", vec![0xfa, 0xde, 0x0c, 0x00, 0, 0, 0, 8]),
            ],
        ] {
            let blob = AclBlob::for_item_trusting("item", applications.clone());
            let bytes = blob.to_bytes();
            assert_eq!(bytes.len(), blob.encoded_len());

            let parsed = AclBlob::parse(&bytes).unwrap();
            assert_eq!(parsed, blob);
            assert_eq!(
                parsed.trusted_paths(),
                applications
                    .iter()
                    .map(|app| app.path.as_str())
                    .collect::<Vec<_>>()
            );
            // Only the item-access entry is restricted; the rest stay open.
            assert_eq!(parsed.entries[0].subject, Some(Subject::Any));
            assert_eq!(
                parsed.entries[1].authorization,
                Some(Authorization::ItemAccess),
                "the restricted entry must be the one macOS restricts"
            );
            assert!(parsed.owner.subject.is_none());
        }
    }

    #[test]
    fn a_new_trusted_application_leaves_the_legacy_hash_zeroed() {
        let app = TrustedApplication::new("/bin/ls", vec![0xfa, 0xde, 0x0c, 0x00, 0, 0, 0, 8]);
        assert_eq!(app.legacy_hash, [0u8; LEGACY_HASH_LEN]);
        // It still round-trips, so a zeroed hash is representable.
        let blob = AclBlob::for_item_trusting("x", vec![app]);
        assert_eq!(AclBlob::parse(&blob.to_bytes()).unwrap(), blob);
    }

    #[test]
    fn an_allow_any_acl_reports_no_trusted_paths() {
        assert!(AclBlob::for_item("x").trusted_paths().is_empty());
    }

    #[test]
    fn database_acl_is_the_observed_length() {
        assert_eq!(database_public_acl().len(), 28);
    }
}
