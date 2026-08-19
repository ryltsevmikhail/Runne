use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use crate::AuthorityError;

/// Fixed-size Ed25519 public key bytes.
pub type ProjectOwnerPublicKey = [u8; 32];
/// Fixed-size Ed25519 signature bytes.
pub type ProjectOwnerSignature = [u8; 64];
/// The immutable Git subject bound by an authority receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitSubject {
    pub object_format: String,
    pub commit_oid: String,
    pub tree_oid: String,
}
/// One immutable document bound by an authority receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub path: String,
    pub mode: String,
    pub blob_oid: String,
    pub content_sha256: String,
    pub byte_length: u64,
    pub schema_id: Option<String>,
}
/// The signed receipt fields, excluding its signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedReceipt {
    pub schema_version: String,
    pub repository_id: String,
    pub role: String,
    pub purpose: String,
    pub trust_config_sha256: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub subject: GitSubject,
    pub documents: Vec<Document>,
    pub issued_at: String,
    pub profile: String,
}

impl UnsignedReceipt {
    /// Parse an unsigned receipt after strict duplicate and unknown-field checks.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthorityError`] when the bytes are invalid UTF-8 or JSON,
    /// contain duplicate or unknown fields, or do not match the receipt model.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let source = std::str::from_utf8(bytes).map_err(|_| AuthorityError::InvalidUtf8)?;
        let value = StrictJsonParser::new(source).parse()?;
        reject_unknown_fields(&value, ROOT_FIELDS)?;
        if let Some(subject) = value.field("subject") {
            reject_unknown_fields(subject, SUBJECT_FIELDS)?;
        }
        if let Some(StrictJson::Array(documents)) = value.field("documents") {
            for document in documents {
                reject_unknown_fields(document, DOCUMENT_FIELDS)?;
            }
        }
        let receipt = serde_json::from_value::<Self>(value.into_value())
            .map_err(|_| AuthorityError::InvalidReceipt)?;
        validate_document_paths(&receipt.documents)?;
        Ok(receipt)
    }
}

const ROOT_FIELDS: &[&str] = &[
    "schema_version",
    "repository_id",
    "role",
    "purpose",
    "trust_config_sha256",
    "key_id",
    "key_epoch",
    "subject",
    "documents",
    "issued_at",
    "profile",
];
const SUBJECT_FIELDS: &[&str] = &["object_format", "commit_oid", "tree_oid"];
const DOCUMENT_FIELDS: &[&str] = &[
    "path",
    "mode",
    "blob_oid",
    "content_sha256",
    "byte_length",
    "schema_id",
];

fn reject_unknown_fields(value: &StrictJson, allowed: &[&str]) -> Result<(), AuthorityError> {
    if let StrictJson::Object(entries) = value {
        for (key, _) in entries {
            if !allowed.contains(&key.as_str()) {
                return Err(AuthorityError::UnknownField(key.clone()));
            }
        }
    }
    Ok(())
}

pub fn validate_document_paths(documents: &[Document]) -> Result<(), AuthorityError> {
    let mut paths = HashSet::new();
    for document in documents {
        if !paths.insert(document.path.as_bytes()) {
            return Err(AuthorityError::DuplicateDocumentPath(document.path.clone()));
        }
    }
    Ok(())
}

enum StrictJson {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl StrictJson {
    fn field(&self, wanted: &str) -> Option<&Self> {
        let Self::Object(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find(|(key, _)| key == wanted)
            .map(|(_, value)| value)
    }

    fn into_value(self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(value),
            Self::Number(value) => Value::Number(value),
            Self::String(value) => Value::String(value),
            Self::Array(values) => Value::Array(values.into_iter().map(Self::into_value).collect()),
            Self::Object(entries) => Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, value.into_value()))
                    .collect::<Map<_, _>>(),
            ),
        }
    }
}

struct StrictJsonParser<'a> {
    source: &'a str,
    offset: usize,
}

impl<'a> StrictJsonParser<'a> {
    const fn new(source: &'a str) -> Self {
        Self { source, offset: 0 }
    }

    fn parse(mut self) -> Result<StrictJson, AuthorityError> {
        let value = self.value()?;
        self.whitespace();
        if self.offset == self.source.len() {
            Ok(value)
        } else {
            Err(AuthorityError::InvalidJson)
        }
    }

    fn value(&mut self) -> Result<StrictJson, AuthorityError> {
        self.whitespace();
        match self.peek() {
            Some(b'"') => self.string().map(StrictJson::String),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b't') => self.literal("true", StrictJson::Bool(true)),
            Some(b'f') => self.literal("false", StrictJson::Bool(false)),
            Some(b'n') => self.literal("null", StrictJson::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(AuthorityError::InvalidJson),
        }
    }

    fn object(&mut self) -> Result<StrictJson, AuthorityError> {
        self.take(b'{')?;
        self.whitespace();
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        if self.take_if(b'}') {
            return Ok(StrictJson::Object(entries));
        }
        loop {
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(AuthorityError::DuplicateKey(key));
            }
            self.whitespace();
            self.take(b':')?;
            let value = self.value()?;
            entries.push((key, value));
            self.whitespace();
            if self.take_if(b'}') {
                return Ok(StrictJson::Object(entries));
            }
            self.take(b',')?;
            self.whitespace();
        }
    }

    fn array(&mut self) -> Result<StrictJson, AuthorityError> {
        self.take(b'[')?;
        self.whitespace();
        let mut values = Vec::new();
        if self.take_if(b']') {
            return Ok(StrictJson::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            if self.take_if(b']') {
                return Ok(StrictJson::Array(values));
            }
            self.take(b',')?;
        }
    }

    fn string(&mut self) -> Result<String, AuthorityError> {
        self.whitespace();
        let start = self.offset;
        self.take(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.offset += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return serde_json::from_str(&self.source[start..self.offset])
                    .map_err(|_| AuthorityError::InvalidJson);
            } else if byte < 0x20 {
                return Err(AuthorityError::InvalidJson);
            }
        }
        Err(AuthorityError::InvalidJson)
    }

    fn number(&mut self) -> Result<StrictJson, AuthorityError> {
        let start = self.offset;
        while matches!(self.peek(), Some(byte) if !byte.is_ascii_whitespace() && !b",]}".contains(&byte))
        {
            self.offset += 1;
        }
        serde_json::from_str(&self.source[start..self.offset])
            .map(StrictJson::Number)
            .map_err(|_| AuthorityError::InvalidJson)
    }

    fn literal(&mut self, literal: &str, value: StrictJson) -> Result<StrictJson, AuthorityError> {
        if self.source[self.offset..].starts_with(literal) {
            self.offset += literal.len();
            Ok(value)
        } else {
            Err(AuthorityError::InvalidJson)
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(byte) if byte.is_ascii_whitespace()) {
            self.offset += 1;
        }
    }

    fn take(&mut self, expected: u8) -> Result<(), AuthorityError> {
        if self.take_if(expected) {
            Ok(())
        } else {
            Err(AuthorityError::InvalidJson)
        }
    }

    fn take_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
}
