use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::{
    AuthorityError, Document, ProjectOwnerSignature, UnsignedReceipt,
    model::validate_document_paths,
};

/// Domain-separated context for an authority signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningDomain {
    bytes: Vec<u8>,
}

impl SigningDomain {
    /// Bind a signature to schema, purpose, repository, and `PROJECT_OWNER`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::LengthTooLarge`] when the domain cannot fit
    /// its required 32-bit length prefix.
    pub fn new(schema: &str, purpose: &str, repository: &str) -> Result<Self, AuthorityError> {
        let fields = [
            schema.as_bytes(),
            purpose.as_bytes(),
            repository.as_bytes(),
            b"PROJECT_OWNER",
        ];
        let mut bytes = Vec::new();
        for field in fields {
            let field_length =
                u32::try_from(field.len()).map_err(|_| AuthorityError::LengthTooLarge)?;
            bytes.extend_from_slice(&field_length.to_be_bytes());
            bytes.extend_from_slice(field);
        }
        u32::try_from(bytes.len()).map_err(|_| AuthorityError::LengthTooLarge)?;
        Ok(Self { bytes })
    }
}

/// Serialize unsigned receipt JSON with sorted UTF-8 keys and one final LF.
///
/// # Errors
///
/// Returns [`AuthorityError::Serialization`] if JSON serialization fails.
pub fn canonical_unsigned_receipt(receipt: &UnsignedReceipt) -> Result<Vec<u8>, AuthorityError> {
    validate_document_paths(&receipt.documents)?;
    let documents = receipt.documents.iter().collect::<Vec<_>>();
    let mut documents = documents;
    documents.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let mut root = BTreeMap::new();
    root.insert(
        "documents",
        Value::Array(documents.into_iter().map(document_value).collect()),
    );
    root.insert("issued_at", Value::String(receipt.issued_at.clone()));
    root.insert("key_epoch", Value::Number(receipt.key_epoch.into()));
    root.insert("key_id", Value::String(receipt.key_id.clone()));
    root.insert("profile", Value::String(receipt.profile.clone()));
    root.insert("purpose", Value::String(receipt.purpose.clone()));
    root.insert(
        "repository_id",
        Value::String(receipt.repository_id.clone()),
    );
    root.insert("role", Value::String(receipt.role.clone()));
    root.insert(
        "schema_version",
        Value::String(receipt.schema_version.clone()),
    );
    root.insert("subject", subject_value(receipt));
    root.insert(
        "trust_config_sha256",
        Value::String(receipt.trust_config_sha256.clone()),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Serialize the checked-in receipt, including its detached signature, with one final LF.
///
/// # Errors
///
/// Returns [`AuthorityError::Serialization`] if the unsigned canonical receipt cannot be
/// converted into the closed checked-in representation.
pub fn canonical_checked_in_receipt(
    receipt: &UnsignedReceipt,
    signature: &ProjectOwnerSignature,
) -> Result<Vec<u8>, AuthorityError> {
    let mut value: Value = serde_json::from_slice(&canonical_unsigned_receipt(receipt)?)
        .map_err(|_| AuthorityError::Serialization)?;
    let object = value.as_object_mut().ok_or(AuthorityError::Serialization)?;
    object.insert(
        "signature".into(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    let mut bytes = serde_json::to_vec(&value).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Build the exact length-prefixed transcript for Ed25519 signing.
///
/// # Panics
///
/// Panics only on a platform where the supplied payload length cannot fit in `u64`.
#[must_use]
pub fn signing_transcript(domain: &SigningDomain, canonical_unsigned_receipt: &[u8]) -> Vec<u8> {
    framed_transcript(&domain.bytes, canonical_unsigned_receipt)
        .expect("SigningDomain guarantees a representable framing")
}

/// Frame an exact domain-separated payload for Ed25519 signing.
///
/// The encoding is `u32be(domain_length) || domain || u64be(payload_length) || payload`.
///
/// # Errors
///
/// Returns [`AuthorityError::LengthTooLarge`] when either length is not representable.
pub fn framed_transcript(domain: &[u8], payload: &[u8]) -> Result<Vec<u8>, AuthorityError> {
    let domain_length = u32::try_from(domain.len()).map_err(|_| AuthorityError::LengthTooLarge)?;
    let payload_length =
        u64::try_from(payload.len()).map_err(|_| AuthorityError::LengthTooLarge)?;
    let mut transcript = Vec::with_capacity(12 + domain.len() + payload.len());
    transcript.extend_from_slice(&domain_length.to_be_bytes());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&payload_length.to_be_bytes());
    transcript.extend_from_slice(payload);
    Ok(transcript)
}

fn document_value(document: &Document) -> Value {
    let mut value = BTreeMap::new();
    value.insert("blob_oid", Value::String(document.blob_oid.clone()));
    value.insert("byte_length", Value::Number(document.byte_length.into()));
    value.insert(
        "content_sha256",
        Value::String(document.content_sha256.clone()),
    );
    value.insert("mode", Value::String(document.mode.clone()));
    value.insert("path", Value::String(document.path.clone()));
    if let Some(schema_id) = &document.schema_id {
        value.insert("schema_id", Value::String(schema_id.clone()));
    }
    Value::Object(
        value
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn subject_value(receipt: &UnsignedReceipt) -> Value {
    let mut value = BTreeMap::new();
    value.insert(
        "commit_oid",
        Value::String(receipt.subject.commit_oid.clone()),
    );
    value.insert(
        "object_format",
        Value::String(receipt.subject.object_format.clone()),
    );
    value.insert("tree_oid", Value::String(receipt.subject.tree_oid.clone()));
    Value::Object(
        value
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
