//! Signing, verification, and canonical bytes for version-3 receipts.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::receipt_v3::{
    PROFILE_V3, PURPOSE, PurposeProfileV3, RECEIPT_SCHEMA_V3, REPOSITORY, ROLE,
    VerifiedInitialAuthorization, subject_value_v3,
};
use crate::{
    AuthorityError, Document, DocumentBinding, GitSubject, ProjectOwnerSignature,
    ProjectOwnerTrustConfigV1, Signer, SigningDomain, TrustAnchorState, key_id, receipt_validation,
    signing_transcript, verify_trust_config,
};

/// Unsigned version-3 reconciliation receipt fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedReceiptV3 {
    /// Receipt schema identifier.
    pub schema_version: String,
    /// Bound repository identity.
    pub repository_id: String,
    /// Fixed project-owner role.
    pub role: String,
    /// Fixed reconciliation purpose.
    pub purpose: String,
    /// Digest of the signing trust configuration.
    pub trust_config_sha256: String,
    /// Signing key identifier.
    pub key_id: String,
    /// Signing key epoch.
    pub key_epoch: u64,
    /// Final immutable Git subject.
    pub subject: GitSubject,
    /// Exact closed document bindings.
    pub documents: Vec<Document>,
    /// UTC issuance timestamp.
    pub issued_at: String,
    /// Fixed v3 profile identifier.
    pub profile: String,
    /// Digest of the independently verified initial authorization receipt.
    pub predecessor_receipt_sha256: [u8; 32],
}

/// A signed version-3 reconciliation receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedReceiptV3 {
    /// SHA-256 of canonical checked-in LF-terminated bytes.
    pub project_owner_authority_receipt_sha256: [u8; 32],
    /// Canonical signed fields.
    pub unsigned: UnsignedReceiptV3,
    /// Detached Ed25519 signature.
    pub signature: ProjectOwnerSignature,
    /// Redundant fixed predecessor digest for explicit caller inspection.
    pub predecessor_receipt_sha256: [u8; 32],
}

/// Sign the exact v3 profile after an independently verified initial v2 receipt.
///
/// # Errors
/// Returns a fail-closed error for pins, bindings, trust, predecessor, or signature mismatch.
#[expect(
    clippy::too_many_arguments,
    reason = "each authority boundary input is explicit"
)]
pub fn sign_receipt_v3(
    profile: &PurposeProfileV3,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
    predecessor: &VerifiedInitialAuthorization,
    subject: GitSubject,
    mut documents: Vec<DocumentBinding>,
    issued_at: String,
    signer: &dyn Signer,
) -> Result<SignedReceiptV3, AuthorityError> {
    verify_trust_config(trust, anchor)?;
    profile.validate_trust(trust)?;
    validate(profile, &documents, &subject)?;
    if !receipt_validation::valid_timestamp(&issued_at) {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    documents.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let unsigned = UnsignedReceiptV3 {
        schema_version: RECEIPT_SCHEMA_V3.into(),
        repository_id: REPOSITORY.into(),
        role: ROLE.into(),
        purpose: PURPOSE.into(),
        trust_config_sha256: receipt_validation::hex(&trust.sha256()?),
        key_id: receipt_validation::hex(&key_id(&trust.public_key)),
        key_epoch: trust.epoch,
        subject,
        documents: documents.into_iter().map(document).collect(),
        issued_at,
        profile: PROFILE_V3.into(),
        predecessor_receipt_sha256: predecessor.digest(),
    };
    let canonical = canonical_unsigned_receipt_v3(&unsigned)?;
    let domain = SigningDomain::new(RECEIPT_SCHEMA_V3, PURPOSE, REPOSITORY)?;
    let signature = signer.sign(&signing_transcript(&domain, &canonical))?;
    verify_signature(&signature, trust, &domain, &canonical)?;
    let digest = Sha256::digest(canonical_checked_in_receipt_v3(&unsigned, &signature)?).into();
    Ok(SignedReceiptV3 {
        project_owner_authority_receipt_sha256: digest,
        predecessor_receipt_sha256: predecessor.digest(),
        unsigned,
        signature,
    })
}

/// Verify a v3 reconciliation receipt and its immutable verified predecessor.
///
/// # Errors
/// Returns a fail-closed error for any predecessor, digest, binding, trust, or signature mismatch.
pub fn verify_receipt_v3(
    receipt: &SignedReceiptV3,
    profile: &PurposeProfileV3,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
    predecessor: &VerifiedInitialAuthorization,
) -> Result<(), AuthorityError> {
    verify_trust_config(trust, anchor)?;
    profile.validate_trust(trust)?;
    let fields = &receipt.unsigned;
    if receipt.predecessor_receipt_sha256 != predecessor.digest()
        || fields.predecessor_receipt_sha256 != predecessor.digest()
        || fields.schema_version != RECEIPT_SCHEMA_V3
        || fields.repository_id != REPOSITORY
        || fields.role != ROLE
        || fields.purpose != PURPOSE
        || fields.profile != PROFILE_V3
        || fields.key_id != receipt_validation::hex(&key_id(&trust.public_key))
        || fields.key_epoch != trust.epoch
        || fields.trust_config_sha256 != receipt_validation::hex(&trust.sha256()?)
        || !receipt_validation::valid_timestamp(&fields.issued_at)
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    let bindings = fields
        .documents
        .iter()
        .cloned()
        .map(binding)
        .collect::<Vec<_>>();
    validate(profile, &bindings, &fields.subject)?;
    let canonical = canonical_unsigned_receipt_v3(fields)?;
    if receipt.project_owner_authority_receipt_sha256
        != Sha256::digest(canonical_checked_in_receipt_v3(fields, &receipt.signature)?).as_slice()
    {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    verify_signature(
        &receipt.signature,
        trust,
        &SigningDomain::new(RECEIPT_SCHEMA_V3, PURPOSE, REPOSITORY)?,
        &canonical,
    )
}

/// Canonical unsigned v3 receipt bytes, sorted and LF terminated.
///
/// # Errors
/// Returns an error only when canonical JSON serialization fails.
pub fn canonical_unsigned_receipt_v3(
    receipt: &UnsignedReceiptV3,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = std::collections::BTreeMap::new();
    root.insert(
        "documents",
        Value::Array(receipt.documents.iter().map(value_document).collect()),
    );
    root.insert("issued_at", Value::String(receipt.issued_at.clone()));
    root.insert("key_epoch", Value::Number(receipt.key_epoch.into()));
    root.insert("key_id", Value::String(receipt.key_id.clone()));
    root.insert(
        "predecessor_receipt_sha256",
        Value::String(receipt_validation::hex(&receipt.predecessor_receipt_sha256)),
    );
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
    root.insert("subject", subject_value_v3(&receipt.subject));
    root.insert(
        "trust_config_sha256",
        Value::String(receipt.trust_config_sha256.clone()),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Canonical checked-in v3 receipt bytes including detached signature.
///
/// # Errors
/// Returns an error only when canonical JSON serialization fails.
pub fn canonical_checked_in_receipt_v3(
    receipt: &UnsignedReceiptV3,
    signature: &ProjectOwnerSignature,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root: std::collections::BTreeMap<String, Value> =
        serde_json::from_slice(&canonical_unsigned_receipt_v3(receipt)?)
            .map_err(|_| AuthorityError::Serialization)?;
    root.insert(
        "signature".into(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn validate(
    profile: &PurposeProfileV3,
    documents: &[DocumentBinding],
    subject: &GitSubject,
) -> Result<(), AuthorityError> {
    let width = receipt_validation::subject_oid_width(subject)?;
    profile.validate_documents(documents)?;
    if documents
        .iter()
        .any(|item| !receipt_validation::lower_hex(&item.blob_oid, width))
    {
        return Err(AuthorityError::InvalidDocumentBinding);
    }
    Ok(())
}
fn verify_signature(
    signature: &ProjectOwnerSignature,
    trust: &ProjectOwnerTrustConfigV1,
    domain: &SigningDomain,
    canonical: &[u8],
) -> Result<(), AuthorityError> {
    let key = VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    key.verify_strict(
        &signing_transcript(domain, canonical),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| AuthorityError::InvalidReceiptSignature)
}
fn document(item: DocumentBinding) -> Document {
    Document {
        path: item.path,
        mode: item.mode,
        blob_oid: item.blob_oid,
        content_sha256: item.content_sha256,
        byte_length: item.byte_length,
        schema_id: item.schema_id,
    }
}
pub fn binding(item: Document) -> DocumentBinding {
    DocumentBinding {
        path: item.path,
        mode: item.mode,
        blob_oid: item.blob_oid,
        content_sha256: item.content_sha256,
        byte_length: item.byte_length,
        schema_id: item.schema_id,
    }
}
fn value_document(item: &Document) -> Value {
    let mut value = std::collections::BTreeMap::new();
    value.insert("blob_oid", Value::String(item.blob_oid.clone()));
    value.insert("byte_length", Value::Number(item.byte_length.into()));
    value.insert("content_sha256", Value::String(item.content_sha256.clone()));
    value.insert("mode", Value::String(item.mode.clone()));
    value.insert("path", Value::String(item.path.clone()));
    if let Some(schema_id) = &item.schema_id {
        value.insert("schema_id", Value::String(schema_id.clone()));
    }
    Value::Object(
        value
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
