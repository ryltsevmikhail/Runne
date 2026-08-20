//! Exact-document receipt signing and public verification.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, Document, GitSubject, ProjectOwnerSignature, ProjectOwnerTrustConfigV1,
    SchemaDigest, SigningDomain, TrustAnchorState, UnsignedReceipt, canonical_checked_in_receipt,
    canonical_unsigned_receipt, receipt_validation, signing_transcript, verify_trust_config,
};

pub const RECEIPT_SCHEMA: &str = "gocode.project-owner.authority-receipt/1";
pub const PROFILE: &str = "gocode.project-owner.v1-platform-scope/1";
pub const PURPOSE: &str = "V1_PLATFORM_SCOPE_AUTHORIZATION";
pub const ROLE: &str = "PROJECT_OWNER";
pub const REPOSITORY: &str = "gocode";
pub const V1_PLATFORM_SCOPE_DECISION_SCHEMA: &str =
    "gocode.governance.v1-platform-scope-decision/1";

const V1_PLATFORM_SCOPE_DECISION_SCHEMA_SHA256: [u8; 32] = [
    0xdb, 0xa8, 0x9e, 0x59, 0xdf, 0xa2, 0xb9, 0xa2, 0x32, 0x20, 0x33, 0x53, 0xd4, 0x5b, 0x56, 0xe2,
    0x44, 0x97, 0x35, 0x3b, 0x70, 0x1d, 0x31, 0x8e, 0x95, 0x69, 0xfc, 0x3c, 0xb7, 0x91, 0x60, 0x2f,
];
const RECEIPT_SCHEMA_SHA256: [u8; 32] = [
    0xf5, 0x66, 0x1a, 0x98, 0x4c, 0x59, 0x3e, 0xfc, 0x0a, 0x58, 0x51, 0x96, 0x3d, 0x23, 0x98, 0x9a,
    0xac, 0xe6, 0x34, 0x0c, 0xcc, 0x2c, 0x59, 0xe5, 0x5e, 0xdb, 0x9f, 0x05, 0xac, 0xaf, 0xa0, 0x5f,
];

/// Return independent exact schema pins for the V1 platform-scope authorization profile.
#[must_use]
pub fn v1_platform_scope_schema_digests() -> Vec<SchemaDigest> {
    vec![
        SchemaDigest {
            schema_id: V1_PLATFORM_SCOPE_DECISION_SCHEMA.into(),
            schema_sha256: V1_PLATFORM_SCOPE_DECISION_SCHEMA_SHA256,
        },
        SchemaDigest {
            schema_id: RECEIPT_SCHEMA.into(),
            schema_sha256: RECEIPT_SCHEMA_SHA256,
        },
    ]
}

/// A closed exact-purpose profile; wildcard paths are never authority inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurposeProfileV1 {
    /// Purpose bound into the receipt transcript.
    pub purpose: String,
    /// Complete, exact set of regular-blob repository paths.
    pub required_paths: BTreeSet<String>,
    /// Required schema identifier for each schema-bound path.
    pub required_schema_ids: BTreeMap<String, String>,
}

impl PurposeProfileV1 {
    /// The sole V1 platform-scope authorization profile.
    #[must_use]
    pub fn v1_platform_scope() -> Self {
        Self {
            purpose: PURPOSE.into(),
            required_paths: BTreeSet::from([
                "docs/adr/ADR-0027-v1-platform-scope.md".into(),
                "docs/decisions/v1-platform-scope-v1.json".into(),
            ]),
            required_schema_ids: BTreeMap::from([(
                "docs/decisions/v1-platform-scope-v1.json".into(),
                V1_PLATFORM_SCOPE_DECISION_SCHEMA.into(),
            )]),
        }
    }

    /// Validate that bindings equal this profile's exact closed path/schema set.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed binding or profile error for every missing, extra, duplicate,
    /// unsafe, nonregular, or schema-mismatched document.
    pub fn validate_documents(&self, documents: &[DocumentBinding]) -> Result<(), AuthorityError> {
        receipt_validation::validate_documents(self, documents)
    }
}

/// A supplied immutable Git blob binding; this core never invokes Git or reads paths.
///
/// These are subject `S` bindings. Evidence commit `E` is deliberately excluded: `E != S`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentBinding {
    /// Safe repository-relative POSIX path.
    pub path: String,
    /// Git mode, exactly regular non-executable `100644`.
    pub mode: String,
    /// Blob object identifier matching the subject object format.
    pub blob_oid: String,
    /// SHA-256 of exact blob bytes.
    pub content_sha256: String,
    /// Exact blob byte length.
    pub byte_length: u64,
    /// Required document schema identifier, when applicable.
    pub schema_id: Option<String>,
}

/// Signing capability held outside the protocol core.
pub trait Signer {
    /// Sign the exact supplied transcript without retaining its bytes.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed signer error without exposing private signing material.
    fn sign(&self, transcript: &[u8]) -> Result<ProjectOwnerSignature, AuthorityError>;
}

/// Public authority receipt: subject `S`, detached signature, and checked-in receipt digest.
///
/// The evidence child commit `E` carries this receipt but is not a signed subject: `E != S`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedReceipt {
    /// All fields covered by the Ed25519 transcript.
    pub unsigned: UnsignedReceipt,
    /// Detached Ed25519 signature over the canonical unsigned receipt.
    pub signature: ProjectOwnerSignature,
    /// SHA-256 of canonical checked-in receipt bytes, including final LF.
    pub project_owner_authority_receipt_sha256: [u8; 32],
}

/// Sign an exact supplied subject and document set without filesystem or Git access.
///
/// # Errors
///
/// Returns a fail-closed error for unpinned trust, a malformed binding, or a signer mismatch.
pub fn sign_receipt(
    profile: &PurposeProfileV1,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
    subject: GitSubject,
    documents: Vec<DocumentBinding>,
    issued_at: String,
    signer: &dyn Signer,
) -> Result<SignedReceipt, AuthorityError> {
    verify_trust_config(trust, anchor)?;
    receipt_validation::validate_schema_digests(trust)?;
    receipt_validation::validate_subject_bindings(profile, &documents, &subject)?;
    if !receipt_validation::valid_timestamp(&issued_at) {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    let unsigned = UnsignedReceipt {
        schema_version: RECEIPT_SCHEMA.into(),
        repository_id: REPOSITORY.into(),
        role: ROLE.into(),
        purpose: profile.purpose.clone(),
        trust_config_sha256: receipt_validation::hex(&trust.sha256()?),
        key_id: receipt_validation::hex(&trust.key_id),
        key_epoch: trust.epoch,
        subject,
        documents: documents
            .into_iter()
            .map(DocumentBinding::into_document)
            .collect(),
        issued_at,
        profile: PROFILE.into(),
    };
    let canonical = canonical_unsigned_receipt(&unsigned)?;
    let domain = SigningDomain::new(RECEIPT_SCHEMA, &unsigned.purpose, REPOSITORY)?;
    let signature = signer.sign(&signing_transcript(&domain, &canonical))?;
    let key = VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    key.verify_strict(
        &signing_transcript(&domain, &canonical),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    let receipt_sha256 =
        Sha256::digest(canonical_checked_in_receipt(&unsigned, &signature)?).into();
    Ok(SignedReceipt {
        unsigned,
        signature,
        project_owner_authority_receipt_sha256: receipt_sha256,
    })
}

/// Verify public receipt, trust, exact bindings, signature, and checked-in LF digest.
///
/// # Errors
///
/// Returns a fail-closed error; verification uses only supplied public objects and bytes.
pub fn verify_receipt(
    receipt: &SignedReceipt,
    profile: &PurposeProfileV1,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    verify_trust_config(trust, anchor)?;
    receipt_validation::validate_schema_digests(trust)?;
    receipt_validation::validate_receipt_trust(&receipt.unsigned, trust, profile)?;
    let bindings = receipt
        .unsigned
        .documents
        .iter()
        .cloned()
        .map(DocumentBinding::from_document)
        .collect::<Vec<_>>();
    receipt_validation::validate_subject_bindings(profile, &bindings, &receipt.unsigned.subject)?;
    let canonical = canonical_unsigned_receipt(&receipt.unsigned)?;
    let expected_sha256 = Sha256::digest(canonical_checked_in_receipt(
        &receipt.unsigned,
        &receipt.signature,
    )?);
    if receipt.project_owner_authority_receipt_sha256 != expected_sha256.as_slice() {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    let domain = SigningDomain::new(RECEIPT_SCHEMA, &receipt.unsigned.purpose, REPOSITORY)?;
    let key = VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    key.verify_strict(
        &signing_transcript(&domain, &canonical),
        &Signature::from_bytes(&receipt.signature),
    )
    .map_err(|_| AuthorityError::InvalidReceiptSignature)
}

impl DocumentBinding {
    fn into_document(self) -> Document {
        Document {
            path: self.path,
            mode: self.mode,
            blob_oid: self.blob_oid,
            content_sha256: self.content_sha256,
            byte_length: self.byte_length,
            schema_id: self.schema_id,
        }
    }

    pub(crate) fn from_document(document: Document) -> Self {
        Self {
            path: document.path,
            mode: document.mode,
            blob_oid: document.blob_oid,
            content_sha256: document.content_sha256,
            byte_length: document.byte_length,
            schema_id: document.schema_id,
        }
    }
}
