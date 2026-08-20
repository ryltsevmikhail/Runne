//! Version-2 exact-document receipt signing and public verification.
use crate::{
    AuthorityError, Document, DocumentBinding, GitSubject, ProjectOwnerSignature,
    ProjectOwnerTrustConfigV1, SchemaDigest, SignedReceipt, Signer, SigningDomain,
    TrustAnchorState, UnsignedReceipt, canonical_checked_in_receipt, canonical_unsigned_receipt,
    receipt_validation, signing_transcript, verify_trust_config,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub const RECEIPT_SCHEMA_V2: &str = "gocode.project-owner.authority-receipt/2";
pub const PROFILE_V2: &str = "gocode.project-owner.v1-platform-scope/2";
const PURPOSE: &str = "V1_PLATFORM_SCOPE_AUTHORIZATION";
const ROLE: &str = "PROJECT_OWNER";
const REPOSITORY: &str = "gocode";
const DECISION_SCHEMA: &str = "gocode.governance.v1-platform-scope-decision/1";
const DECISION_SCHEMA_SHA256: [u8; 32] = [
    0xdb, 0xa8, 0x9e, 0x59, 0xdf, 0xa2, 0xb9, 0xa2, 0x32, 0x20, 0x33, 0x53, 0xd4, 0x5b, 0x56, 0xe2,
    0x44, 0x97, 0x35, 0x3b, 0x70, 0x1d, 0x31, 0x8e, 0x95, 0x69, 0xfc, 0x3c, 0xb7, 0x91, 0x60, 0x2f,
];
const RECEIPT_SCHEMA_SHA256: [u8; 32] = [
    0xf9, 0xc2, 0x1f, 0x44, 0x85, 0xb6, 0x6b, 0xec, 0x34, 0xc8, 0xfd, 0x07, 0x40, 0x2c, 0xd3, 0xb7,
    0x33, 0x1b, 0xf5, 0x5b, 0x87, 0x4d, 0x52, 0x83, 0x3f, 0xf4, 0x7e, 0xe0, 0x38, 0xd4, 0x82, 0xea,
];
/// Return the reviewed v2 receipt and decision-schema trust pins.
#[must_use]
pub fn v2_platform_scope_schema_digests() -> Vec<SchemaDigest> {
    vec![
        SchemaDigest {
            schema_id: DECISION_SCHEMA.into(),
            schema_sha256: DECISION_SCHEMA_SHA256,
        },
        SchemaDigest {
            schema_id: RECEIPT_SCHEMA_V2.into(),
            schema_sha256: RECEIPT_SCHEMA_SHA256,
        },
    ]
}

/// A closed v2 platform-scope profile with an exact reviewed trust-schema pin set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurposeProfileV2 {
    /// Purpose bound into the receipt transcript.
    pub purpose: String,
    /// Complete, exact set of regular-blob repository paths.
    pub required_paths: BTreeSet<String>,
    /// Required schema identifier for each schema-bound path.
    pub required_schema_ids: BTreeMap<String, String>,
    reviewed_schema_digests: Vec<SchemaDigest>,
}

impl PurposeProfileV2 {
    /// Build the currently reviewed v2 platform-scope profile.
    /// # Panics
    /// Panics only if the crate's built-in reviewed schema pins become internally invalid.
    #[must_use]
    pub fn v1_platform_scope() -> Self {
        Self::with_reviewed_schema_digests(v2_platform_scope_schema_digests())
            .expect("built-in v2 schema pins are sorted and complete")
    }

    /// Build the profile with every independently reviewed successor-lineage schema pin.
    /// # Errors
    /// Returns an error unless pins are the exact reviewed v2 set, in canonical order.
    pub fn with_reviewed_schema_digests(
        reviewed_schema_digests: Vec<SchemaDigest>,
    ) -> Result<Self, AuthorityError> {
        let profile = Self {
            purpose: PURPOSE.into(),
            required_paths: BTreeSet::from([
                "docs/adr/ADR-0027-v1-platform-scope.md".into(),
                "docs/decisions/v1-platform-scope-v1.json".into(),
                "docs/desktop/adr/ADR-0015-v1-platform-scope.md".into(),
                "docs/schemas/v1-platform-scope-decision-v1.schema.json".into(),
            ]),
            required_schema_ids: BTreeMap::from([(
                "docs/decisions/v1-platform-scope-v1.json".into(),
                DECISION_SCHEMA.into(),
            )]),
            reviewed_schema_digests,
        };
        profile.validate_profile()?;
        Ok(profile)
    }

    /// Validate that bindings equal this profile's exact closed path/schema set.
    /// # Errors
    /// Returns a fail-closed binding or profile error for every missing, extra, duplicate,
    /// unsafe, nonregular, or schema-mismatched document.
    pub fn validate_documents(&self, documents: &[DocumentBinding]) -> Result<(), AuthorityError> {
        self.validate_profile()?;
        let mut paths = BTreeSet::new();
        let mut schemas = BTreeMap::new();
        for document in documents {
            receipt_validation::validate_document_binding(document)?;
            if !paths.insert(document.path.clone()) {
                return Err(AuthorityError::InvalidPurposeProfile);
            }
            schemas.insert(document.path.clone(), document.schema_id.clone());
        }
        if paths != self.required_paths
            || schemas.len() != self.required_paths.len()
            || schemas
                .into_iter()
                .any(|(path, value)| self.required_schema_ids.get(&path) != value.as_ref())
        {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        Ok(())
    }

    fn validate_profile(&self) -> Result<(), AuthorityError> {
        let base = v2_platform_scope_schema_digests();
        if self.purpose != PURPOSE
            || self.required_paths
                != BTreeSet::from([
                    "docs/adr/ADR-0027-v1-platform-scope.md".into(),
                    "docs/decisions/v1-platform-scope-v1.json".into(),
                    "docs/desktop/adr/ADR-0015-v1-platform-scope.md".into(),
                    "docs/schemas/v1-platform-scope-decision-v1.schema.json".into(),
                ])
            || self.required_schema_ids
                != BTreeMap::from([(
                    "docs/decisions/v1-platform-scope-v1.json".into(),
                    DECISION_SCHEMA.into(),
                )])
            || self
                .required_paths
                .iter()
                .any(|path| path.contains(['*', '?', '[', ']']))
            || self.reviewed_schema_digests != base
        {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        Ok(())
    }
}

/// Sign an exact supplied v2 subject and document set without filesystem or Git access.
/// # Errors
/// Returns a fail-closed error for unpinned trust, malformed bindings, or signer mismatch.
pub fn sign_receipt_v2(
    profile: &PurposeProfileV2,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
    subject: GitSubject,
    mut documents: Vec<DocumentBinding>,
    issued_at: String,
    signer: &dyn Signer,
) -> Result<SignedReceipt, AuthorityError> {
    verify_trust_config(trust, anchor)?;
    validate_trust(profile, trust)?;
    validate_bindings(profile, &documents, &subject)?;
    if !receipt_validation::valid_timestamp(&issued_at) {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    documents.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let unsigned = UnsignedReceipt {
        schema_version: RECEIPT_SCHEMA_V2.into(),
        repository_id: REPOSITORY.into(),
        role: ROLE.into(),
        purpose: profile.purpose.clone(),
        trust_config_sha256: receipt_validation::hex(&trust.sha256()?),
        key_id: receipt_validation::hex(&trust.key_id),
        key_epoch: trust.epoch,
        subject,
        documents: documents.into_iter().map(binding_document).collect(),
        issued_at,
        profile: PROFILE_V2.into(),
    };
    let canonical = canonical_unsigned_receipt(&unsigned)?;
    let domain = SigningDomain::new(RECEIPT_SCHEMA_V2, &unsigned.purpose, REPOSITORY)?;
    let signature = signer.sign(&signing_transcript(&domain, &canonical))?;
    verify_signature(&signature, trust, &domain, &canonical)?;
    Ok(SignedReceipt {
        project_owner_authority_receipt_sha256: Sha256::digest(canonical_checked_in_receipt(
            &unsigned, &signature,
        )?)
        .into(),
        unsigned,
        signature,
    })
}

/// Verify public v2 receipt, trust, exact bindings, signature, and checked-in LF digest.
/// # Errors
/// Returns a fail-closed error; verification uses only supplied public objects and bytes.
pub fn verify_receipt_v2(
    receipt: &SignedReceipt,
    profile: &PurposeProfileV2,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    verify_trust_config(trust, anchor)?;
    validate_trust(profile, trust)?;
    if receipt.unsigned.schema_version != RECEIPT_SCHEMA_V2
        || receipt.unsigned.repository_id != REPOSITORY
        || receipt.unsigned.role != ROLE
        || receipt.unsigned.purpose != profile.purpose
        || receipt.unsigned.profile != PROFILE_V2
        || receipt.unsigned.key_id != receipt_validation::hex(&crate::key_id(&trust.public_key))
        || receipt.unsigned.key_epoch != trust.epoch
        || receipt.unsigned.trust_config_sha256 != receipt_validation::hex(&trust.sha256()?)
        || !receipt_validation::valid_timestamp(&receipt.unsigned.issued_at)
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    let bindings = receipt
        .unsigned
        .documents
        .iter()
        .cloned()
        .map(document_binding)
        .collect::<Vec<_>>();
    validate_bindings(profile, &bindings, &receipt.unsigned.subject)?;
    let canonical = canonical_unsigned_receipt(&receipt.unsigned)?;
    if receipt.project_owner_authority_receipt_sha256
        != Sha256::digest(canonical_checked_in_receipt(
            &receipt.unsigned,
            &receipt.signature,
        )?)
        .as_slice()
    {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    let domain = SigningDomain::new(RECEIPT_SCHEMA_V2, &receipt.unsigned.purpose, REPOSITORY)?;
    verify_signature(&receipt.signature, trust, &domain, &canonical)
}

fn validate_trust(
    profile: &PurposeProfileV2,
    trust: &ProjectOwnerTrustConfigV1,
) -> Result<(), AuthorityError> {
    profile.validate_profile()?;
    if trust.schema_digests != profile.reviewed_schema_digests {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    Ok(())
}

fn validate_bindings(
    profile: &PurposeProfileV2,
    documents: &[DocumentBinding],
    subject: &GitSubject,
) -> Result<(), AuthorityError> {
    let width = receipt_validation::subject_oid_width(subject)?;
    profile.validate_documents(documents)?;
    if documents
        .iter()
        .any(|document| !receipt_validation::lower_hex(document.blob_oid.as_str(), width))
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

fn binding_document(binding: DocumentBinding) -> Document {
    Document {
        path: binding.path,
        mode: binding.mode,
        blob_oid: binding.blob_oid,
        content_sha256: binding.content_sha256,
        byte_length: binding.byte_length,
        schema_id: binding.schema_id,
    }
}

fn document_binding(document: Document) -> DocumentBinding {
    DocumentBinding {
        path: document.path,
        mode: document.mode,
        blob_oid: document.blob_oid,
        content_sha256: document.content_sha256,
        byte_length: document.byte_length,
        schema_id: document.schema_id,
    }
}
