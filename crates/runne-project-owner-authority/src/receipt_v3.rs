//! Version-3 reconciliation receipts, bound to a verified initial receipt.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{
    AuthorityError, DocumentBinding, ProjectOwnerTrustConfigV1, ProjectOwnerTrustConfigV2,
    ProjectOwnerTrustConfigV3, SchemaDigest, TrustAnchorState,
    receipt_lineage::VerifiedTrustLineage, receipt_validation, verify_receipt_v2_bytes,
};

/// Fixed schema identifier for post-RC0 reconciliation receipts.
pub const RECEIPT_SCHEMA_V3: &str = "runne.project-owner.authority-receipt/3";
/// Fixed reconciliation profile identifier.
pub const PROFILE_V3: &str = "runne.project-owner.post-rc0-document-reconciliation/1";
pub const PURPOSE: &str = "POST_RC0_DOCUMENT_RECONCILIATION";
pub const REPOSITORY: &str = "runne";
pub const ROLE: &str = "PROJECT_OWNER";
const PINS: [(&str, [u8; 32]); 3] = [
    (
        "runne.project-owner.authority-receipt/3",
        [
            0x49, 0x38, 0x64, 0x0a, 0x3f, 0x2c, 0x7e, 0x66, 0xf7, 0x42, 0x59, 0x88, 0xb3, 0xc4,
            0xd3, 0x0b, 0xd8, 0x9f, 0x57, 0x51, 0x4a, 0xea, 0x51, 0x85, 0x76, 0xcd, 0x2c, 0x60,
            0x3b, 0x8d, 0x23, 0x2b,
        ],
    ),
    (
        "runne.rc0.post-rc0-platform-composed-universe/1",
        [
            0xcf, 0xcb, 0x48, 0xc0, 0x81, 0x6c, 0xc8, 0x80, 0x64, 0xe6, 0x4b, 0x81, 0xbf, 0x6e,
            0x9b, 0x27, 0xbb, 0x7d, 0xe7, 0x78, 0xdf, 0xa9, 0xce, 0xeb, 0x59, 0x44, 0x68, 0x83,
            0x42, 0x2b, 0xfb, 0x3b,
        ],
    ),
    (
        "runne.v1-platform-scope-claim-migration/1",
        [
            0x93, 0x84, 0xad, 0xf3, 0xbc, 0x7b, 0xa3, 0x68, 0xca, 0xd0, 0x52, 0x57, 0x3d, 0x04,
            0x83, 0xc0, 0x13, 0xd9, 0x8f, 0xba, 0x5c, 0x24, 0x52, 0xfb, 0x52, 0x1a, 0xa9, 0x11,
            0x09, 0x3d, 0xdb, 0xdb,
        ],
    ),
];
const PATHS: [&str; 28] = [
    "docs/ROADMAP.md",
    "docs/STATUS.md",
    "docs/adr/ADR-0010-sandbox-enforcement.md",
    "docs/adr/README.md",
    "docs/decisions/DECISION_LOG.md",
    "docs/decisions/OPEN_QUESTIONS.md",
    "docs/desktop/07-testing/CI_AND_PLATFORM_MATRIX.md",
    "docs/desktop/09-release/PLATFORM_SUPPORT.md",
    "docs/desktop/ROADMAP.md",
    "docs/desktop/STATUS.md",
    "docs/desktop/adr/ADR-0012-platform-support-floor.md",
    "docs/desktop/adr/README.md",
    "docs/desktop/decisions/DECISION_LOG.md",
    "docs/desktop/decisions/OPEN_QUESTIONS.md",
    "docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md",
    "docs/matrices/REQUIREMENTS_TRACEABILITY.md",
    "docs/matrices/v1-platform-scope-claim-migration-v1.json",
    "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json",
    "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_MANIFEST_V1.md",
    "docs/release/COMPATIBILITY_V1.md",
    "docs/release/POST_RC0_PLATFORM_QUALIFICATION_INTERFACE_V1.md",
    "docs/release/RELEASE_MANIFEST_V1.md",
    "docs/superpowers/specs/2026-07-27-phase6-core-native-qualification-design.md",
    "docs/superpowers/specs/2026-07-27-phase6-security-platform-design.md",
    "docs/superpowers/specs/2026-07-28-phase10-release-qualification-design.md",
    "docs/superpowers/specs/2026-07-31-production-capabilities-program-design.md",
    "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
];

/// A closed reconciliation profile with exact independent schema pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurposeProfileV3 {
    reviewed_schema_digests: Vec<SchemaDigest>,
}

impl PurposeProfileV3 {
    /// Construct the sole reviewed post-RC0 document reconciliation profile.
    #[must_use]
    pub fn post_rc0_document_reconciliation() -> Self {
        Self {
            reviewed_schema_digests: v3_reconciliation_schema_digests(),
        }
    }
    /// Construct the profile only from its exact immutable pin set.
    /// # Errors
    /// Returns an error when pins differ from the reviewed v3 set.
    pub fn with_reviewed_schema_digests(pins: Vec<SchemaDigest>) -> Result<Self, AuthorityError> {
        let value = Self {
            reviewed_schema_digests: pins,
        };
        if value.reviewed_schema_digests != v3_reconciliation_schema_digests() {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        Ok(value)
    }
    /// Validate the exact 28-path regular document set.
    /// # Errors
    /// Returns an error for missing, extra, duplicate, unsafe, or schema-bearing bindings.
    pub fn validate_documents(&self, documents: &[DocumentBinding]) -> Result<(), AuthorityError> {
        if self.reviewed_schema_digests != v3_reconciliation_schema_digests() {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        let mut paths = BTreeSet::new();
        for item in documents {
            receipt_validation::validate_document_binding(item)?;
            let expected_schema = match item.path.as_str() {
                "docs/matrices/v1-platform-scope-claim-migration-v1.json" => {
                    Some("runne.v1-platform-scope-claim-migration/1")
                }
                "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json" => {
                    Some("runne.rc0.post-rc0-platform-composed-universe/1")
                }
                _ => None,
            };
            if item.schema_id.as_deref() != expected_schema || !paths.insert(item.path.as_str()) {
                return Err(AuthorityError::InvalidPurposeProfile);
            }
        }
        if paths.iter().copied().collect::<Vec<_>>() != PATHS {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        Ok(())
    }
    /// Validate an exact trust configuration pin set.
    /// # Errors
    /// Returns an error unless the trust pins match this profile's pins exactly.
    pub fn validate_trust(&self, trust: &ProjectOwnerTrustConfigV1) -> Result<(), AuthorityError> {
        if self.reviewed_schema_digests != v3_reconciliation_schema_digests() {
            return Err(AuthorityError::InvalidPurposeProfile);
        }
        if trust.schema_digests != self.reviewed_schema_digests {
            return Err(AuthorityError::InvalidSchemaDigests);
        }
        Ok(())
    }
    /// Validate the production V2 trust pin union.
    ///
    /// # Errors
    /// Returns an error unless the V2 pins equal the reviewed union exactly.
    pub fn validate_trust_v2(
        &self,
        trust: &ProjectOwnerTrustConfigV2,
    ) -> Result<(), AuthorityError> {
        if self.reviewed_schema_digests != v3_reconciliation_schema_digests()
            || trust.schema_digests != crate::v2_trust_schema_digests()
        {
            return Err(AuthorityError::InvalidSchemaDigests);
        }
        Ok(())
    }
}

/// Return the immutable pin set for reconciliation and its verified predecessor contract.
#[must_use]
pub fn v3_reconciliation_schema_digests() -> Vec<SchemaDigest> {
    PINS.into_iter()
        .map(|(schema_id, schema_sha256)| SchemaDigest {
            schema_id: schema_id.into(),
            schema_sha256,
        })
        .collect()
}

/// Opaque evidence that the initial v2 authorization was fully verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInitialAuthorization {
    digest: [u8; 32],
    lineage: VerifiedTrustLineage,
}

impl VerifiedInitialAuthorization {
    /// Return the verified initial receipt digest without exposing a constructor.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn authorizes_v2(
        &self,
        trust: &ProjectOwnerTrustConfigV2,
    ) -> Result<(), AuthorityError> {
        self.lineage.authorizes_v2(trust)
    }
}

/// Opaque proof that a reconciliation receipt passed strict raw-byte verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDocumentReconciliation {
    digest: [u8; 32],
    lineage: VerifiedTrustLineage,
}

impl VerifiedDocumentReconciliation {
    /// Return the strictly verified reconciliation receipt digest.
    #[must_use]
    pub const fn receipt_sha256(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn authorizes_v3(
        &self,
        trust: &ProjectOwnerTrustConfigV3,
    ) -> Result<(), AuthorityError> {
        self.lineage.authorizes_v3(trust)
    }
}

pub fn verified_document_reconciliation(
    digest: [u8; 32],
    trust: &ProjectOwnerTrustConfigV2,
) -> Result<VerifiedDocumentReconciliation, AuthorityError> {
    Ok(VerifiedDocumentReconciliation {
        digest,
        lineage: VerifiedTrustLineage::v2(trust)?,
    })
}

/// Fixture-only evidence from the V1 trust compatibility verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureVerifiedDocumentReconciliation([u8; 32]);

impl FixtureVerifiedDocumentReconciliation {
    /// Return the fixture verification digest without conferring production predecessor authority.
    #[must_use]
    pub const fn receipt_sha256(&self) -> [u8; 32] {
        self.0
    }
}

pub const fn fixture_verified_document_reconciliation(
    digest: [u8; 32],
) -> FixtureVerifiedDocumentReconciliation {
    FixtureVerifiedDocumentReconciliation(digest)
}

/// Verify strict canonical initial v2 bytes before permitting a v3 predecessor binding.
///
/// # Errors
/// Returns the v2 raw-byte verifier's fail-closed error for a digest, byte, trust, or signature mismatch.
pub fn verify_initial_authorization_v2_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<VerifiedInitialAuthorization, AuthorityError> {
    verify_receipt_v2_bytes(
        bytes,
        expected_sha256,
        &crate::PurposeProfileV2::v1_platform_scope(),
        trust,
        anchor,
    )?;
    Ok(VerifiedInitialAuthorization {
        digest: expected_sha256,
        lineage: VerifiedTrustLineage::v1(trust)?,
    })
}

/// Serialize a Git subject using the v3 canonical field order.
pub fn subject_value_v3(item: &crate::GitSubject) -> Value {
    let mut value = BTreeMap::new();
    value.insert("commit_oid", Value::String(item.commit_oid.clone()));
    value.insert("object_format", Value::String(item.object_format.clone()));
    value.insert("tree_oid", Value::String(item.tree_oid.clone()));
    Value::Object(
        value
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
