//! Context manifest domain types — content references with secret boundary.

use crate::id::{AttemptId, ContextManifestId, CycleId, IntegrityDigest, SecretRefId, TaskRunId};

/// Immutable owner-bound reference to a committed context manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextManifestRef {
    /// Manifest identity.
    pub manifest_id: ContextManifestId,
    /// Owning task run.
    pub taskrun_id: TaskRunId,
    /// Owning attempt.
    pub attempt_id: AttemptId,
    /// Loop cycle for which the manifest was assembled.
    pub cycle_id: CycleId,
    /// Immutable manifest revision.
    pub revision: u64,
    /// Context policy revision used for assembly.
    pub policy_revision: String,
    /// Digest of the committed manifest.
    pub integrity_digest: IntegrityDigest,
}

// ── ManifestContentRef ──────────────────────────────────────────────────

/// Content reference in a ContextManifest.
///
/// SecretRef is a separate variant — never wrapped in NonSecretClassificationRef.
/// ClassifiedNonSecret carries immutable classification evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestContentRef {
    /// Classified non-secret content with provenance and digest.
    ClassifiedNonSecret {
        /// Reference to blob or artifact.
        content_ref: BlobOrArtifactRef,
        /// Immutable non-secret classification.
        classification: NonSecretClassificationRef,
        /// Policy revision that produced this classification.
        policy_revision: String,
        /// Integrity digest of the classified content.
        digest: IntegrityDigest,
    },
    /// Opaque secret reference — never contains raw secret bytes.
    Secret(SecretRef),
}

// ── BlobOrArtifactRef ───────────────────────────────────────────────────

/// Reference to a blob or artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobOrArtifactRef {
    Blob {
        blob_id: String,
        digest: IntegrityDigest,
    },
    Artifact {
        artifact_id: String,
        digest: IntegrityDigest,
    },
}

// ── NonSecretClassificationRef ──────────────────────────────────────────

/// Immutable evidence that content is non-secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonSecretClassificationRef {
    /// Classification identifier.
    pub classification_id: String,
    /// Producer of the classification.
    pub producer: String,
    /// Sensitivity level (Public, Internal, Sensitive).
    pub sensitivity: DataSensitivity,
    /// Integrity digest of classification evidence.
    pub digest: IntegrityDigest,
}

// ── DataSensitivity ─────────────────────────────────────────────────────

/// Data sensitivity level. All three are valid; secrets are prohibited separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSensitivity {
    Public,
    Internal,
    Sensitive,
}

// ── SecretRef ───────────────────────────────────────────────────────────

/// Opaque reference to a secret — never contains secret bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// Secret identifier.
    pub secret_ref_id: SecretRefId,
    /// Secret metadata version.
    pub metadata_version: u64,
    /// Integrity digest of secret metadata.
    pub metadata_digest: IntegrityDigest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{AttemptId, ContextManifestId, CycleId, SecretRefId, TaskRunId};

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    #[test]
    fn secret_ref_separate_from_classified() {
        let secret = ManifestContentRef::Secret(SecretRef {
            secret_ref_id: UUID.parse::<SecretRefId>().unwrap(),
            metadata_version: 7,
            metadata_digest: IntegrityDigest::from_bytes([0u8; 32]),
        });

        let classified = ManifestContentRef::ClassifiedNonSecret {
            content_ref: BlobOrArtifactRef::Blob {
                blob_id: "blob1".into(),
                digest: IntegrityDigest::from_bytes([1u8; 32]),
            },
            classification: NonSecretClassificationRef {
                classification_id: "cls1".into(),
                producer: "system".into(),
                sensitivity: DataSensitivity::Internal,
                digest: IntegrityDigest::from_bytes([2u8; 32]),
            },
            policy_revision: "v1".into(),
            digest: IntegrityDigest::from_bytes([3u8; 32]),
        };

        // Secret is not ClassifiedNonSecret
        assert!(matches!(secret, ManifestContentRef::Secret(_)));
        assert!(matches!(
            classified,
            ManifestContentRef::ClassifiedNonSecret { .. }
        ));
    }

    #[test]
    fn context_manifest_ref_binds_owner_attempt_cycle_and_policy() {
        let reference = ContextManifestRef {
            manifest_id: UUID.parse::<ContextManifestId>().unwrap(),
            taskrun_id: UUID.parse::<TaskRunId>().unwrap(),
            attempt_id: UUID.parse::<AttemptId>().unwrap(),
            cycle_id: UUID.parse::<CycleId>().unwrap(),
            revision: 4,
            policy_revision: "context-policy-v3".into(),
            integrity_digest: IntegrityDigest::from_bytes([4; 32]),
        };

        assert_eq!(reference.revision, 4);
        assert_eq!(reference.policy_revision, "context-policy-v3");
    }

    #[test]
    fn sensitive_label_accepted() {
        let classified = ManifestContentRef::ClassifiedNonSecret {
            content_ref: BlobOrArtifactRef::Artifact {
                artifact_id: "art1".into(),
                digest: IntegrityDigest::from_bytes([0u8; 32]),
            },
            classification: NonSecretClassificationRef {
                classification_id: "cls1".into(),
                producer: "system".into(),
                sensitivity: DataSensitivity::Sensitive,
                digest: IntegrityDigest::from_bytes([1u8; 32]),
            },
            policy_revision: "v1".into(),
            digest: IntegrityDigest::from_bytes([2u8; 32]),
        };

        assert!(matches!(
            classified,
            ManifestContentRef::ClassifiedNonSecret {
                classification: NonSecretClassificationRef {
                    sensitivity: DataSensitivity::Sensitive,
                    ..
                },
                ..
            }
        ));
    }
}
