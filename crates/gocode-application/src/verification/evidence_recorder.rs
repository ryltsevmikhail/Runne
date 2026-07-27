use async_trait::async_trait;
use gocode_domain::verification::digest::VerificationDigest;
use gocode_domain::verification::evidence::*;
use gocode_domain::verification::identity::*;

/// Public entry point for recording verification evidence.
/// record_raw is the ONLY public method — no scanner bypass possible.
#[async_trait]
pub trait EvidenceRecorder: Send + Sync {
    /// Scan raw content for secrets → compute digest → commit metadata.
    /// Rejects BEFORE persistence if content contains secrets.
    async fn record_raw(
        &self,
        run_id: RunID,
        profile_id: ProfileID,
        profile_digest: VerificationDigest,
        layer: EvidenceLayer,
        evidence_type: EvidenceType,
        raw_content: &[u8],
        producer_identity: &str,
        sensitivity: SensitivityLabel,
    ) -> Result<EvidenceRefID, EvidenceRecorderError>;

    async fn validate(&self, ref_id: &EvidenceRefID) -> Result<(), EvidenceRecorderError>;
    async fn get(&self, ref_id: &EvidenceRefID) -> Result<EvidenceItem, EvidenceRecorderError>;
    async fn list_for_run(
        &self,
        run_id: &RunID,
    ) -> Result<Vec<EvidenceRefID>, EvidenceRecorderError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceRecorderError {
    #[error("secret content detected")]
    SecretContentDetected,
    #[error("evidence already recorded")]
    AlreadyRecorded,
    #[error("invalid digest")]
    InvalidDigest,
    #[error("profile mismatch")]
    ProfileMismatch,
    #[error("untrusted source")]
    UntrustedSource,
    #[error("evidence not found")]
    NotFound,
}
