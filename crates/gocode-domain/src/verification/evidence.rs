use crate::verification::digest::VerificationDigest;
use crate::verification::identity::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceLayer {
    L0,
    L1,
    L2S,
    L2I,
    L3,
    L4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceType {
    TestResult,
    SemanticTrace,
    HumanReview,
    Metric,
    AuditRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SensitivityLabel {
    Public,
    Internal,
    Sensitive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustClass {
    TrustedRuntime,
    TrustedExecutor,
    UntrustedExternal,
    UntrustedFixture,
}

#[derive(Clone, Debug)]
pub struct EvidenceItem {
    pub evidence_ref_id: EvidenceRefID,
    pub run_id: RunID,
    pub profile_id: ProfileID,
    pub profile_digest: VerificationDigest,
    pub layer: EvidenceLayer,
    pub evidence_type: EvidenceType,
    pub evidence_digest: VerificationDigest,
    pub content_ref: String,
    pub source: String,
    pub producer_identity: String,
    pub sensitivity: SensitivityLabel,
    pub verified_by: String,
}

#[derive(Clone, Debug)]
pub struct EvidenceSet {
    pub items: Vec<EvidenceItem>,
}

impl EvidenceSet {
    pub fn new(items: Vec<EvidenceItem>) -> Result<Self, EvidenceSetError> {
        let run_id = items
            .first()
            .map(|i| i.run_id)
            .ok_or(EvidenceSetError::Empty)?;
        let profile_digest = items.first().unwrap().profile_digest.clone();
        for item in &items {
            if item.run_id != run_id {
                return Err(EvidenceSetError::CrossRunBinding);
            }
            if item.profile_digest != profile_digest {
                return Err(EvidenceSetError::CrossProfileBinding);
            }
        }
        // Check for duplicate ref IDs
        let mut ids: Vec<_> = items.iter().map(|i| i.evidence_ref_id).collect();
        ids.sort();
        for w in ids.windows(2) {
            if w[0] == w[1] {
                return Err(EvidenceSetError::DuplicateRef(w[0]));
            }
        }
        Ok(Self { items })
    }
}

#[derive(Debug)]
pub enum EvidenceSetError {
    Empty,
    CrossRunBinding,
    CrossProfileBinding,
    DuplicateRef(EvidenceRefID),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_item(run_id: Uuid, profile_digest: VerificationDigest) -> EvidenceItem {
        EvidenceItem {
            evidence_ref_id: Uuid::now_v7(),
            run_id,
            profile_id: Uuid::now_v7(),
            profile_digest,
            layer: EvidenceLayer::L0,
            evidence_type: EvidenceType::TestResult,
            evidence_digest: crate::verification::digest::VerificationDigest::from_bytes([1u8; 32]),
            content_ref: "blob:abc".into(),
            source: "test".into(),
            producer_identity: "test".into(),
            sensitivity: SensitivityLabel::Public,
            verified_by: "test".into(),
        }
    }

    #[test]
    fn evidence_set_same_run_ok() {
        let rid = Uuid::now_v7();
        let d = crate::verification::digest::VerificationDigest::from_bytes([1u8; 32]);
        assert!(EvidenceSet::new(vec![test_item(rid, d.clone()), test_item(rid, d)]).is_ok());
    }
    #[test]
    fn evidence_set_cross_run_rejected() {
        let d = crate::verification::digest::VerificationDigest::from_bytes([1u8; 32]);
        assert!(
            EvidenceSet::new(vec![
                test_item(Uuid::now_v7(), d.clone()),
                test_item(Uuid::now_v7(), d)
            ])
            .is_err()
        );
    }
    #[test]
    fn evidence_set_duplicate_ref_rejected() {
        let rid = Uuid::now_v7();
        let d = crate::verification::digest::VerificationDigest::from_bytes([1u8; 32]);
        let mut i1 = test_item(rid, d.clone());
        let i2 = i1.clone();
        assert!(EvidenceSet::new(vec![i1, i2]).is_err());
    }
}
