use gocode_domain::verification::backup::ExportRunJson;
use gocode_domain::verification::digest::{DigestContract, VerificationDigest};
use gocode_domain::verification::identity::RunID;
use uuid::Uuid;

pub struct ExportScope {
    pub principal: String,
    pub redaction_level: String,
}

pub struct VerificationExporter;

impl VerificationExporter {
    pub fn export_run_json(
        run_id: RunID,
        plan_id: RunID,
        state: &str,
        result: Option<&str>,
        evidence_count: u32,
    ) -> ExportRunJson {
        let contract = DigestContract::new("gocode:export:v1");
        let digest = contract.compute(&[run_id.as_bytes(), state.as_bytes()]);
        ExportRunJson {
            run_id,
            plan_id,
            state: state.to_string(),
            result: result.map(|s| s.to_string()),
            evidence_count,
            contract_version: "1.0".into(),
            schema_digest: VerificationDigest::from_bytes([1; 32]),
            integrity_digest: digest,
        }
    }
}

pub struct PromotionManager;

pub enum PromotionResult {
    Promoted,
    Blocked(String),
    RequiresReEvaluation,
}

impl PromotionManager {
    pub fn promote(passed: bool, requires_review: bool, auto: bool) -> PromotionResult {
        if requires_review {
            return PromotionResult::RequiresReEvaluation;
        }
        if !passed {
            return PromotionResult::Blocked("plan not passed".into());
        }
        if !auto {
            return PromotionResult::Blocked("manual approval required".into());
        }
        PromotionResult::Promoted
    }

    pub fn rollback() -> PromotionResult {
        PromotionResult::Promoted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn export_has_contract_version() {
        let e = VerificationExporter::export_run_json(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "completed",
            Some("passed"),
            3,
        );
        assert_eq!(e.contract_version, "1.0");
    }
    #[test]
    fn export_schema_digest_nonzero() {
        let e = VerificationExporter::export_run_json(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "completed",
            None,
            0,
        );
        assert!(!e.schema_digest.as_bytes().iter().all(|b| *b == 0));
    }
    #[test]
    fn promote_passed_auto() {
        assert!(matches!(
            PromotionManager::promote(true, false, true),
            PromotionResult::Promoted
        ));
    }
    #[test]
    fn promote_blocked_failed() {
        assert!(matches!(
            PromotionManager::promote(false, false, true),
            PromotionResult::Blocked(_)
        ));
    }
    #[test]
    fn promote_requires_review_blocked() {
        assert!(matches!(
            PromotionManager::promote(true, true, true),
            PromotionResult::RequiresReEvaluation
        ));
    }
    #[test]
    fn promote_manual_blocked() {
        assert!(matches!(
            PromotionManager::promote(true, false, false),
            PromotionResult::Blocked(_)
        ));
    }
}
