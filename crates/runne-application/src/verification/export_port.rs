use std::sync::Arc;

use runne_domain::verification::backup::ExportRunJson;
use runne_domain::verification::digest::{DigestContract, VerificationDigest};
use runne_domain::verification::identity::RunID;
use thiserror::Error;

use crate::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};

pub struct ExportScope {
    pub principal: String,
    pub redaction_level: String,
}

/// Failure to produce a synthetic verification export at an outbound boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VerificationOutboundError {
    /// Serialization failed before any bytes were returned.
    #[error("verification export serialization failed")]
    Serialization,
    /// Prohibited content or unavailable classification denied delivery.
    #[error("verification export denied by content policy")]
    PolicyDenied,
}

/// Synthetic verification exporter used to prove the outbound guard contract.
pub struct VerificationExporter {
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl VerificationExporter {
    /// Constructs an exporter with a mandatory prohibited-content guard.
    pub fn new(prohibited_content: Arc<dyn ProhibitedContentPort>) -> Self {
        Self { prohibited_content }
    }

    /// Serializes and inspects a synthetic `ExportRunJson` before returning bytes.
    pub fn export_run_json(
        &self,
        run_id: RunID,
        plan_id: RunID,
        state: &str,
        result: Option<&str>,
        evidence_count: u32,
    ) -> Result<Vec<u8>, VerificationOutboundError> {
        let contract = DigestContract::new("runne:export:v1");
        let digest = contract.compute(&[run_id.as_bytes(), state.as_bytes()]);
        let export = ExportRunJson {
            run_id,
            plan_id,
            state: state.to_string(),
            result: result.map(str::to_owned),
            evidence_count,
            contract_version: "1.0".into(),
            schema_digest: VerificationDigest::from_bytes([1; 32]),
            integrity_digest: digest,
        };
        let bytes = serialize_export(&export)?;
        match self
            .prohibited_content
            .inspect(CanonicalContentBoundary::OutboundDelivery, &bytes)
        {
            Ok(ContentDisposition::Allowed { .. }) => Ok(bytes),
            Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                Err(VerificationOutboundError::PolicyDenied)
            }
        }
    }
}

fn serialize_export(export: &ExportRunJson) -> Result<Vec<u8>, VerificationOutboundError> {
    serde_json::to_vec(&serde_json::json!({
        "runId": export.run_id.to_string(),
        "planId": export.plan_id.to_string(),
        "state": export.state,
        "result": export.result,
        "evidenceCount": export.evidence_count,
        "contractVersion": export.contract_version,
        "schemaDigest": export.schema_digest.as_bytes(),
        "integrityDigest": export.integrity_digest.as_bytes(),
    }))
    .map_err(|_| VerificationOutboundError::Serialization)
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
    use crate::prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ContentGuardError,
    };
    use uuid::Uuid;

    struct AvailableGuard;

    impl ProhibitedContentPort for AvailableGuard {
        fn inspect(
            &self,
            _boundary: CanonicalContentBoundary,
            _bytes: &[u8],
        ) -> Result<ContentDisposition, ContentGuardError> {
            Ok(ContentDisposition::Allowed { policy_epoch: 1 })
        }
    }

    fn exporter() -> VerificationExporter {
        VerificationExporter::new(Arc::new(AvailableGuard))
    }

    #[test]
    fn export_has_contract_version() {
        let bytes = exporter()
            .export_run_json(
                Uuid::now_v7(),
                Uuid::now_v7(),
                "completed",
                Some("passed"),
                3,
            )
            .unwrap();
        let export: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(export["contractVersion"], "1.0");
    }
    #[test]
    fn export_schema_digest_nonzero() {
        let bytes = exporter()
            .export_run_json(Uuid::now_v7(), Uuid::now_v7(), "completed", None, 0)
            .unwrap();
        let export: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            export["schemaDigest"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_u64() != Some(0))
        );
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
