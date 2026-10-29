//! TUI confirmation adapter for the existing durable approval response protocol.
use runne_runtime_client::{
    ApprovalDecisionDto, ApprovalSummaryDto, AuthenticatedRuntimeClient, RuntimeSessionInfo,
};
use sha2::{Digest, Sha256};

pub(super) fn review_key(approval: &ApprovalSummaryDto, session: &RuntimeSessionInfo) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runne:tui-displayed-approval:v1\0");
    // These are closed, safe DTOs, with every scope/version field included.
    hash.update(format!("{approval:?}\0{session:?}"));
    hex::encode(hash.finalize())
}

pub(super) async fn decide(
    client: &AuthenticatedRuntimeClient,
    displayed: ApprovalSummaryDto,
    displayed_key: &str,
    decision: bool,
) -> Result<(), String> {
    if review_key(&displayed, client.session_info()) != displayed_key {
        return Err("Approval or runtime scope changed after display; review it again".into());
    }
    let decision = if decision {
        ApprovalDecisionDto::Approve
    } else {
        ApprovalDecisionDto::Deny
    };
    let id = displayed.approval_id();
    let intent = crate::ApprovalResponseIntent {
        approval_id: id,
        command_id: id,
        idempotency_key: format!("tui-approval:{id}"),
        decision,
    };
    let consent = TerminalConsent {
        displayed: displayed.into(),
        decision,
    };
    #[cfg(target_os = "linux")]
    {
        let state = dirs::state_dir().ok_or("Recovery directory unavailable")?;
        let index = crate::LinuxPermissionRecoveryIndex::new(state);
        super::approval_retry::execute(client, intent, &index, &consent)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (client, intent, consent);
        Err("Terminal approval recovery is unavailable on this platform".into())
    }
}

struct TerminalConsent {
    displayed: crate::ApprovalSnapshot,
    decision: ApprovalDecisionDto,
}
struct TerminalToken {
    digest: [u8; 32],
    expires_at: i64,
}

impl crate::ApprovalConsent for TerminalConsent {
    type Token = TerminalToken;
    fn present(
        &self,
        intent: &crate::ApprovalResponseIntent,
        approval: &crate::ApprovalSnapshot,
        digest: [u8; 32],
    ) -> Result<Self::Token, crate::ApprovalConfirmationError> {
        // A key is authorization only for the snapshot already displayed by this UI.
        if approval != &self.displayed || intent.decision != self.decision {
            return Err(crate::ApprovalConfirmationError::Declined);
        }
        if chrono::Utc::now().timestamp_millis() >= approval.expires_at {
            return Err(crate::ApprovalConfirmationError::Expired);
        }
        Ok(TerminalToken {
            digest,
            expires_at: approval.expires_at,
        })
    }
    fn consume(&self, token: Self::Token, digest: [u8; 32], expires_at: i64) -> bool {
        token.digest == digest
            && token.expires_at == expires_at
            && chrono::Utc::now().timestamp_millis() < expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApprovalConsent;
    #[test]
    fn consent_rejects_same_id_with_changed_version() {
        let id = runne_runtime_client::CanonicalId::now_v7();
        let approval = crate::ApprovalSnapshot {
            approval_id: id,
            task_run_id: id,
            attempt_id: None,
            invocation_id: id,
            action: "edit".into(),
            resource: "file".into(),
            action_digest: [1; 32],
            policy_revision: 1,
            request_version: 1,
            approval_generation: 1,
            expires_at: chrono::Utc::now().timestamp_millis() + 60_000,
            risk_summary: "write".into(),
            state: runne_runtime_client::ApprovalStateDto::Pending,
        };
        let consent = TerminalConsent {
            displayed: approval.clone(),
            decision: ApprovalDecisionDto::Approve,
        };
        let intent = crate::ApprovalResponseIntent {
            approval_id: approval.approval_id,
            command_id: approval.approval_id,
            idempotency_key: "test".into(),
            decision: ApprovalDecisionDto::Approve,
        };
        let mut changed = approval;
        changed.request_version += 1;
        assert!(consent.present(&intent, &changed, [1; 32]).is_err());
    }
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod protocol_tests;
