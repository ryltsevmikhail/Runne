use serde::{Deserialize, Serialize};
use std::future::Future;

use crate::protected_activation::{PermissionControlContextV1, PermissionControlErrorV1};
use crate::{ApiPrincipalId, PermissionModeHostErrorV1};
use runne_domain::id::CommandId;

pub const MAX_NATIVE_PENDING_PAGE_SIZE_V2: usize = 32;

/// Non-proof protected-channel request context for a durable pending mode command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeNativePendingContextV2 {
    pub runtime_authority: String,
    pub store_lineage_id: [u8; 16],
    pub stable_subject_digest: [u8; 32],
    pub protected_launch_authority_id: [u8; 16],
    pub desktop_authority_id: [u8; 16],
    pub daemon_instance_id: [u8; 16],
    pub protected_session_id: [u8; 16],
    pub launch_generation: u64,
    pub native_key_epoch: u64,
    pub command_id: String,
    pub idempotency_key: String,
    pub public_request_digest: [u8; 32],
    pub predecessor_transcript_digest: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl PermissionModeNativePendingContextV2 {
    pub fn control_context(&self) -> Result<PermissionControlContextV1, PermissionControlErrorV1> {
        let command_id = self
            .command_id
            .parse::<runne_domain::id::CommandId>()
            .map_err(|_| PermissionControlErrorV1::InvalidContract)?;
        Ok(PermissionControlContextV1 {
            runtime_authority: self.runtime_authority.clone(),
            store_lineage_id: self.store_lineage_id,
            stable_subject_digest: self.stable_subject_digest,
            protected_launch_authority_id: self.protected_launch_authority_id,
            desktop_authority_id: self.desktop_authority_id,
            daemon_instance_id: self.daemon_instance_id,
            protected_session_id: self.protected_session_id,
            launch_generation: self.launch_generation,
            native_key_epoch: self.native_key_epoch,
            command_id: command_id.into_bytes(),
            idempotency_key: self.idempotency_key.clone(),
            public_request_digest: self.public_request_digest,
            predecessor_transcript_digest: self.predecessor_transcript_digest,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }
}

/// One pending request visible only to the authenticated current principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeNativePendingV2 {
    pub workspace_id: String,
    pub principal_id: String,
    pub context: PermissionModeNativePendingContextV2,
}

/// Bounded read-only page through current-session pending mode requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeNativePendingPageV2 {
    pub pending: Vec<PermissionModeNativePendingV2>,
    pub next_cursor: Option<String>,
}

/// Authenticated, bounded discovery of durable requests for one current principal.
pub trait PermissionModeNativePendingHostV2: Send + Sync {
    fn native_pending(
        &self,
        principal: ApiPrincipalId,
        after: Option<CommandId>,
    ) -> impl Future<Output = Result<PermissionModeNativePendingPageV2, PermissionModeHostErrorV1>> + Send;
}
