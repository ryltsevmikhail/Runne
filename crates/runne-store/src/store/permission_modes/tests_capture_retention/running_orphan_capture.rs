//! Immutable capture projection; native ownership remains with the real handle.
use crate::store::LocalCommandPermissionCaptureV1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capture {
    pub task: String,
    pub attempt: String,
    pub fence: u64,
    pub invocation: String,
    pub canonical_digest: [u8; 32],
    pub binding_digest: [u8; 32],
    pub binding: Vec<u8>,
    pub owner: [u8; 16],
    pub generation: u64,
}
impl Capture {
    pub(super) fn of(value: &LocalCommandPermissionCaptureV1) -> Self {
        Self {
            task: value.taskrun_id.to_string(),
            attempt: value.attempt_id.to_string(),
            fence: value.fence,
            invocation: value.invocation_id.to_string(),
            canonical_digest: value.canonical_binding_digest,
            binding_digest: value.binding_digest,
            binding: value.binding.clone(),
            owner: value.native_owner_id,
            generation: value.native_owner_generation,
        }
    }
}
