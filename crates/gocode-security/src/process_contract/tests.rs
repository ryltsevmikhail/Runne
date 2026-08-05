mod approval;
mod authorization;
mod current_context;
mod digest;
mod environment;
mod input;
mod redaction;
mod support;

use super::{ApprovalId, ProcessContractError};

#[test]
fn opaque_ids_reject_sentinel_values() {
    assert_eq!(
        ApprovalId::new([0; 16]),
        Err(ProcessContractError::IntentMalformed)
    );
}
