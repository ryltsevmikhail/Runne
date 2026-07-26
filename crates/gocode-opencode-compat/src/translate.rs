//! Translation layer — Phase 2a: all reject.

use crate::classify::{RejectionCode, RejectionRationale};
use crate::inventory::{InventoryEntry, classify};
use crate::profile::{OperationSelector, ProfileId, ProfileRejection, TranslationDecision};

pub fn translate_request(
    profile_id: &ProfileId,
    profile_revision: u16,
    selector: OperationSelector,
) -> TranslationDecision {
    let entry = classify(&selector);
    match entry {
        Some(e) => TranslationDecision::Reject(ProfileRejection {
            profile_id: profile_id.clone(),
            profile_revision,
            attempted_selector: selector,
            inventory_id: Some(e.inventory_id.clone()),
            upstream_operation_id: e.upstream_operation_id.clone(),
            code: match e.implementation_status {
                crate::classify::ImplementationStatus::Planned => RejectionCode::OperationPlanned,
                _ => RejectionCode::OperationUnsupported,
            },
            rationale: e.rationale,
            detail: None,
        }),
        None => TranslationDecision::Reject(ProfileRejection {
            profile_id: profile_id.clone(),
            profile_revision,
            attempted_selector: selector,
            inventory_id: None,
            upstream_operation_id: None,
            code: RejectionCode::UnknownOperation,
            rationale: None,
            detail: Some("selector not found in inventory".into()),
        }),
    }
}
