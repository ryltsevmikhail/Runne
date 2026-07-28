//! Translation layer — Phase 2a: all reject.

use crate::classify::RejectionCode;
use crate::inventory::classify;
use crate::profile::{
    OPENCODE_BASELINE_INVENTORY_PROFILE_ID, OperationSelector, ProfileAcceptance, ProfileId,
    ProfileRejection, SESSION_CREATE_PROFILE_REVISION, SESSION_V1_COMPAT_PROFILE_REVISION,
    TranslationDecision,
};

pub fn translate_request(
    profile_id: &ProfileId,
    profile_revision: u16,
    selector: OperationSelector,
) -> TranslationDecision {
    let entry = classify(&selector);
    if profile_id.as_str() != OPENCODE_BASELINE_INVENTORY_PROFILE_ID
        || !matches!(
            profile_revision,
            1 | SESSION_CREATE_PROFILE_REVISION | SESSION_V1_COMPAT_PROFILE_REVISION
        )
    {
        return TranslationDecision::Reject(ProfileRejection {
            profile_id: profile_id.clone(),
            profile_revision,
            attempted_selector: selector,
            inventory_id: entry.map(|value| value.inventory_id.clone()),
            upstream_operation_id: entry.and_then(|value| value.upstream_operation_id.clone()),
            code: RejectionCode::ProfileMismatch,
            rationale: None,
            detail: Some("unsupported compatibility profile or revision".into()),
        });
    }

    match entry {
        Some(e)
            if profile_revision == SESSION_V1_COMPAT_PROFILE_REVISION
                || (profile_revision == SESSION_CREATE_PROFILE_REVISION
                    && e.inventory_id == "session.create") =>
        {
            TranslationDecision::Accept(ProfileAcceptance {
                profile_id: profile_id.clone(),
                profile_revision,
                selector,
                inventory_id: e.inventory_id.clone(),
                upstream_operation_id: e
                    .upstream_operation_id
                    .clone()
                    .expect("pinned baseline inventory entries have operation identifiers"),
            })
        }
        Some(e) => TranslationDecision::Reject(ProfileRejection {
            profile_id: profile_id.clone(),
            profile_revision,
            attempted_selector: selector,
            inventory_id: Some(e.inventory_id.clone()),
            upstream_operation_id: e.upstream_operation_id.clone(),
            code: RejectionCode::OperationPlanned,
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
