// ── ReplayService re-exports ──────────────────────────────────────────────

pub use crate::replay_service::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest,
    ReplayBaselineResumeRequestV2, ReplayError, ReplayEvent, ReplayOpenResult,
    ReplayAcceptedPromotionV2, ReplayAcceptedPromotionV2Parts,
    ReplayRetentionBaselineCandidateV1, ReplayRetentionBaselineCandidateV2,
    ReplayRetentionBaselineCandidateV2Parts, ReplaySession, ReplayState, ReplayStorePort,
};
pub use gocode_domain::replay::{CatchUpCompletion, ReplayCursor, ReplayScope, RetentionManifest};
