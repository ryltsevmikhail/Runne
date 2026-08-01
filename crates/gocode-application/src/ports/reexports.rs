// ── ReplayService re-exports ──────────────────────────────────────────────

pub use crate::replay_service::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    ReplayEvent, ReplayOpenResult, ReplaySession, ReplayState, ReplayStorePort,
};
pub use gocode_domain::replay::{
    CatchUpCompletion, GapRangeRef, ReplayCursor, ReplayScope, RetentionManifest,
};
