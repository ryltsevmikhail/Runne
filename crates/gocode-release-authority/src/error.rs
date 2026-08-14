use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuthorityError {
    #[error("promotion authority is not provisioned")]
    AuthorityNotProvisioned,
    #[error("active authority version is superseded")]
    AuthorityVersionSuperseded,
    #[error("owner policy proof is unresolved")]
    PolicyUnresolved,
    #[error("identity dimensions are not distinct")]
    IdentitySeparationViolation,
    #[error("candidate or stage binding mismatch")]
    BindingMismatch,
    #[error("invalid promotion state transition")]
    InvalidTransition,
    #[error("stale compare-and-swap revision")]
    StaleRevision,
    #[error("command replay fingerprint diverged")]
    CommandReplayDiverged,
    #[error("invalid publication effect transition")]
    InvalidEffectTransition,
    #[error("stage payload is not strict canonical LF form")]
    NonCanonicalPayload,
    #[error("durable fixture state is unavailable or corrupt")]
    DurableStateUnavailable,
}
