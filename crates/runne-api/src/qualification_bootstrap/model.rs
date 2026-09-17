use std::fmt;

pub const QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN: &str = "runne/qualification-bootstrap-control/v1";
pub const QUALIFICATION_BOOTSTRAP_CONTROL_VERSION: u8 = 1;
pub const MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES: usize = 8_192;
pub const MAX_QUALIFICATION_BOOTSTRAP_SIGNED_PROOF_BYTES: usize = 2_048;
pub(super) const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;

/// Shape failure for a closed bootstrap-control message. This is not a trust decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationBootstrapControlError {
    InvalidMessage,
}
impl fmt::Display for QualificationBootstrapControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid qualification bootstrap control message")
    }
}
impl std::error::Error for QualificationBootstrapControlError {}

/// Immutable digest-only facts shared by the offer and acknowledgement.
pub struct RunBinding {
    pub(super) workflow_run_id: String,
    pub(super) source_revision: [u8; 20],
    pub(super) candidate_sha256: [u8; 32],
    pub(super) raw_v3_tuple_sha256: [u8; 32],
    pub(super) namespace_sha256: [u8; 32],
    pub(super) manifest_sha256: [u8; 32],
    pub(super) profile_sha256: [u8; 32],
}
impl RunBinding {
    pub fn new(
        workflow_run_id: &str,
        source_revision: [u8; 20],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        namespace_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        profile_sha256: [u8; 32],
    ) -> Result<Self, QualificationBootstrapControlError> {
        let value = Self {
            workflow_run_id: workflow_run_id.into(),
            source_revision,
            candidate_sha256,
            raw_v3_tuple_sha256,
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }
    #[must_use]
    pub const fn source_revision(&self) -> [u8; 20] {
        self.source_revision
    }
    #[must_use]
    pub const fn candidate_sha256(&self) -> [u8; 32] {
        self.candidate_sha256
    }
    #[must_use]
    pub const fn raw_v3_tuple_sha256(&self) -> [u8; 32] {
        self.raw_v3_tuple_sha256
    }
    #[must_use]
    pub const fn namespace_sha256(&self) -> [u8; 32] {
        self.namespace_sha256
    }
    #[must_use]
    pub const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    #[must_use]
    pub const fn profile_sha256(&self) -> [u8; 32] {
        self.profile_sha256
    }
    fn valid(&self) -> bool {
        valid_run_id(&self.workflow_run_id)
            && nonzero(&self.source_revision)
            && nonzero(&self.candidate_sha256)
            && nonzero(&self.raw_v3_tuple_sha256)
            && nonzero(&self.namespace_sha256)
            && nonzero(&self.manifest_sha256)
            && nonzero(&self.profile_sha256)
    }
}

pub struct DesktopOfferRequest {
    pub(super) desktop_challenge: [u8; 32],
}
impl DesktopOfferRequest {
    pub fn new(desktop_challenge: [u8; 32]) -> Result<Self, QualificationBootstrapControlError> {
        nonzero(&desktop_challenge)
            .then_some(Self { desktop_challenge })
            .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub const fn desktop_challenge(&self) -> [u8; 32] {
        self.desktop_challenge
    }
}
pub struct DesktopOffer {
    pub(super) desktop_challenge: [u8; 32],
    pub(super) offer_id: [u8; 32],
    pub(super) binding: RunBinding,
    pub(super) expires_at: u64,
    pub(super) run_not_after: u64,
}
impl DesktopOffer {
    pub fn new(
        desktop_challenge: [u8; 32],
        offer_id: [u8; 32],
        binding: RunBinding,
        expires_at: u64,
        run_not_after: u64,
    ) -> Result<Self, QualificationBootstrapControlError> {
        let value = Self {
            desktop_challenge,
            offer_id,
            binding,
            expires_at,
            run_not_after,
        };
        (nonzero(&value.desktop_challenge)
            && nonzero(&value.offer_id)
            && valid_times(value.expires_at, value.run_not_after))
        .then_some(value)
        .ok_or(QualificationBootstrapControlError::InvalidMessage)
    }
    #[must_use]
    pub const fn desktop_challenge(&self) -> [u8; 32] {
        self.desktop_challenge
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }
    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        &self.binding
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }
}

pub(super) fn valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
pub(super) fn nonzero<const N: usize>(value: &[u8; N]) -> bool {
    value != &[0; N]
}
pub(super) fn valid_time(value: u64) -> bool {
    value > 0 && value <= MAX_SAFE_JS_INTEGER
}
pub(super) fn valid_times(expires_at: u64, run_not_after: u64) -> bool {
    valid_time(expires_at) && valid_time(run_not_after) && expires_at <= run_not_after
}
