use runne_api::RunBinding;

use crate::QualificationReplayLedgerError;

const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;

pub struct BootstrapPreparation {
    binding: RunBinding,
    offer_id: [u8; 32],
    context_id: [u8; 32],
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    max_run_duration: u64,
}

impl BootstrapPreparation {
    /// # Errors
    ///
    /// Returns an error when any supplied binding, replay identity, or time
    /// boundary is malformed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: RunBinding,
        offer_id: [u8; 32],
        context_id: [u8; 32],
        nonce: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        run_not_after: u64,
        max_run_duration: u64,
    ) -> Result<Self, QualificationReplayLedgerError> {
        let value = Self {
            binding,
            offer_id,
            context_id,
            nonce,
            issued_at,
            expires_at,
            run_not_after,
            max_run_duration,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(QualificationReplayLedgerError)
    }
    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        &self.binding
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }
    #[must_use]
    pub const fn context_id(&self) -> [u8; 32] {
        self.context_id
    }
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }
    #[must_use]
    pub const fn max_run_duration(&self) -> u64 {
        self.max_run_duration
    }
    pub(crate) fn valid(&self) -> bool {
        self.binding_is_valid()
            && [self.offer_id, self.context_id, self.nonce]
                .into_iter()
                .all(nonzero)
            && valid_times(
                self.issued_at,
                self.expires_at,
                self.run_not_after,
                self.max_run_duration,
            )
    }
    fn binding_is_valid(&self) -> bool {
        let binding = &self.binding;
        binding.workflow_run_id().len() <= 128
            && !binding.workflow_run_id().is_empty()
            && binding
                .workflow_run_id()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            && binding.source_revision() != [0; 20]
            && [
                binding.candidate_sha256(),
                binding.raw_v3_tuple_sha256(),
                binding.namespace_sha256(),
                binding.manifest_sha256(),
                binding.profile_sha256(),
            ]
            .into_iter()
            .all(nonzero)
    }
}

pub struct BootstrapArmed {
    preparation: BootstrapPreparation,
    challenge: [u8; 32],
}

impl BootstrapArmed {
    pub(crate) fn new(
        preparation: BootstrapPreparation,
        challenge: [u8; 32],
    ) -> Result<Self, QualificationReplayLedgerError> {
        (preparation.valid() && nonzero(challenge))
            .then_some(Self {
                preparation,
                challenge,
            })
            .ok_or(QualificationReplayLedgerError)
    }
    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        self.preparation.binding()
    }
    #[must_use]
    pub const fn offer_id(&self) -> [u8; 32] {
        self.preparation.offer_id()
    }
    #[must_use]
    pub const fn context_id(&self) -> [u8; 32] {
        self.preparation.context_id()
    }
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.preparation.nonce()
    }
    #[must_use]
    pub const fn challenge(&self) -> [u8; 32] {
        self.challenge
    }
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.preparation.issued_at()
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.preparation.expires_at()
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.preparation.run_not_after()
    }
    #[must_use]
    pub const fn max_run_duration(&self) -> u64 {
        self.preparation.max_run_duration()
    }
}

pub fn nonzero(value: [u8; 32]) -> bool {
    value != [0; 32]
}

pub fn valid_times(
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    max_run_duration: u64,
) -> bool {
    issued_at > 0
        && expires_at > issued_at
        && run_not_after >= expires_at
        && run_not_after <= MAX_SAFE_JS_INTEGER
        && max_run_duration > 0
        && max_run_duration <= MAX_SAFE_JS_INTEGER
        && run_not_after
            .checked_sub(issued_at)
            .is_some_and(|duration| duration <= max_run_duration)
}
