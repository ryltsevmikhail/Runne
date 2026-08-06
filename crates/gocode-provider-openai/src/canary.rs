//! Pure, compiled offline canary values.

use core::fmt;

mod accounting;
mod contract;

pub use accounting::{
    AccountingDisposition, CanaryAccounting, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS,
    RESERVATION_MICRO_USD, TerminalUsage,
};
pub use contract::{
    CANARY_DIGEST, CanaryCandidate, CanaryIdentity, CanaryOverlay, CandidateDisposition,
    PROFILE_DIGEST,
};

/// Closed digest-and-length evidence for the compiled candidate.
#[derive(Clone, Copy)]
pub struct CanaryEvidence {
    candidate_digest: [u8; 32],
    profile_digest: [u8; 32],
    request_digest: [u8; 32],
    prompt_digest: [u8; 32],
    result_digest: [u8; 32],
    request_length: u64,
    prompt_length: u64,
    result_length: u64,
}

macro_rules! evidence_digest {
    ($field:ident, $doc:literal) => {
        #[doc = $doc]
        #[must_use]
        pub const fn $field(&self) -> &[u8; 32] {
            &self.$field
        }
    };
}

impl CanaryEvidence {
    const fn new(digests: [[u8; 32]; 5], lengths: [u64; 3]) -> Self {
        Self {
            candidate_digest: digests[0],
            profile_digest: digests[1],
            request_digest: digests[2],
            prompt_digest: digests[3],
            result_digest: digests[4],
            request_length: lengths[0],
            prompt_length: lengths[1],
            result_length: lengths[2],
        }
    }

    evidence_digest!(candidate_digest, "Returns the raw candidate digest.");
    evidence_digest!(profile_digest, "Returns the raw profile digest.");
    evidence_digest!(request_digest, "Returns the raw framed request digest.");
    evidence_digest!(prompt_digest, "Returns the raw prompt digest.");
    evidence_digest!(result_digest, "Returns the raw result digest.");
    /// Returns the framed request preimage length.
    #[must_use]
    pub const fn request_length(&self) -> u64 {
        self.request_length
    }
    /// Returns the prompt byte length.
    #[must_use]
    pub const fn prompt_length(&self) -> u64 {
        self.prompt_length
    }
    /// Returns the result byte length.
    #[must_use]
    pub const fn result_length(&self) -> u64 {
        self.result_length
    }
}

impl fmt::Debug for CanaryEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanaryEvidence")
    }
}
