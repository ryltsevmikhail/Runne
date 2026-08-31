use crate::LaunchAuthorityError;
use sha2::{Digest, Sha256};

const BROKER_HANDOFF_MAGIC: &[u8; 8] = b"GCBRKV3\0";
const BROKER_HANDOFF_UNSIGNED_BYTES: usize = 128;
const BROKER_HANDOFF_PROOF_BYTES: usize = 32;

/// Session-bound facts every broker handoff frame re-proves.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderCredentialBrokerHandoffContext {
    authority_id: [u8; 16],
    session_id: [u8; 16],
    launch_generation: u64,
    binding: [u8; 32],
}

impl ProviderCredentialBrokerHandoffContext {
    /// Binds every frame of one handoff to the exact V3 launch and rendezvous.
    pub fn new(
        authority_id: [u8; 16],
        session_id: [u8; 16],
        launch_generation: u64,
        binding: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        if authority_id == [0; 16]
            || session_id == [0; 16]
            || launch_generation == 0
            || binding == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            authority_id,
            session_id,
            launch_generation,
            binding,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

impl fmt::Debug for ProviderCredentialBrokerHandoffContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCredentialBrokerHandoffContext(<redacted>)")
    }
}

/// Returns whether one ordinary protected-channel frame is a broker handoff frame.
#[must_use]
pub fn is_broker_handoff_frame(bytes: &[u8]) -> bool {
    bytes.len() >= 4 + BROKER_HANDOFF_UNSIGNED_BYTES + BROKER_HANDOFF_PROOF_BYTES
        && bytes[4..12] == *BROKER_HANDOFF_MAGIC
}

/// Digest binding the final daemon acknowledgement to the exact kill binding.
#[must_use]
pub fn broker_handoff_kill_ack_binding(
    kill_binding: &ProviderCredentialBrokerKillBindingV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider-credential-broker/kill-ack/v1\0");
    hasher.update(kill_binding.to_exact_wire());
    hasher.finalize().into()
}
