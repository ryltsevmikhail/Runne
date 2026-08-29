use runne_api::{CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerKillBindingV1};

use crate::{MacOsPeerKillError, MacOsPeerKillReadyProof};

pub const MACOS_PEER_KILL_READY_WIRE_BYTES: usize = 224;
const BINDING_BYTES: usize = MACOS_PEER_KILL_READY_WIRE_BYTES - 32;

impl MacOsPeerKillReadyProof {
    #[must_use]
    pub fn to_exact_wire(&self) -> [u8; MACOS_PEER_KILL_READY_WIRE_BYTES] {
        let mut wire = [0; MACOS_PEER_KILL_READY_WIRE_BYTES];
        wire[..BINDING_BYTES].copy_from_slice(&self.binding.to_exact_wire());
        wire[BINDING_BYTES..].copy_from_slice(&self.proof);
        wire
    }

    /// Accepts Ready only when its fixed frame authenticates an exact tuple.
    ///
    /// # Errors
    ///
    /// Rejects malformed, incomplete, or unauthenticated bytes.
    pub fn from_authenticated_wire(
        wire: &[u8],
        authenticator: &CredentialBrokerTransferAuthenticator,
        expected_binding: &ProviderCredentialBrokerKillBindingV1,
    ) -> Result<Self, MacOsPeerKillError> {
        let wire: &[u8; MACOS_PEER_KILL_READY_WIRE_BYTES] =
            wire.try_into().map_err(|_| MacOsPeerKillError::Rejected)?;
        let field = |index: usize| {
            wire[index * 32..(index + 1) * 32]
                .try_into()
                .map_err(|_| MacOsPeerKillError::Rejected)
        };
        let binding = ProviderCredentialBrokerKillBindingV1::new(
            field(0)?,
            field(1)?,
            field(2)?,
            field(3)?,
            field(4)?,
            field(5)?,
        );
        let candidate = Self {
            binding: binding.clone(),
            proof: wire[BINDING_BYTES..]
                .try_into()
                .map_err(|_| MacOsPeerKillError::Rejected)?,
        };
        (binding == *expected_binding
            && expected_binding.is_complete()
            && candidate.verifies(authenticator, expected_binding))
        .then_some(candidate)
        .ok_or(MacOsPeerKillError::Rejected)
    }
}
