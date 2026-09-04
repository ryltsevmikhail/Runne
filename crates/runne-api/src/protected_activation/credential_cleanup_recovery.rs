use super::{LaunchAuthorityError, ProtectedActivationKeys, authenticated_mac, derive_key};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

mod bootstrap;
mod model;
mod request;
mod terminal;
pub use bootstrap::ProtectedCredentialRecoveryBootstrap;
pub use model::{ProtectedCredentialRecoveryContext, ProtectedCredentialRecoveryOffer};

/// Recovery messages are transport evidence, never credential effect authority.
pub struct ProtectedCredentialRecoveryCodec {
    key: Zeroizing<[u8; 32]>,
    context: Option<ProtectedCredentialRecoveryContext>,
    bootstrap: ProtectedCredentialRecoveryBootstrap,
    sent: u64,
    received: u64,
    requested_operation: Option<[u8; 16]>,
    accepted_offer: Option<[u8; 32]>,
    terminal: bool,
}

const DOMAIN: &[u8] = b"runne/protected-credential-cleanup-recovery/v1";
const MAGIC: &[u8; 8] = b"RNCCRECV";
const VERSION: u8 = 1;
const OFFER: u8 = 1; // daemon -> native Desktop
const ACCEPT: u8 = 2; // native Desktop -> daemon
const HEADER: usize = 18;

impl ProtectedCredentialRecoveryCodec {
    /// Routing hint only. Version, framing and MAC still require full decoding.
    pub fn recognizes_frame(frame: &[u8]) -> bool {
        frame.get(4..12) == Some(MAGIC.as_slice())
    }
    /// Starts a Desktop exchange without guessing daemon/database measurements.
    /// Only a verified offer can establish the exact context used by Accept.
    pub fn for_desktop(
        keys: &ProtectedActivationKeys,
        bootstrap: ProtectedCredentialRecoveryBootstrap,
    ) -> Result<Self, LaunchAuthorityError> {
        Ok(Self {
            key: Zeroizing::new(derive_key(keys.readiness_key(), DOMAIN)),
            context: None,
            bootstrap,
            sent: 0,
            received: 0,
            requested_operation: None,
            accepted_offer: None,
            terminal: false,
        })
    }
    /// Retains one admitted session's key and sequence state; do not recreate per frame.
    /// The request/offer exchange establishes support before any writer spawn.
    pub fn new(
        keys: &ProtectedActivationKeys,
        context: ProtectedCredentialRecoveryContext,
    ) -> Self {
        Self {
            key: Zeroizing::new(derive_key(keys.readiness_key(), DOMAIN)),
            bootstrap: ProtectedCredentialRecoveryBootstrap::from_context(&context),
            context: Some(context),
            sent: 0,
            received: 0,
            requested_operation: None,
            accepted_offer: None,
            terminal: false,
        }
    }

    /// Authenticates metadata only. `now` is the caller's high-water Unix seconds.
    pub fn encode_daemon_offer(
        &mut self,
        offer: &ProtectedCredentialRecoveryOffer,
        now: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        offer.require_current(self.exact_context()?, now)?;
        self.require_requested_operation(offer.operation)?;
        self.encode(OFFER, &offer.payload())
    }

    /// Validates the next offer against this exact host/rendezvous and lease.
    pub fn decode_daemon_offer(
        &mut self,
        frame: &[u8],
        now: u64,
    ) -> Result<ProtectedCredentialRecoveryOffer, LaunchAuthorityError> {
        let payload = self.decode(frame, OFFER, 296)?;
        let offer = ProtectedCredentialRecoveryOffer::from_payload(payload)?;
        if let Some(context) = &self.context {
            offer.require_current(context, now)?;
        } else {
            if self.requested_operation.is_none() {
                return Err(LaunchAuthorityError::InvalidContract);
            }
            self.bootstrap.require_context(&offer.context)?;
            offer.require_current(&offer.context, now)?;
        }
        self.require_requested_operation(offer.operation)?;
        self.context = Some(offer.context.clone());
        self.received += 1;
        Ok(offer)
    }

    /// Acknowledges the exact offer, without manufacturing a native intent proof.
    pub fn encode_desktop_accept(
        &mut self,
        offer: &ProtectedCredentialRecoveryOffer,
        now: u64,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        offer.require_current(self.exact_context()?, now)?;
        self.require_requested_operation(offer.operation)?;
        let digest: [u8; 32] = Sha256::digest(offer.payload()).into();
        let frame = self.encode(ACCEPT, &digest)?;
        self.accepted_offer = Some(digest);
        Ok(frame)
    }

    /// Confirms the next acknowledgement; it does not replace the store's CAS.
    pub fn decode_desktop_accept(
        &mut self,
        frame: &[u8],
        offer: &ProtectedCredentialRecoveryOffer,
        now: u64,
    ) -> Result<(), LaunchAuthorityError> {
        offer.require_current(self.exact_context()?, now)?;
        self.require_requested_operation(offer.operation)?;
        let payload = self.decode(frame, ACCEPT, 32)?;
        if !bool::from(payload.ct_eq(Sha256::digest(offer.payload()).as_slice())) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.received += 1;
        self.accepted_offer = Some(Sha256::digest(offer.payload()).into());
        Ok(())
    }

    fn exact_context(&self) -> Result<&ProtectedCredentialRecoveryContext, LaunchAuthorityError> {
        self.context
            .as_ref()
            .ok_or(LaunchAuthorityError::InvalidContract)
    }

    fn encode(&mut self, kind: u8, payload: &[u8]) -> Result<Vec<u8>, LaunchAuthorityError> {
        if self.terminal {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let sequence = self
            .sent
            .checked_add(1)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let mut frame = Vec::with_capacity(4 + HEADER + payload.len() + 32);
        frame.extend_from_slice(&((HEADER + payload.len() + 32) as u32).to_be_bytes());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&[VERSION, kind]);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(payload);
        let proof = authenticated_mac(&self.key, DOMAIN, &frame[4..]);
        frame.extend_from_slice(&proof);
        self.sent = sequence;
        Ok(frame)
    }

    fn decode<'a>(
        &self,
        frame: &'a [u8],
        kind: u8,
        payload_len: usize,
    ) -> Result<&'a [u8], LaunchAuthorityError> {
        if self.terminal || frame.len() != 4 + HEADER + payload_len + 32 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let body = &frame[4..];
        let next = self
            .received
            .checked_add(1)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        if u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize != body.len()
            || &body[..8] != MAGIC
            || body[8] != VERSION
            || body[9] != kind
            || u64::from_be_bytes(body[10..18].try_into().unwrap()) != next
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let end = HEADER + payload_len;
        let expected = authenticated_mac(&self.key, DOMAIN, &body[..end]);
        if !bool::from(body[end..].ct_eq(&expected)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(&body[HEADER..end])
    }
}

#[cfg(test)]
mod tests;
