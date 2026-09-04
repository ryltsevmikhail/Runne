use super::{
    CborEncoder, LaunchAuthorityError, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3, authenticated_mac, derive_key,
    encode_enrollment_binding, encode_owned_core, encode_provider_binding, write_key,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"runne/credential-enrollment-round/v1";
const MAGIC: &[u8; 8] = b"RNCRND01";
const HEADER: usize = 42;

/// Fresh daemon-owned rendezvous metadata, never a credential effect grant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProtectedCredentialRoundBrokerFacts {
    channel: [u8; 32],
    publication: [u8; 32],
}

impl ProtectedCredentialRoundBrokerFacts {
    pub fn new(channel: [u8; 32], publication: [u8; 32]) -> Result<Self, LaunchAuthorityError> {
        if channel == [0; 32] || publication == [0; 32] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            channel,
            publication,
        })
    }
    pub const fn channel_binding(self) -> [u8; 32] {
        self.channel
    }
    pub const fn publication_key(self) -> [u8; 32] {
        self.publication
    }
}

enum State {
    Fresh,
    Requested([u8; 32]),
    Offered([u8; 32]),
    Accepted,
}

/// One Request/Offer/Accept bound to the complete current owned V3 launch.
/// The host must separately require a terminal previous round and a newly
/// rotated live session. This codec cannot authorize a store claim or effect.
pub struct ProtectedCredentialRoundCodec {
    key: Zeroizing<[u8; 32]>,
    owned: [u8; 32],
    state: State,
}

impl ProtectedCredentialRoundCodec {
    pub fn new(
        keys: &ProtectedActivationKeys,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Self {
        let mut encoder = CborEncoder::new();
        encoder.write_map_header(3);
        write_key(&mut encoder, 0);
        encode_owned_core(&mut encoder, &owned.core);
        write_key(&mut encoder, 1);
        encode_provider_binding(&mut encoder, &owned.provider);
        write_key(&mut encoder, 2);
        encode_enrollment_binding(&mut encoder, &owned.enrollment);
        Self {
            key: Zeroizing::new(derive_key(keys.readiness_key(), DOMAIN)),
            owned: Sha256::digest(encoder.into_bytes()).into(),
            state: State::Fresh,
        }
    }

    /// Routing hint only; all authentication checks remain mandatory.
    pub fn recognizes_frame(frame: &[u8]) -> bool {
        frame.get(4..12) == Some(MAGIC.as_slice())
    }

    pub fn encode_request(&mut self, nonce: [u8; 32]) -> Result<Vec<u8>, LaunchAuthorityError> {
        if !matches!(self.state, State::Fresh) || nonce == [0; 32] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let frame = self.encode(1, &nonce);
        self.state = State::Requested(nonce);
        Ok(frame)
    }

    pub fn decode_request(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        if !matches!(self.state, State::Fresh) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let nonce: [u8; 32] = self.decode(frame, 1, 32)?.try_into().unwrap();
        if nonce == [0; 32] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.state = State::Requested(nonce);
        Ok(())
    }

    pub fn encode_offer(
        &mut self,
        facts: ProtectedCredentialRoundBrokerFacts,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        let State::Requested(nonce) = self.state else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&facts.channel);
        payload.extend_from_slice(&facts.publication);
        let frame = self.encode(2, &payload);
        self.state = State::Offered(Sha256::digest(payload).into());
        Ok(frame)
    }

    pub fn decode_offer(
        &mut self,
        frame: &[u8],
    ) -> Result<ProtectedCredentialRoundBrokerFacts, LaunchAuthorityError> {
        let State::Requested(nonce) = self.state else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        let payload = self.decode(frame, 2, 96)?;
        if !bool::from(payload[..32].ct_eq(&nonce)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let facts = ProtectedCredentialRoundBrokerFacts::new(
            payload[32..64].try_into().unwrap(),
            payload[64..].try_into().unwrap(),
        )?;
        self.state = State::Offered(Sha256::digest(payload).into());
        Ok(facts)
    }

    pub fn encode_accept(&mut self) -> Result<Vec<u8>, LaunchAuthorityError> {
        let State::Offered(digest) = self.state else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        let frame = self.encode(3, &digest);
        self.state = State::Accepted;
        Ok(frame)
    }

    pub fn decode_accept(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        let State::Offered(digest) = self.state else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        let payload = self.decode(frame, 3, 32)?;
        if !bool::from(payload.ct_eq(&digest)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.state = State::Accepted;
        Ok(())
    }

    fn encode(&self, kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + HEADER + payload.len() + 32);
        frame.extend_from_slice(&((HEADER + payload.len() + 32) as u32).to_be_bytes());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&[1, kind]);
        frame.extend_from_slice(&self.owned);
        frame.extend_from_slice(payload);
        let proof = authenticated_mac(&self.key, DOMAIN, &frame[4..]);
        frame.extend_from_slice(&proof);
        frame
    }

    fn decode<'a>(
        &self,
        frame: &'a [u8],
        kind: u8,
        length: usize,
    ) -> Result<&'a [u8], LaunchAuthorityError> {
        if frame.len() != 4 + HEADER + length + 32 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let body = &frame[4..];
        if u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize != body.len()
            || &body[..8] != MAGIC
            || body[8] != 1
            || body[9] != kind
            || !bool::from(body[10..42].ct_eq(&self.owned))
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let end = HEADER + length;
        let proof = authenticated_mac(&self.key, DOMAIN, &body[..end]);
        if !bool::from(body[end..].ct_eq(&proof)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(&body[HEADER..end])
    }
}

#[cfg(test)]
mod tests;
