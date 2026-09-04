use super::{
    CborEncoder, LaunchAuthorityError, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3, authenticated_mac, derive_key,
    encode_enrollment_binding, encode_owned_core, encode_provider_binding, write_key,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"runne/credential-cleanup-discovery/v1";
const MAGIC: &[u8; 8] = b"RNCDSC01";
const HEADER: usize = 42;

enum State {
    Fresh,
    Requested([u8; 32]),
    Complete,
}

/// Metadata-only discovery; never an enrollment or recovery authority.
pub struct ProtectedCredentialDiscoveryCodec {
    key: Zeroizing<[u8; 32]>,
    owned: [u8; 32],
    state: State,
}

impl ProtectedCredentialDiscoveryCodec {
    /// Startup metadata query before V2→V3 transition. The daemon derives the
    /// installation owner from its verified composition, never a client claim.
    pub fn for_startup(
        keys: &ProtectedActivationKeys,
        owned: &super::ProtectedOwnedLaunchV2,
    ) -> Self {
        let mut encoder = CborEncoder::new();
        encoder.write_map_header(2);
        write_key(&mut encoder, 0);
        encoder.write_unsigned(2);
        write_key(&mut encoder, 1);
        super::encode_owned_launch_v2(&mut encoder, owned);
        Self {
            key: Zeroizing::new(derive_key(keys.readiness_key(), DOMAIN)),
            owned: Sha256::digest(encoder.into_bytes()).into(),
            state: State::Fresh,
        }
    }

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

    /// Routing hint only, never authentication.
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
        let nonce: [u8; 32] = self
            .decode(frame, 1)?
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        if nonce == [0; 32] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.state = State::Requested(nonce);
        Ok(())
    }

    pub fn encode_response(&mut self, ids: &[[u8; 16]]) -> Result<Vec<u8>, LaunchAuthorityError> {
        let State::Requested(nonce) = self.state else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        validate_ids(ids)?;
        let mut payload = nonce.to_vec();
        payload.push(ids.len() as u8);
        for id in ids {
            payload.extend_from_slice(id);
        }
        let frame = self.encode(2, &payload);
        self.state = State::Complete;
        Ok(frame)
    }

    pub fn decode_response(&mut self, frame: &[u8]) -> Result<Vec<[u8; 16]>, LaunchAuthorityError> {
        let State::Requested(nonce) = self.state else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        let payload = self.decode(frame, 2)?;
        if payload.len() < 33 || !bool::from(payload[..32].ct_eq(&nonce)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let count = usize::from(payload[32]);
        if count > 64 || payload.len() != 33 + count * 16 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let ids: Vec<[u8; 16]> = payload[33..]
            .chunks_exact(16)
            .map(|id| id.try_into().unwrap())
            .collect();
        validate_ids(&ids)?;
        self.state = State::Complete;
        Ok(ids)
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

    fn decode<'a>(&self, frame: &'a [u8], kind: u8) -> Result<&'a [u8], LaunchAuthorityError> {
        if !(4 + HEADER + 32..=4 + HEADER + 33 + 64 * 16 + 32).contains(&frame.len()) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let body = &frame[4..];
        let end = body.len() - 32;
        if u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize != body.len()
            || &body[..8] != MAGIC
            || body[8] != 1
            || body[9] != kind
            || !bool::from(body[10..42].ct_eq(&self.owned))
            || !bool::from(body[end..].ct_eq(&authenticated_mac(&self.key, DOMAIN, &body[..end])))
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(&body[HEADER..end])
    }
}

fn validate_ids(ids: &[[u8; 16]]) -> Result<(), LaunchAuthorityError> {
    if ids.len() > 64
        || ids
            .iter()
            .enumerate()
            .any(|(index, id)| *id == [0; 16] || ids[..index].contains(id))
    {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
