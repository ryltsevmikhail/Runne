//! Strict fixed-length versioned encodings for owner-key Keychain records.

use zeroize::Zeroizing;

use super::super::{
    PendingProjectOwnerKey, ProjectOwnerAnchorFloor, ProjectOwnerKeyRef, StoreStatus,
};

const KEY_MAGIC: &[u8; 4] = b"GOPK";
const FLOOR_MAGIC: &[u8; 4] = b"GOPF";
const VERSION: u8 = 1;
const ACTIVE: u8 = 1;
const PENDING: u8 = 2;
const RECOVERY: u8 = 3;
const KEY_BYTES: usize = 78;
const PENDING_BYTES: usize = 174;
const FLOOR_BYTES: usize = 45;

pub(super) struct StoredKey {
    pub(super) reference: ProjectOwnerKeyRef,
    pub(super) seed: Zeroizing<[u8; 32]>,
}

pub(super) struct StoredPending {
    pub(super) key: StoredKey,
    pub(super) proof: [u8; 64],
    pub(super) token: Zeroizing<[u8; 32]>,
}

impl StoredKey {
    pub(super) fn encode(&self, kind: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(KEY_BYTES);
        bytes.extend_from_slice(KEY_MAGIC);
        bytes.extend_from_slice(&[VERSION, kind]);
        bytes.extend_from_slice(&self.reference.key_epoch().to_be_bytes());
        bytes.extend_from_slice(&self.reference.public_key());
        bytes.extend_from_slice(&*self.seed);
        bytes
    }

    pub(super) fn decode(bytes: &[u8], expected_kind: u8) -> Result<Self, StoreStatus> {
        if bytes.len() != KEY_BYTES
            || bytes[..4] != *KEY_MAGIC
            || bytes[4] != VERSION
            || bytes[5] != expected_kind
        {
            return Err(StoreStatus::Denied);
        }
        let epoch = u64::from_be_bytes(bytes[6..14].try_into().map_err(|_| StoreStatus::Denied)?);
        let public_key = bytes[14..46].try_into().map_err(|_| StoreStatus::Denied)?;
        let seed = Zeroizing::new(bytes[46..78].try_into().map_err(|_| StoreStatus::Denied)?);
        let reference = ProjectOwnerKeyRef::new("gocode", public_key, epoch)?;
        if ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            != public_key
        {
            return Err(StoreStatus::Denied);
        }
        Ok(Self { reference, seed })
    }
}

impl StoredPending {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.key.encode(PENDING);
        bytes.extend_from_slice(&*self.token);
        bytes.extend_from_slice(&self.proof);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, StoreStatus> {
        if bytes.len() != PENDING_BYTES {
            return Err(StoreStatus::Denied);
        }
        let key = StoredKey::decode(&bytes[..KEY_BYTES], PENDING)?;
        let token = Zeroizing::new(
            bytes[KEY_BYTES..KEY_BYTES + 32]
                .try_into()
                .map_err(|_| StoreStatus::Denied)?,
        );
        let proof = bytes[KEY_BYTES + 32..]
            .try_into()
            .map_err(|_| StoreStatus::Denied)?;
        Ok(Self { key, proof, token })
    }

    pub(super) fn into_pending(
        self,
        transcript: &[u8],
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        PendingProjectOwnerKey::from_backend_generated(
            self.key.reference,
            self.proof,
            self.token,
            transcript,
        )
    }
}

pub(super) fn encode_floor(floor: &ProjectOwnerAnchorFloor) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FLOOR_BYTES);
    bytes.extend_from_slice(FLOOR_MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&floor.highest_key_epoch().to_be_bytes());
    bytes.extend_from_slice(&floor.accepted_trust_config_sha256());
    bytes
}

pub(super) fn decode_floor(bytes: &[u8]) -> Result<ProjectOwnerAnchorFloor, StoreStatus> {
    if bytes.len() != FLOOR_BYTES || bytes[..4] != *FLOOR_MAGIC || bytes[4] != VERSION {
        return Err(StoreStatus::Denied);
    }
    let epoch = u64::from_be_bytes(bytes[5..13].try_into().map_err(|_| StoreStatus::Denied)?);
    let hash = bytes[13..45].try_into().map_err(|_| StoreStatus::Denied)?;
    ProjectOwnerAnchorFloor::new("gocode", epoch, hash)
}

pub(super) const fn active_kind() -> u8 {
    ACTIVE
}
pub(super) const fn recovery_kind() -> u8 {
    RECOVERY
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use zeroize::Zeroizing;

    use super::*;

    fn key() -> StoredKey {
        let seed = Zeroizing::new([7_u8; 32]);
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        StoredKey {
            reference: ProjectOwnerKeyRef::new("gocode", public_key, 1).expect("valid reference"),
            seed,
        }
    }

    #[test]
    fn key_codec_rejects_version_kind_length_and_seed_binding_mutations() {
        let encoded = key().encode(active_kind());
        assert!(StoredKey::decode(&encoded, active_kind()).is_ok());
        for mutation in [
            Vec::new(),
            {
                let mut bytes = encoded.clone();
                bytes[4] = 2;
                bytes
            },
            {
                let mut bytes = encoded.clone();
                bytes[5] = PENDING;
                bytes
            },
            {
                let mut bytes = encoded;
                bytes[46] ^= 1;
                bytes
            },
        ] {
            assert!(matches!(
                StoredKey::decode(&mutation, active_kind()),
                Err(StoreStatus::Denied)
            ));
        }
    }

    #[test]
    fn floor_codec_rejects_noncanonical_or_truncated_records() {
        let floor = ProjectOwnerAnchorFloor::new("gocode", 1, [9_u8; 32]).expect("valid floor");
        let encoded = encode_floor(&floor);
        assert_eq!(decode_floor(&encoded), Ok(floor));
        for mutation in [encoded[..44].to_vec(), {
            let mut bytes = encoded;
            bytes[0] = b'X';
            bytes
        }] {
            assert_eq!(decode_floor(&mutation), Err(StoreStatus::Denied));
        }
    }
}
