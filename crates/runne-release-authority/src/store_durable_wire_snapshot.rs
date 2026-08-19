use sha2::{Digest as _, Sha256};

use super::SnapshotWire;
use crate::{AuthorityError, Digest, PromotionStateSnapshot};

pub(super) fn decode(value: &SnapshotWire) -> Result<PromotionStateSnapshot, AuthorityError> {
    let bytes = hex_bytes(&value.bytes)?;
    let digest = bytes
        .last()
        .is_some_and(|last| *last == b'\n')
        .then(|| Digest::from_bytes(Sha256::digest(&bytes[..bytes.len() - 1]).into()))
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    if digest != parse_digest(&value.digest)? {
        return Err(AuthorityError::BindingMismatch);
    }
    Ok(PromotionStateSnapshot {
        bytes,
        digest,
        revision: value.revision,
    })
}

fn parse_digest(value: &str) -> Result<Digest, AuthorityError> {
    let bytes = hex_bytes(value)?;
    bytes
        .try_into()
        .map(Digest::from_bytes)
        .map_err(|_| AuthorityError::NonCanonicalPayload)
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, AuthorityError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| AuthorityError::NonCanonicalPayload)
        })
        .collect()
}
