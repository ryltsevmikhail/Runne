use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

use crate::Digest;
use crate::threshold_context::{ThresholdMetadataEvidence, ThresholdVerificationState};

pub fn matches(evidence: &ThresholdMetadataEvidence, state: &ThresholdVerificationState) -> bool {
    state.role_bodies.get("root").map_or_else(
        || {
            evidence.root_predecessor_body == Digest::from_bytes([0; 32])
                && evidence.root_predecessor_keyset == Digest::from_bytes([0; 32])
        },
        |body| {
            evidence.root_predecessor_body == Digest::from_bytes(Sha256::digest(body).into())
                && evidence.root_predecessor_keyset == keyset_digest(&state.root_keys)
        },
    )
}

fn keyset_digest(keys: &BTreeMap<String, [u8; 32]>) -> Digest {
    let mut transcript = b"runne.release.rc2-threshold-keyset/2\0".to_vec();
    for (key_id, key) in keys {
        append(&mut transcript, key_id.as_bytes());
        append(&mut transcript, key);
    }
    Digest::from_bytes(Sha256::digest(transcript).into())
}

pub fn keyset(keys: &[(String, [u8; 32])]) -> BTreeMap<String, [u8; 32]> {
    keys.iter().cloned().collect()
}

fn append(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
    transcript.extend_from_slice(field);
}
