use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};

pub fn verify_role(
    role: &str,
    unsigned: &[u8],
    proofs: &[(String, [u8; 64])],
    keys: &BTreeMap<String, [u8; 32]>,
) -> bool {
    proofs.len() == 2
        && proofs.iter().all(|proof| {
            keys.get(&proof.0)
                .is_some_and(|key| verify(role, unsigned, key, &proof.1))
        })
}

pub fn verify_one(
    role: &str,
    unsigned: &[u8],
    proof: &(String, [u8; 64]),
    key: &(String, [u8; 32]),
) -> bool {
    proof.0 == key.0 && verify(role, unsigned, &key.1, &proof.1)
}

fn verify(role: &str, unsigned: &[u8], key: &[u8; 32], signature: &[u8; 64]) -> bool {
    let mut transcript = Vec::with_capacity(48 + role.len() + unsigned.len());
    transcript.extend_from_slice(b"gocode.release.rc2-threshold-signature/1\0");
    transcript.extend_from_slice(role.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(unsigned);
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(&transcript, &Signature::from_bytes(signature))
            .is_ok()
    })
}
