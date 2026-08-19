use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;

/// Return a deterministic fixture public key for a closed threshold key identifier.
///
/// # Panics
/// Panics when `key_id` is outside the closed fixture registry.
#[must_use]
pub fn threshold_public_key(key_id: &str) -> [u8; 32] {
    let seed = match key_id {
        "r1" => 1,
        "r2" => 2,
        "r3" => 3,
        "t1" => 4,
        "t2" => 5,
        "t3" => 6,
        "snapshot" => 7,
        "timestamp" => 8,
        _ => panic!("unknown threshold fixture key"),
    };
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

#[must_use]
pub fn threshold_keyset(prefix: &str) -> BTreeMap<String, [u8; 32]> {
    (1..=3)
        .map(|index| {
            let key_id = format!("{prefix}{index}");
            (key_id.clone(), threshold_public_key(&key_id))
        })
        .collect()
}
