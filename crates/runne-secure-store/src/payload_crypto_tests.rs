use super::{decrypt, encrypt};

const KEY: &[u8] = b"synthetic-fixture-anchor-key";
const PROFILE: [u8; 32] = [0x31; 32];
const DATABASE: [u8; 32] = [0x52; 32];
const AAD: &[u8] = b"synthetic fixture row binding";
const PLAINTEXT: &[u8] = b"synthetic local intent payload";

fn seal() -> Vec<u8> {
    encrypt(KEY, PROFILE, DATABASE, AAD, PLAINTEXT).expect("synthetic encryption")
}

#[test]
fn payload_round_trip_and_fresh_envelopes() {
    let first = seal();
    let second = seal();
    assert_ne!(first, second, "fresh seals use distinct nonces");
    assert_eq!(
        decrypt(KEY, PROFILE, DATABASE, AAD, &first)
            .unwrap()
            .as_slice(),
        PLAINTEXT
    );
    assert_eq!(
        decrypt(KEY, PROFILE, DATABASE, AAD, &second)
            .unwrap()
            .as_slice(),
        PLAINTEXT
    );
}

#[test]
fn payload_authentication_binds_key_profile_database_and_aad() {
    let envelope = seal();
    assert!(matches!(
        decrypt(
            b"different synthetic key",
            PROFILE,
            DATABASE,
            AAD,
            &envelope
        ),
        Err(crate::SecureStoreError::InvalidSeal)
    ));
    let other_profile = [0x32; 32];
    assert!(decrypt(KEY, other_profile, DATABASE, AAD, &envelope).is_err());
    let other_database = [0x53; 32];
    assert!(decrypt(KEY, PROFILE, other_database, AAD, &envelope).is_err());
    assert!(
        decrypt(
            KEY,
            PROFILE,
            DATABASE,
            b"other synthetic row binding",
            &envelope
        )
        .is_err()
    );
}

#[test]
fn payload_nonce_ciphertext_tag_tampering_and_truncation_fail_closed() {
    let original = seal();
    for index in [0, 12, original.len() - 1] {
        let mut changed = original.clone();
        changed[index] ^= 0x80;
        assert!(decrypt(KEY, PROFILE, DATABASE, AAD, &changed).is_err());
    }
    let truncated = &original[..original.len() - 1];
    assert!(decrypt(KEY, PROFILE, DATABASE, AAD, truncated).is_err());
    assert!(decrypt(KEY, PROFILE, DATABASE, AAD, &[0; 12]).is_err());
}
