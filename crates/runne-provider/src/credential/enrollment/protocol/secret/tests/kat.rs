use crate::{CredentialBindingDigest, CredentialOperationId, CredentialTicketAttempt};
use zeroize::Zeroizing;

#[test]
fn sealed_credential_cipher_matches_independent_hkdf_chacha20poly1305_vector() {
    let transcript = super::super::cipher::CipherTranscript {
        operation: CredentialOperationId::from_bytes([1; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(1).unwrap(),
        claim: CredentialBindingDigest::from_measured([2; 32]).unwrap(),
        offer: CredentialBindingDigest::from_measured([3; 32]).unwrap(),
        writer: [4; 32],
        sealer: [5; 32],
        length: 5,
    };
    let ciphertext =
        super::super::cipher::seal(&[0xa5; 32], &transcript, Zeroizing::new(b"hello".to_vec()))
            .unwrap();

    // Computed independently with Node.js OpenSSL `hkdfSync` and
    // `chacha20-poly1305`, not by a seal/open round-trip.
    assert_eq!(
        ciphertext.as_slice(),
        [
            0x71, 0xb6, 0x36, 0xb6, 0xc5, 0x3a, 0x52, 0x39, 0x47, 0xbb, 0x19, 0x73, 0x4e, 0x25,
            0xa8, 0xc6, 0x1a, 0x30, 0x6e, 0x8e, 0x60,
        ]
    );
}
