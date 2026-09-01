use crate::{CredentialWriterSessionAttestationCodec, daemon_credential_publication};

use super::support::{
    EXPECTED_ATTESTATION_DIGEST, EXPECTED_PUBLIC_KEY, SEED, claims, frame, kat_bytes, resign,
};

const DOMAIN: &[u8] = b"GOCODE_PROVIDER_CREDENTIAL_WRITER_SESSION_ATTESTATION_V1\0";

#[test]
fn attestation_matches_independent_signature_and_digest_vector() {
    let bytes = kat_bytes();
    let decoded =
        CredentialWriterSessionAttestationCodec::decode_and_verify(&bytes, EXPECTED_PUBLIC_KEY)
            .unwrap();

    assert_eq!(
        CredentialWriterSessionAttestationCodec::encode(&decoded),
        bytes
    );
    assert_eq!(
        decoded.binding_digest().as_bytes(),
        EXPECTED_ATTESTATION_DIGEST
    );
}

#[test]
fn attestation_rejects_self_rooted_foreign_key_and_wrong_domain() {
    let mut foreign = kat_bytes();
    let foreign_key = resign(&mut foreign, [43; 32], DOMAIN);
    foreign[345..377].copy_from_slice(&foreign_key);
    resign(&mut foreign, [43; 32], DOMAIN);

    let mut wrong_domain = kat_bytes();
    resign(&mut wrong_domain, SEED, b"WRONG_DOMAIN\0");

    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(&foreign, EXPECTED_PUBLIC_KEY)
            .is_err()
    );
    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(
            &wrong_domain,
            EXPECTED_PUBLIC_KEY
        )
        .is_err()
    );
}

#[test]
fn attestation_signature_covers_every_canonical_field() {
    let original = kat_bytes();
    for offset in [
        1, 17, 25, 57, 89, 121, 153, 185, 217, 249, 257, 265, 297, 305, 313, 345, 377, 409, 441,
        473, 505, 537,
    ] {
        let mut changed = original;
        changed[offset] ^= 0x80;
        assert!(
            CredentialWriterSessionAttestationCodec::decode_and_verify(
                &changed,
                EXPECTED_PUBLIC_KEY
            )
            .is_err(),
            "offset {offset} was not authenticated"
        );
    }
}

#[test]
fn attestation_rejects_nonexact_version_sequence_signature_and_length() {
    let original = kat_bytes();
    for offset in [0, 569, 577] {
        let mut changed = original;
        changed[offset] ^= 1;
        assert!(
            CredentialWriterSessionAttestationCodec::decode_and_verify(
                &changed,
                EXPECTED_PUBLIC_KEY
            )
            .is_err()
        );
    }
    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(
            &original[..640],
            EXPECTED_PUBLIC_KEY
        )
        .is_err()
    );
    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(
            &[original.as_slice(), &[0]].concat(),
            EXPECTED_PUBLIC_KEY
        )
        .is_err()
    );
}

#[test]
fn attestation_rejects_zero_and_invalid_time_fields_even_when_resigned() {
    for range in [
        1..17,
        17..25,
        25..57,
        57..89,
        89..121,
        121..153,
        153..185,
        185..217,
        217..249,
        249..257,
        257..265,
        265..297,
        297..305,
        313..345,
        345..377,
        377..409,
        409..441,
        441..473,
        473..505,
        505..537,
        537..569,
    ] {
        let mut changed = kat_bytes();
        changed[range].fill(0);
        resign(&mut changed, SEED, DOMAIN);
        assert!(
            CredentialWriterSessionAttestationCodec::decode_and_verify(
                &changed,
                EXPECTED_PUBLIC_KEY
            )
            .is_err()
        );
    }
    let mut negative_issued = kat_bytes();
    negative_issued[297..305].copy_from_slice(&(-1_i64).to_be_bytes());
    resign(&mut negative_issued, SEED, DOMAIN);
    let mut nonadvancing_expiry = kat_bytes();
    nonadvancing_expiry[305..313].copy_from_slice(&13_i64.to_be_bytes());
    resign(&mut nonadvancing_expiry, SEED, DOMAIN);
    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(
            &negative_issued,
            EXPECTED_PUBLIC_KEY
        )
        .is_err()
    );
    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(
            &nonadvancing_expiry,
            EXPECTED_PUBLIC_KEY
        )
        .is_err()
    );
}

#[test]
fn generated_attestation_round_trips_with_independently_expected_key() {
    let issue = frame(30, 1, 31, 32, 33, 1);
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([32; 32])
            .unwrap();
    let expected_key = signer.public_key();
    let (attestation, publication_signer) = signer.sign(claims(&issue)).unwrap();
    let encoded = CredentialWriterSessionAttestationCodec::encode(&attestation);

    assert_eq!(attestation.publication_public_key(), expected_key);
    assert_eq!(publication_signer.public_key(), expected_key);
    assert!(
        CredentialWriterSessionAttestationCodec::decode_and_verify(&encoded, expected_key).is_ok()
    );
}
