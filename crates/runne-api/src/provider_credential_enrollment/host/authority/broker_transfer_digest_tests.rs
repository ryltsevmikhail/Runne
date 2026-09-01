use super::{ProviderCredentialBrokerKillBindingV1, ProviderCredentialEnrollmentHostError};

#[test]
fn kill_binding_digest_matches_independent_sha256_vector() {
    assert_eq!(
        binding([1, 2, 3, 4, 5, 6]).binding_digest().unwrap(),
        [
            0xe4, 0x5a, 0x3b, 0xb1, 0xda, 0x8e, 0x8d, 0xf8, 0x57, 0x01, 0x19, 0xe4, 0xde, 0xbe,
            0x37, 0xac, 0xad, 0x20, 0xd6, 0x20, 0xb2, 0xff, 0x22, 0x59, 0x54, 0xf9, 0x01, 0x25,
            0x24, 0xf8, 0x38, 0x3c,
        ]
    );
}

#[test]
fn kill_binding_digest_changes_for_every_tuple_field() {
    let baseline = binding([1, 2, 3, 4, 5, 6]).binding_digest().unwrap();
    for changed in [
        [7, 2, 3, 4, 5, 6],
        [1, 7, 3, 4, 5, 6],
        [1, 2, 7, 4, 5, 6],
        [1, 2, 3, 7, 5, 6],
        [1, 2, 3, 4, 7, 6],
        [1, 2, 3, 4, 5, 7],
    ] {
        assert_ne!(binding(changed).binding_digest().unwrap(), baseline);
    }
}

#[test]
fn kill_binding_digest_rejects_each_zero_tuple_field() {
    for index in 0..6 {
        let mut fields = [1, 2, 3, 4, 5, 6];
        fields[index] = 0;
        assert_eq!(
            binding(fields).binding_digest(),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        );
    }
}

fn binding(values: [u8; 6]) -> ProviderCredentialBrokerKillBindingV1 {
    ProviderCredentialBrokerKillBindingV1::new(
        [values[0]; 32],
        [values[1]; 32],
        [values[2]; 32],
        [values[3]; 32],
        [values[4]; 32],
        [values[5]; 32],
    )
}
