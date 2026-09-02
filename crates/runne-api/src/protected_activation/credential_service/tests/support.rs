use super::super::*;
use crate::protected_activation::LaunchSecret;

pub(super) fn binding() -> CredentialServiceRegistrationBinding {
    CredentialServiceRegistrationBinding::new(
        [2; 16],
        [1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 1],
        11,
        12,
        13,
        14,
        [3; 32],
        [4; 32],
        [5; 16],
        2,
        100,
    )
    .unwrap()
}

pub(super) fn auth(byte: u8) -> CredentialServiceSessionAuthenticator {
    CredentialServiceSessionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([byte; 32]).unwrap().derive_keys(),
    )
}

pub(super) fn mutated_bindings() -> Vec<CredentialServiceRegistrationBinding> {
    let mut values = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut value = binding();
            value.$field = $value;
            values.push(value);
        }};
    }
    changed!(service_epoch, [9; 16]);
    changed!(daemon_authority_generation, 99);
    changed!(runtime_generation, 99);
    changed!(supervisor_generation, 99);
    changed!(installed_generation, 99);
    changed!(installation_owner, [9; 32]);
    changed!(release_binding, [9; 32]);
    changed!(challenge_nonce, [9; 16]);
    changed!(join_attempt, 3);
    changed!(expires_at_unix_millis, 101);
    values
}
