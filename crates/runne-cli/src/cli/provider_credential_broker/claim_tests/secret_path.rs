use std::io::Read;

use runne_provider::{CredentialOperationAction, CredentialSecretInputPresence};

use super::{accepted, binding, claim_for_test, command, endpoint, issue};

#[test]
fn secret_path_is_pair_only_and_consumes_the_post_ack_state() {
    let pair = command(9, CredentialOperationAction::Pair);
    let (pair_parts, _) = endpoint(
        issue(pair.clone(), binding(), [11; 32]),
        Some(accepted(&pair)),
    );
    let claimed = claim_for_test(pair_parts, CredentialSecretInputPresence::Present)
        .expect("pair acknowledgement");
    assert!(claimed.authorize_without_secret().is_err());

    let revoke = command(10, CredentialOperationAction::Revoke);
    let (revoke_parts, _) = endpoint(
        issue(revoke.clone(), binding(), [11; 32]),
        Some(accepted(&revoke)),
    );
    let claimed = claim_for_test(revoke_parts, CredentialSecretInputPresence::Absent)
        .expect("revoke acknowledgement");
    assert!(claimed.read_pair_secret(&mut PanicReader).is_err());
}

struct PanicReader;

impl Read for PanicReader {
    fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
        panic!("non-Pair path must not read a secret source")
    }
}
