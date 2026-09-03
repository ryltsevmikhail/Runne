use std::time::{Duration, Instant};

use super::ProviderEffectStartReceipt;

#[test]
fn credential_read_receipt_is_stable_and_binds_the_durable_effect_start() {
    let first = receipt(3);
    let same = receipt(3);
    let changed = receipt(4);

    assert_eq!(
        first.credential_read_receipt_digest(),
        same.credential_read_receipt_digest()
    );
    assert_ne!(
        first.credential_read_receipt_digest(),
        changed.credential_read_receipt_digest()
    );
    assert_ne!(first.credential_read_receipt_digest(), [0; 32]);
}

fn receipt(credential_version: u64) -> ProviderEffectStartReceipt {
    ProviderEffectStartReceipt {
        expires_at: 30,
        attempt_id: [1; 16],
        permit_id: [2; 16],
        provider_idempotency_key: "provider:test".into(),
        prepared_digest: [3; 32],
        render_digest: [4; 32],
        profile_digest: [5; 32],
        fencing_token: 6,
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        deadline: Instant::now() + Duration::from_secs(5),
        credential_provider: "deepseek".into(),
        credential_version,
        credential_ref_digest: [9; 32],
        credential_owner: [10; 16],
        credential_expires_at: 40,
        credential_fencing_token: 11,
    }
}
