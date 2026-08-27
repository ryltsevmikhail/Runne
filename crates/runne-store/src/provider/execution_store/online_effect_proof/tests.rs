use super::{CommittedEffectProofFields, IssuanceProofFields};
use crate::provider::execution_store::authority_test_support::Fixture;
use runne_application::provider::ProviderJournalKeyBinding;

#[test]
fn issuance_proof_rejects_every_distinct_single_field_mutation() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let state = fixture.store.online_effect_proof.lock().unwrap();
    let proof = state.as_ref().unwrap();
    let fields = issuance_fields(proof.binding());
    let mac = proof.issue(&fields).unwrap();
    assert!(proof.verify_issue(&fields, &mac), "unchanged issuance");

    macro_rules! rejects {
        ($name:literal, $change:expr) => {{
            let mut changed = fields.clone();
            $change(&mut changed);
            assert!(!proof.verify_issue(&changed, &mac), $name);
        }};
    }
    rejects!("proof_version", |value: &mut IssuanceProofFields| value
        .proof_version =
        2);
    rejects!("key_id", |value: &mut IssuanceProofFields| value.key =
        key([8; 16], 1, [1; 16], 7));
    rejects!("key_version", |value: &mut IssuanceProofFields| value.key =
        key([9; 16], 2, [1; 16], 7));
    rejects!(
        "key_runtime_authority",
        |value: &mut IssuanceProofFields| value.key = key([9; 16], 1, [4; 16], 7)
    );
    rejects!(
        "key_database_generation",
        |value: &mut IssuanceProofFields| value.key = key([9; 16], 1, [1; 16], 8)
    );
    rejects!("runtime_authority_id", |value: &mut IssuanceProofFields| {
        value.runtime_authority_id = [5; 16]
    });
    rejects!("database_generation", |value: &mut IssuanceProofFields| {
        value.database_generation = 12
    });
    rejects!("provider_id", |value: &mut IssuanceProofFields| value
        .provider_id =
        "other".into());
    rejects!("idempotency", |value: &mut IssuanceProofFields| value
        .provider_idempotency_key =
        "other-key".into());
    rejects!("call_id", |value: &mut IssuanceProofFields| value.call_id =
        [6; 16]);
    rejects!("attempt_id", |value: &mut IssuanceProofFields| value
        .attempt_id =
        [7; 16]);
    rejects!("authority_id", |value: &mut IssuanceProofFields| value
        .authority_id =
        [8; 16]);
    rejects!("authority_revision", |value: &mut IssuanceProofFields| {
        value.authority_revision = 14
    });
    rejects!("semantic_digest", |value: &mut IssuanceProofFields| value
        .semantic_digest =
        [9; 32]);
    rejects!("permit_id", |value: &mut IssuanceProofFields| value
        .permit_id =
        [10; 16]);
    rejects!("token_reservation_id", |value: &mut IssuanceProofFields| {
        value.token_reservation_id = [11; 16]
    });
    rejects!("cost_reservation_id", |value: &mut IssuanceProofFields| {
        value.cost_reservation_id = [12; 16]
    });
    rejects!("generation", |value: &mut IssuanceProofFields| value
        .generation =
        15);
    rejects!("fencing_token", |value: &mut IssuanceProofFields| value
        .fencing_token =
        16);
    rejects!("prepared_digest", |value: &mut IssuanceProofFields| value
        .prepared_digest =
        [13; 32]);
    rejects!("render_digest", |value: &mut IssuanceProofFields| value
        .render_digest =
        [14; 32]);
    rejects!("profile_digest", |value: &mut IssuanceProofFields| value
        .profile_digest =
        [15; 32]);
    rejects!("pricing_digest", |value: &mut IssuanceProofFields| value
        .pricing_revision_digest =
        [16; 32]);
    rejects!("issued_at", |value: &mut IssuanceProofFields| value
        .issued_at =
        18);
    rejects!("expires_at", |value: &mut IssuanceProofFields| value
        .expires_at =
        19);
}

#[test]
fn committed_effect_proof_rejects_every_distinct_single_field_mutation() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let state = fixture.store.online_effect_proof.lock().unwrap();
    let proof = state.as_ref().unwrap();
    let binding = proof.binding();
    let fields = committed_fields();
    let mac = proof.effect(binding, &fields).unwrap();
    assert!(
        proof.verify_effect(binding, &fields, &mac),
        "unchanged effect"
    );

    macro_rules! rejects {
        ($name:literal, $field:ident, $value:expr) => {{
            let mut changed = fields.clone();
            changed.$field = $value;
            assert!(!proof.verify_effect(binding, &changed, &mac), $name);
        }};
    }
    rejects!("issuance_mac", issuance_mac, [20; 32]);
    rejects!("attempt_id", attempt_id, [21; 16]);
    rejects!("provider_id", provider_id, "other".into());
    rejects!("launch_generation", launch_generation, 22);
    rejects!("lifecycle_revision", lifecycle_revision, 23);
    rejects!("credential_fence", credential_fence, 24);
    rejects!("credential_version", credential_version, 25);
    rejects!("credential_ref_digest", credential_ref_digest, [26; 32]);
    rejects!("lease_owner", lease_owner, [27; 16]);
    rejects!("lease_expires_at", lease_expires_at, 28);
    rejects!("lease_fence", lease_fence, 29);
    rejects!("effect_started_at", effect_started_at, 30);
    rejects!("effect_expires_at", effect_expires_at, 31);
}

fn issuance_fields(key: ProviderJournalKeyBinding) -> IssuanceProofFields {
    IssuanceProofFields {
        proof_version: 1,
        key,
        runtime_authority_id: [1; 16],
        database_generation: 7,
        provider_id: "openai".into(),
        provider_idempotency_key: "proof-issue".into(),
        call_id: [2; 16],
        attempt_id: [3; 16],
        authority_id: [4; 16],
        authority_revision: 13,
        semantic_digest: [5; 32],
        permit_id: [6; 16],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        generation: 11,
        fencing_token: 12,
        prepared_digest: [9; 32],
        render_digest: [10; 32],
        profile_digest: [11; 32],
        pricing_revision_digest: [12; 32],
        issued_at: 16,
        expires_at: 17,
    }
}

fn committed_fields() -> CommittedEffectProofFields {
    CommittedEffectProofFields {
        issuance_mac: [1; 32],
        attempt_id: [2; 16],
        provider_id: "openai".into(),
        launch_generation: 3,
        lifecycle_revision: 4,
        credential_fence: 5,
        credential_version: 6,
        credential_ref_digest: [7; 32],
        lease_owner: [8; 16],
        lease_expires_at: 9,
        lease_fence: 10,
        effect_started_at: 11,
        effect_expires_at: 12,
    }
}

fn key(
    id: [u8; 16],
    version: u64,
    authority: [u8; 16],
    generation: u64,
) -> ProviderJournalKeyBinding {
    ProviderJournalKeyBinding::new(id, version, authority, generation).unwrap()
}
