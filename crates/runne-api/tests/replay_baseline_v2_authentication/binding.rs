use super::*;

#[test]
fn authenticated_local_capabilities_remain_bound_to_their_originating_baseline() {
    let binding = binding();
    let authenticator =
        runne_api::ReplayBaselineV2Authenticator::from_native_rust_tcb([7; 32], binding.clone())
            .unwrap();
    let first = authenticator
        .verify_wire_v2(
            &signed_fields(&binding),
            ApiReplayAggregateKind::Conversation,
            ID,
            1_000,
        )
        .unwrap();
    let mut other_fields = signed_fields(&binding).to_unauthenticated_fields();
    other_fields.head_integrity_digest[0] ^= 1;
    let other = authenticator
        .verify_wire_v2(
            &sign_fields(other_fields, &binding),
            ApiReplayAggregateKind::Conversation,
            ID,
            1_000,
        )
        .unwrap();
    let checkpoint = authenticator
        .authenticate_resume_checkpoint_v2(
            &first,
            runne_api::UnauthenticatedReplayBaselineCheckpointFactsV2 {
                cursor: "runne-replay-cursor-v1.00".into(),
                aggregate_kind: ApiReplayAggregateKind::Conversation,
                aggregate_id: ID,
                event_id: *first.head_event_id(),
                sequence: first.sequence(),
                global_position: first.baseline_global_position(),
            },
        )
        .unwrap();

    assert!(checkpoint.matches_baseline(&first));
    assert!(!checkpoint.matches_baseline(&other));
    assert_eq!(
        first.durable_replay_binding_digest(),
        durable_binding_digest(&binding)
    );
}

fn durable_binding_digest(binding: &runne_api::RuntimeSessionBinding) -> [u8; 32] {
    let stable = binding.stable();
    let values = [
        lower_hex(stable.authority_id()),
        stable.principal_id().as_str().to_owned(),
        uuid_text(stable.lineage_id().as_bytes()),
        stable.profile_id().to_owned(),
        lower_hex(stable.schema_hash()),
        lower_hex(stable.capability_digest()),
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"runne/replay-persistence-binding/v1\0");
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().into()
}

fn uuid_text(value: &[u8; 16]) -> String {
    let value = lower_hex(value);
    format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    )
}

fn lower_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value
        .iter()
        .fold(String::with_capacity(value.len() * 2), |mut out, byte| {
            write!(&mut out, "{byte:02x}").unwrap();
            out
        })
}
