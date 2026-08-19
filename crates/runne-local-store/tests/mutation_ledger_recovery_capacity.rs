use runne_local_store::{
    BoundedCanonicalId, LocalStore, MAX_MUTATION_RECOVERY_RECORDS, MutationIdentity,
    MutationOperation, MutationRecoveryBinding, MutationRecoveryLimit, MutationTargetKind,
    NormalizedMutationCommand, V7MutationTransition,
};
use runne_secure_store::test_support::DeterministicSecureStore;

#[test]
fn recovery_capacity_is_binding_scoped_and_frees_only_after_terminalization() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [31; 32];
    let secure = DeterministicSecureStore::new(profile);
    let mut store =
        LocalStore::open_anchored(&directory.path().join("profile.sqlite3"), &secure, profile)
            .expect("admitted");
    let binding = ([1; 32], [2; 32]);
    let mut first = None;
    for index in 0..MAX_MUTATION_RECOVERY_RECORDS {
        let (identity, command) = prepared(index, binding);
        let permit = store
            .prepare_anchored_mutation_v7(&secure, identity.clone(), command)
            .expect("capacity slot");
        if index == 0 {
            first = Some((identity, permit.generation()));
        }
    }
    let (first_identity, _) = first.expect("first record");
    store
        .prepare_anchored_mutation_v7(&secure, first_identity.clone(), command_for_index(0))
        .expect("duplicate predecessor");
    assert_eq!(
        store
            .recover_anchored_mutations_v7(
                &secure,
                MutationRecoveryBinding::new(binding.0, binding.1).expect("binding"),
                MutationRecoveryLimit::new(MAX_MUTATION_RECOVERY_RECORDS).expect("limit"),
            )
            .expect("recovery")
            .records()
            .len(),
        MAX_MUTATION_RECOVERY_RECORDS,
    );
    let (blocked, command) = prepared(MAX_MUTATION_RECOVERY_RECORDS, binding);
    assert!(
        store
            .prepare_anchored_mutation_v7(&secure, blocked.clone(), command)
            .is_err()
    );
    let (other_binding, command) = prepared(MAX_MUTATION_RECOVERY_RECORDS, ([3; 32], [4; 32]));
    assert!(
        store
            .prepare_anchored_mutation_v7(&secure, other_binding, command)
            .is_ok()
    );
    store
        .transition_anchored_mutation_v7(
            &secure,
            first_identity,
            V7MutationTransition::ManualResolution {
                summary: "cancelled".into(),
                timestamp: 1,
            },
        )
        .expect("terminal");
    assert!(
        store
            .prepare_anchored_mutation_v7(
                &secure,
                blocked,
                command_for_index(MAX_MUTATION_RECOVERY_RECORDS)
            )
            .is_ok()
    );
}

fn prepared(
    index: usize,
    binding: ([u8; 32], [u8; 32]),
) -> (MutationIdentity, NormalizedMutationCommand) {
    let name = format!("project-{index}");
    let identity = MutationIdentity::new(
        binding.0,
        binding.1,
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id(&name),
        format!("key-{index}"),
        0,
        [u8::try_from(index + 1).expect("bounded test index"); 32],
    )
    .expect("identity");
    (identity, command_for_index(index))
}

fn command_for_index(index: usize) -> NormalizedMutationCommand {
    NormalizedMutationCommand::create_project(id(&format!("project-{index}")), "Project".into())
        .expect("command")
}

fn id(value: &str) -> BoundedCanonicalId {
    let hash = value.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
    });
    BoundedCanonicalId::parse(
        format!(
            "018f2e3a-7000-7000-8000-{:012x}",
            hash & 0x0000_ffff_ffff_ffff
        )
        .as_bytes(),
    )
    .expect("canonical id")
}
