use super::*;
use crate::provider::CredentialDispatchAuthority;

#[test]
fn sealed_stale_dispatch_refuses_native_materialization_before_effect_rows() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "sealed-stale.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 86, "sealed-stale");
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 86, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let binding = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (credential, _) = binding.split();
    let fencing = reopen_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::hard_fence_provider(
        &fencing,
        HardFenceProvider::new(
            provider(),
            CredentialFence::new(2).unwrap(),
            CredentialFence::new(3).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    assert!(
        credential
            .validate_online_materialization(
                CredentialDispatchAuthority::new(&lifecycle, &launch),
                admission.claim(),
                100,
            )
            .is_err()
    );
    assert_eq!(counts(&path), (0, 0, 0));
}
