use super::super::ProviderOnlineEffectStartReceipt;
use super::*;
use crate::provider::credential_lifecycle::online_test_support::revoke;

#[test]
fn successful_online_final_send_authority_is_one_use() {
    let (_directory, _path, _store, online_receipt) = started_online(88, "final-send-live");
    let mut receipt = online_receipt.into_effect_receipt();
    receipt
        .take_final_send_authority()
        .unwrap()
        .consume()
        .unwrap();
    assert!(receipt.take_final_send_authority().is_err());
}

#[test]
fn revoked_credential_is_denied_by_the_one_use_final_send_gate() {
    let (_directory, path, _store, online_receipt) = started_online(89, "final-send-revoked");
    let mut receipt = online_receipt.into_effect_receipt();
    let authority = receipt.take_final_send_authority().unwrap();
    reopen_test_store(&path, 100)
        .begin(revoke(90, "final-send-revocation", 2, 2))
        .unwrap();

    let mut sends = 0;
    if authority.consume().is_ok() {
        sends += 1;
    }

    assert_eq!(sends, 0);
    assert!(receipt.take_final_send_authority().is_err());
}

fn started_online(
    id: u8,
    key: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SqliteProviderExecutionStore,
    ProviderOnlineEffectStartReceipt,
) {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "final-send.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, id, key);
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 100)).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::super::authority_test_support::prepare_request_for_provider(
                &launch, &path, id, "openai",
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
    let (_, effect_binding) = binding.split();
    let receipt = store
        .start_online_effect(&launch, admission.claim(), &effect_binding)
        .unwrap();
    (directory, path, store, receipt)
}
