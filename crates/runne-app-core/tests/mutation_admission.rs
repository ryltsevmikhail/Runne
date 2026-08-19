use runne_app_core::{AppCore, AppCoreError, MutationRequest};
use runne_runtime_client::CanonicalId;

#[tokio::test]
async fn legacy_core_cannot_prepare_a_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).unwrap();
    let result = core
        .prepare_mutation(
            MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7())
                .unwrap(),
        )
        .await;
    assert_eq!(
        result.unwrap_err().to_string(),
        AppCoreError::RuntimeUnavailable.to_string()
    );
}
