use runne_app_core::{
    AppCore, AppCoreError, DestructiveConfirmationContext, DestructiveConfirmationFuture,
    DestructiveConfirmationPort, ProjectDestructiveOperation,
};
use runne_runtime_client::CanonicalId;

struct Deny;
impl DestructiveConfirmationPort for Deny {
    fn confirm(&self, _: DestructiveConfirmationContext) -> DestructiveConfirmationFuture<'_> {
        Box::pin(std::future::ready(None))
    }
}

#[tokio::test]
async fn destructive_project_action_requires_a_live_anchored_runtime() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("core");

    let result = core
        .execute_destructive_project_action(
            ProjectDestructiveOperation::Archive,
            CanonicalId::now_v7(),
            1,
            &Deny,
        )
        .await;

    assert_eq!(
        result
            .expect_err("legacy core must fail closed")
            .to_string(),
        AppCoreError::RuntimeUnavailable.to_string(),
    );
}
