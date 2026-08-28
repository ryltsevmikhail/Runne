use runne_provider::{CredentialLifecycleError, ProviderCredentialEnrollmentStore};

use super::online_test_support::{complete_pair, provider, store};

#[test]
fn current_verification_context_binds_the_exact_ready_active_version_and_release_tuple() {
    let store = store();
    complete_pair(&store, 70, "verification-context");

    let context =
        ProviderCredentialEnrollmentStore::current_verification_context(&store, &provider())
            .unwrap();

    assert_eq!(context.provider(), &provider());
    assert_eq!(context.active_version().version(), 1);
    assert_eq!(context.lifecycle_revision().get(), 2);
    assert_eq!(context.fence().get(), 2);
    assert_eq!(context.readiness_revision().get(), 2);
    assert_eq!(context.release_tuple_digest().as_bytes(), [92; 32]);
}

#[test]
fn current_verification_context_rejects_missing_or_stale_readiness() {
    let store = store();
    assert_eq!(
        ProviderCredentialEnrollmentStore::current_verification_context(&store, &provider()),
        Err(CredentialLifecycleError::NotFound),
    );
    ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider()).unwrap();
    assert_eq!(
        ProviderCredentialEnrollmentStore::current_verification_context(&store, &provider()),
        Err(CredentialLifecycleError::Conflict),
    );
}
