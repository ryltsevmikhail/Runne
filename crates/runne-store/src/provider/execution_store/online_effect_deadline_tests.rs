use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::authority_test_support::{config, prepare_request_for_provider};
use super::{ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore};
use crate::provider::credential_lifecycle::online_claim_test_support::{
    open_test_store, reopen_test_store,
};
use crate::provider::credential_lifecycle::online_test_support::complete_pair;

#[test]
fn delayed_online_readback_uses_only_remaining_effect_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join("deadline.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 86, "deadline-online");
    drop(lifecycle);
    let now = Arc::new(AtomicI64::new(100));
    let reads = Arc::new(AtomicUsize::new(0));
    let clock_now = Arc::clone(&now);
    let clock_reads = Arc::clone(&reads);
    let store = SqliteProviderExecutionStore::open_with_now(
        &path,
        Arc::new(move || {
            if clock_reads.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                clock_now.store(210, Ordering::SeqCst);
            }
            clock_now.load(Ordering::SeqCst)
        }),
    )
    .unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    reads.store(0, Ordering::SeqCst);
    let admission = match store
        .issue(
            &launch,
            &prepare_request_for_provider(&launch, &path, 86, "openai"),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    now.store(100, Ordering::SeqCst);
    reads.store(0, Ordering::SeqCst);
    let binding = reopen_test_store(&path, 100)
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    let deadline = store
        .start_online_effect(&launch, admission.claim(), &effect_binding)
        .unwrap()
        .into_effect_receipt()
        .deadline();
    assert!(
        deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(11),
        "readback must not mint a renewed 120-second deadline"
    );
}

#[test]
fn backward_online_readback_does_not_extend_the_original_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join("backward-deadline.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 87, "backward-deadline-online");
    drop(lifecycle);
    let now = Arc::new(AtomicI64::new(100));
    let reads = Arc::new(AtomicUsize::new(0));
    let clock_now = Arc::clone(&now);
    let clock_reads = Arc::clone(&reads);
    let store = SqliteProviderExecutionStore::open_with_now(
        &path,
        Arc::new(move || {
            if clock_reads.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                clock_now.store(90, Ordering::SeqCst);
            }
            clock_now.load(Ordering::SeqCst)
        }),
    )
    .unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    reads.store(0, Ordering::SeqCst);
    let admission = match store
        .issue(
            &launch,
            &prepare_request_for_provider(&launch, &path, 87, "openai"),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    now.store(100, Ordering::SeqCst);
    reads.store(0, Ordering::SeqCst);
    let binding = reopen_test_store(&path, 100)
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    let deadline = store
        .start_online_effect(&launch, admission.claim(), &effect_binding)
        .unwrap()
        .into_effect_receipt()
        .deadline();
    let remaining = deadline.saturating_duration_since(Instant::now());
    assert!(remaining <= Duration::from_secs(121));
    assert!(remaining >= Duration::from_secs(118));
}

#[test]
fn expired_online_readback_is_post_claim_uncertain() {
    for readback_at in [220, 221] {
        let directory = tempfile::tempdir().unwrap();
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = daemon.join(format!("expired-deadline-{readback_at}.sqlite"));
        let lifecycle = open_test_store(&path, 100);
        complete_pair(&lifecycle, 88, "expired-deadline-online");
        drop(lifecycle);
        let now = Arc::new(AtomicI64::new(100));
        let reads = Arc::new(AtomicUsize::new(0));
        let clock_now = Arc::clone(&now);
        let clock_reads = Arc::clone(&reads);
        let store = SqliteProviderExecutionStore::open_with_now(
            &path,
            Arc::new(move || {
                if clock_reads.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                    clock_now.store(readback_at, Ordering::SeqCst);
                }
                clock_now.load(Ordering::SeqCst)
            }),
        )
        .unwrap();
        let launch = store.activate_runtime_launch(&config()).unwrap();
        super::online_proof_test_support::arm(&store);
        reads.store(0, Ordering::SeqCst);
        let admission = match store
            .issue(
                &launch,
                &prepare_request_for_provider(&launch, &path, 88, "openai"),
            )
            .unwrap()
        {
            ProviderAuthorityIssueOutcome::Winner(value) => value,
            ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
        };
        now.store(100, Ordering::SeqCst);
        reads.store(0, Ordering::SeqCst);
        let binding = reopen_test_store(&path, 100)
            .authorize_online_dispatch(&launch, admission.claim(), 100)
            .unwrap();
        let (_, effect_binding) = binding.split();
        assert!(matches!(
            store.start_online_effect(&launch, admission.claim(), &effect_binding),
            Err(runne_application::provider::ProviderAdmissionError::PostClaimUncertain)
        ));
    }
}
