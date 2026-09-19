use super::{
    SqliteProviderCredentialLifecycleStore,
    online_test_support::{begin, digest, operation, ticket},
    qualification_tests::{admission, counts},
};
use runne_provider::{
    AttachCredentialProcess, CredentialAuthorityPair, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, ProviderCredentialEnrollmentStore,
};
use std::{
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

fn open(
    path: &Path,
) -> (
    SqliteProviderCredentialLifecycleStore,
    CredentialEnrollmentMeasurementAuthority,
) {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = if path.exists() {
        SqliteProviderCredentialLifecycleStore::open_with_connection_authorities_and_now(
            crate::schema::open_test_shared_writer(path).unwrap(),
            lifecycle,
            authority,
            Arc::new(|| 100),
        )
    } else {
        SqliteProviderCredentialLifecycleStore::open_with_authorities_and_now(
            path,
            lifecycle,
            authority,
            Arc::new(|| 100),
        )
    }
    .unwrap();
    (store, measurements)
}

#[test]
fn qualified_crash_child() {
    let Ok(path) = std::env::var("RUNNE_QUALIFIED_CRASH_DB") else {
        return;
    };
    let (store, measurements) = open(Path::new(&path));
    store.begin(begin(1, "qualified-crash", 2)).unwrap();
    store
        .attach_process(AttachCredentialProcess::new(operation(1), digest(4)).unwrap())
        .unwrap();
    store
        .issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&measurements))
        .unwrap();
    panic!("child must be killed at the requested transaction boundary");
}

#[test]
fn qualified_process_kill_before_and_after_commit_preserves_exact_durable_consumption() {
    for stage in ["before", "after"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("crash.sqlite");
        let marker = directory.path().join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "provider::credential_lifecycle::qualification_crash_tests::qualified_crash_child",
                "--nocapture",
            ])
            .env("RUNNE_QUALIFIED_CRASH_DB", &path)
            .env("RUNNE_QUALIFIED_CRASH_POINT", stage)
            .env("RUNNE_QUALIFIED_CRASH_MARKER", &marker)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !marker.exists() && Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not reach {stage}-commit pause");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let (store, measurements) = open(&path);
        let expected = if stage == "after" { (1, 1) } else { (0, 0) };
        assert_eq!(counts(&store), expected);
        let replay = store.issue_ticket_attempt_with_qualification_fence(
            ticket(1, 1, 5, 4),
            admission(&measurements),
        );
        assert_eq!(replay.is_ok(), stage == "before");
        assert_eq!(counts(&store), (1, 1));
    }
}

pub(super) fn pause(stage: &str) {
    if std::env::var("RUNNE_QUALIFIED_CRASH_POINT").as_deref() != Ok(stage) {
        return;
    }
    let marker = std::env::var_os("RUNNE_QUALIFIED_CRASH_MARKER").expect("child marker");
    std::fs::write(marker, b"ready").unwrap();
    loop {
        std::thread::park();
    }
}
