use gocode_api::{
    ExecutableIdentityV1, PendingFirstActivationV1, ProtectedRuntimeProfileV1,
    StableRuntimeBindingV1,
};
use gocode_daemon::bootstrap::bootstrap_protected;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use rusqlite::OptionalExtension as _;
use sha2::{Digest, Sha256};

const STABLE_AUTHORITY: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 1,
];
const LINEAGE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 2,
];
const PREPARATION: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 3,
];
const FIRST_LAUNCH: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 4,
];
const SECOND_LAUNCH: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 5,
];

fn pending() -> PendingFirstActivationV1 {
    PendingFirstActivationV1::new(
        PREPARATION,
        [0x10; 32],
        StableRuntimeBindingV1::new(
            STABLE_AUTHORITY,
            "local-owner",
            LINEAGE,
            "gocode-ui-client/1",
            [0x20; 32],
            [0x30; 32],
        )
        .unwrap(),
        ExecutableIdentityV1::new([0x40; 32], [0x50; 32], 4_096).unwrap(),
        ProtectedRuntimeProfileV1::new(
            "gocode-bundled-runtime/1",
            1,
            "gocode-ui-client/1",
            [0x20; 32],
            [0x30; 32],
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn protected_bootstrap_commits_prepared_identity_and_consumes_authority_first() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    let first_secret = [0x61; 32];
    let first = bootstrap_protected(
        &config,
        FIRST_LAUNCH,
        first_secret,
        Some(&pending()),
        || Ok(()),
    )
    .unwrap();
    assert_eq!(first.authority_id, STABLE_AUTHORITY);
    assert_eq!(first.local_session_authority_id, STABLE_AUTHORITY);
    assert_eq!(first.launch_generation, 1);
    let expected_secret_marker: [u8; 32] = Sha256::digest(first_secret).into();
    assert_eq!(
        first.launch_identity.bootstrap_secret_marker(),
        expected_secret_marker
    );
    drop(first);

    let reused = bootstrap_protected(&config, FIRST_LAUNCH, [0x62; 32], Some(&pending()), || {
        Ok(())
    })
    .unwrap_err();
    assert!(reused.to_string().contains("already consumed"));
    let connection = rusqlite::Connection::open(&config.db_path).unwrap();
    let generation: String = connection
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(generation, "1");
    drop(connection);

    let second = bootstrap_protected(&config, SECOND_LAUNCH, [0x63; 32], None, || Ok(())).unwrap();
    assert_eq!(second.authority_id, STABLE_AUTHORITY);
    assert_eq!(second.launch_generation, 2);
}

#[test]
fn freshness_failure_after_sidecar_work_does_not_consume_or_advance_launch() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    let expired = bootstrap_protected(&config, FIRST_LAUNCH, [0x61; 32], Some(&pending()), || {
        Err(gocode_daemon::error::DaemonError::Bootstrap(
            "protected launch authority expired".into(),
        ))
    })
    .unwrap_err();
    assert!(expired.to_string().contains("expired"));

    let connection = rusqlite::Connection::open(&config.db_path).unwrap();
    let generation: Option<String> = connection
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    let consumed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM _daemon_info
             WHERE key LIKE 'protected_launch_authority_v1:%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(generation, None);
    assert_eq!(consumed, 0);
    drop(connection);

    let recovered =
        bootstrap_protected(&config, FIRST_LAUNCH, [0x62; 32], Some(&pending()), || {
            Ok(())
        })
        .expect("unconsumed exact preparation remains recoverable");
    assert_eq!(recovered.launch_generation, 1);
}
