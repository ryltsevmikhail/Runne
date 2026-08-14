use std::path::Path;
use std::sync::{Arc, Barrier};

use gocode_application::local_session::{
    BootstrapReservationError, BootstrapReservationStore, ConsumeReservation,
    PreallocateReservation,
};
use gocode_store::{
    local_session::SqliteBootstrapReservationStore,
    schema::{
        ConnectionMode, apply_migrations, ensure_authority_id, ensure_event_log_lineage_id,
        generate_authority_id, open_managed_connection, read_authority_id,
        read_event_log_lineage_id, reopen_managed_connection_validated,
    },
};

#[test]
fn concurrent_legitimate_preallocation_has_one_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("gocode-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = std::fs::canonicalize(daemon)
        .unwrap()
        .join("concurrent.sqlite");
    let stores = concurrent_stores(&path, 8);
    let barrier = Arc::new(Barrier::new(9));
    let threads = stores
        .into_iter()
        .map(|store| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.preallocate(input(1, 100)).unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let reservations = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();

    assert!(
        reservations
            .iter()
            .all(|value| value.challenge_id == reservations[0].challenge_id)
    );
    assert!(
        reservations
            .iter()
            .all(|value| value.server_nonce == reservations[0].server_nonce)
    );
}

#[test]
fn clock_regression_rejects_before_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("clock.sqlite");
    let store = store(&path);
    assert_eq!(store.observe_clock(200).unwrap(), 200);
    assert!(matches!(
        store.preallocate(input(1, 199)),
        Err(BootstrapReservationError::ClockRegression),
    ));
    drop(store);
    assert_eq!(row_count(&path, "bootstrap_reservations"), 0);
}

#[test]
fn restart_preserves_reservation_tombstone_clock_and_single_consume() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restart.sqlite");
    let first_store = store(&path);
    let reservation = first_store.preallocate(input(1, 100)).unwrap();
    assert_eq!(first_store.observe_clock(150).unwrap(), 150);
    drop(first_store);

    let reopened = store(&path);
    assert!(matches!(
        reopened.observe_clock(149),
        Err(BootstrapReservationError::ClockRegression),
    ));
    let accept = |_: &_| true;
    assert!(matches!(
        reopened.consume_final(ConsumeReservation {
            challenge_id: reservation.challenge_id,
            binding_proof: [3; 32],
            authority_digest: [7; 32],
            observed_at_unix_microseconds: 150,
            verify: &accept,
        }),
        Err(BootstrapReservationError::Rejected),
    ));
    reopened
        .consume_final(ConsumeReservation {
            challenge_id: reservation.challenge_id,
            binding_proof: [2; 32],
            authority_digest: [7; 32],
            observed_at_unix_microseconds: 151,
            verify: &accept,
        })
        .unwrap();
    drop(reopened);

    let after_crash = store(&path);
    assert!(matches!(
        after_crash.consume_final(ConsumeReservation {
            challenge_id: reservation.challenge_id,
            binding_proof: [2; 32],
            authority_digest: [8; 32],
            observed_at_unix_microseconds: 152,
            verify: &accept,
        }),
        Err(BootstrapReservationError::Rejected),
    ));
    drop(after_crash);
    assert_eq!(row_count(&path, "bootstrap_reservation_tombstones"), 1);
    assert_eq!(clock(&path), 151);
}

#[test]
fn crash_after_reservation_before_response_reuses_durable_challenge() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("response-crash.sqlite");
    let before_crash = store(&path);
    let first = before_crash.preallocate(input(1, 100)).unwrap();
    drop(before_crash);

    let after_crash = store(&path);
    let replay = after_crash.preallocate(input(1, 101)).unwrap();
    assert!(replay.challenge_id == first.challenge_id);
    assert_eq!(replay.server_nonce, first.server_nonce);
}

#[test]
fn reservation_key_collision_rejects_without_amplification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("collision.sqlite");
    let store = store(&path);
    store.preallocate(input(1, 100)).unwrap();
    let mut collision = input(1, 101);
    collision.client_nonce = [4; 32];

    assert!(matches!(
        store.preallocate(collision),
        Err(BootstrapReservationError::Rejected),
    ));
    drop(store);
    assert_eq!(row_count(&path, "bootstrap_reservations"), 1);
    assert_eq!(clock(&path), 100);
}

#[test]
fn thirty_two_plus_load_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded.sqlite");
    let store = store(&path);
    for key in 0..32_u8 {
        store.preallocate(input(key, 100)).unwrap();
    }
    assert!(matches!(
        store.preallocate(input(32, 100)),
        Err(BootstrapReservationError::Capacity),
    ));
    drop(store);
    assert_eq!(row_count(&path, "bootstrap_reservations"), 32);
}

#[test]
fn failed_attempt_fence_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fenced.sqlite");
    let first_store = store(&path);
    let reservation = first_store.preallocate(input(1, 100)).unwrap();
    let reject = |_: &_| false;
    for now in 101..109 {
        assert!(matches!(
            first_store.consume_final(ConsumeReservation {
                challenge_id: reservation.challenge_id,
                binding_proof: [2; 32],
                authority_digest: [7; 32],
                observed_at_unix_microseconds: now,
                verify: &reject,
            }),
            Err(BootstrapReservationError::Rejected),
        ));
    }
    drop(first_store);

    let reopened = store(&path);
    let accept = |_: &_| true;
    assert!(matches!(
        reopened.consume_final(ConsumeReservation {
            challenge_id: reservation.challenge_id,
            binding_proof: [2; 32],
            authority_digest: [7; 32],
            observed_at_unix_microseconds: 109,
            verify: &accept,
        }),
        Err(BootstrapReservationError::Rejected),
    ));
}

fn store(path: &Path) -> SqliteBootstrapReservationStore {
    let connection = open_managed_connection(path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    SqliteBootstrapReservationStore::new(connection)
}

fn concurrent_stores(path: &Path, count: usize) -> Vec<SqliteBootstrapReservationStore> {
    assert!(count > 0);
    let first = open_managed_connection(path, ConnectionMode::Writer).unwrap();
    apply_migrations(&first).unwrap();
    let authority = generate_authority_id();
    ensure_authority_id(&first, &authority).unwrap();
    let lineage = ensure_event_log_lineage_id(&first).unwrap();
    let mut stores = vec![SqliteBootstrapReservationStore::new(first)];
    for _ in 1..count {
        let connection = reopen_managed_connection_validated(
            path,
            ConnectionMode::ValidatedReopen,
            |connection| {
                if read_authority_id(connection)? == Some(authority)
                    && read_event_log_lineage_id(connection)? == Some(lineage)
                {
                    Ok(())
                } else {
                    Err(rusqlite::Error::InvalidQuery)
                }
            },
        )
        .unwrap();
        stores.push(SqliteBootstrapReservationStore::new(connection));
    }
    stores
}

fn input(key: u8, now: i64) -> PreallocateReservation {
    PreallocateReservation {
        reservation_key: [key; 32],
        binding_proof: [2; 32],
        key_version: 1,
        client_nonce: [3; 32],
        not_before_rfc3339_utc_microseconds: "1970-01-01T00:00:00.000000Z".into(),
        expiry_rfc3339_utc_microseconds: "1970-01-01T00:00:01.000000Z".into(),
        not_before_unix_microseconds: 0,
        expiry_unix_microseconds: 1_000_000,
        observed_at_unix_microseconds: now,
        fence: 7,
    }
}

fn row_count(path: &Path, table: &str) -> i64 {
    let connection = open_managed_connection(path, ConnectionMode::Writer).unwrap();
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn clock(path: &Path) -> i64 {
    let connection = open_managed_connection(path, ConnectionMode::Writer).unwrap();
    connection
        .query_row(
            "SELECT observed_at FROM bootstrap_last_observed_clock WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

include!("bootstrap_reservation_store/capacity_clock.rs");
