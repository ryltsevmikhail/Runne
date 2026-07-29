//! Integration tests for ReplayStore SQLite implementation.
//!
//! Tests cover: session lifecycle, authorization, HMAC integrity,
//! state transitions, and error conditions.

use gocode_application::ports::{ReplayError, ReplayState, ReplayStorePort};
use gocode_store::replay_store::{ReplayStore, build_test_high_water_ref};
use gocode_store::schema::apply_migrations;
use rusqlite::{Connection, params};

// ── Helpers ──────────────────────────────────────────────────────────────

const AUTH_ID: [u8; 16] = [0xAA; 16];
const AGG_ID: [u8; 16] = [0xBB; 16];
const SECRET: [u8; 32] = [0xCC; 32];
const PRINCIPAL: &str = "test-principal";

fn fresh_file_db(name: &str) -> (String, ReplayStore) {
    let mut path = std::env::temp_dir();
    path.push(format!("gocode-test-replay-{}.sqlite", name));
    let db_path = path.to_str().unwrap().to_string();

    // Clean up any previous test run
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));

    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .unwrap();
    apply_migrations(&conn).unwrap();
    let store = ReplayStore::new(conn);
    (db_path, store)
}

fn cleanup_db(db_path: &str) {
    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
}

/// Open a second connection to the same file-based DB.
fn open_read_conn(db_path: &str) -> Connection {
    let conn = Connection::open(db_path).unwrap();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
        .unwrap();
    conn
}

/// Insert an aggregate stream row so events can reference it.
fn insert_aggregate_stream(conn: &Connection, aggregate_type: i32, aggregate_id: &[u8; 16]) {
    conn.execute(
        "INSERT OR IGNORE INTO aggregate_streams
         (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
         VALUES (?1, ?2, 0, NULL, NULL, 0)",
        params![aggregate_type, aggregate_id.as_slice()],
    )
    .unwrap();
}

/// Insert a test event row.
fn insert_event(
    conn: &Connection,
    global_position: i64,
    event_id: &[u8; 16],
    aggregate_type: i32,
    aggregate_id: &[u8; 16],
    payload: &[u8],
    timestamp: i64,
) {
    let integrity_digest = [0u8; 32];
    conn.execute(
        "INSERT INTO events
         (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
          sensitivity, schema_version, causation_id, command_id, idempotency_key,
          actor, payload, integrity_digest, correlation_id, correlation_type,
          integrity_profile)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 8, NULL, ?1, x'01', x'02', ?7, ?8, ?1, 1, 1)",
        params![
            event_id.as_slice(),
            aggregate_type,
            aggregate_id.as_slice(),
            global_position, // sequence = global_position for simplicity
            global_position,
            timestamp,
            payload,
            integrity_digest.as_slice(),
        ],
    )
    .unwrap();
}

// ── open_session ─────────────────────────────────────────────────────────

#[tokio::test]
async fn open_session_atomic_commit() {
    let (db_path, store) = fresh_file_db("open_session_atomic_commit");
    let read_conn = open_read_conn(&db_path);

    // Insert aggregate stream and one event
    insert_aggregate_stream(&read_conn, 1, &AGG_ID);
    insert_event(&read_conn, 1, &[0x01; 16], 1, &AGG_ID, b"hello", 1000);

    let (session, events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].global_position, 1);
    assert_eq!(session.state, ReplayState::CatchingUp);
    assert_eq!(session.principal_id, PRINCIPAL);
    assert_eq!(session.high_water_position, 1);
    assert_eq!(session.high_water_ref.len(), 77);

    // Verify row exists in _replay_subscriptions
    let count: i64 = read_conn
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);

    cleanup_db(&db_path);
}

#[tokio::test]
async fn open_session_returns_multiple_events() {
    let (db_path, store) = fresh_file_db("open_session_multiple");
    let read_conn = open_read_conn(&db_path);

    insert_aggregate_stream(&read_conn, 1, &AGG_ID);
    for i in 1..=5 {
        let mut eid = [0u8; 16];
        eid[0] = i as u8;
        insert_event(&read_conn, i, &eid, 1, &AGG_ID, b"data", i * 100);
    }

    let (_session, events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    assert_eq!(events.len(), 5);
    assert!(
        events
            .windows(2)
            .all(|w| w[0].global_position < w[1].global_position),
        "events must be in global_position order"
    );

    cleanup_db(&db_path);
}

// ── read_page ────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_page_returns_empty_for_new_db() {
    let (db_path, store) = fresh_file_db("read_page_empty");

    let (session, events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    assert!(events.is_empty());

    let page = store
        .read_page(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, 100)
        .await
        .unwrap();

    assert!(page.is_empty());

    cleanup_db(&db_path);
}

#[tokio::test]
async fn read_page_returns_next_page() {
    let (db_path, store) = fresh_file_db("read_page_next");
    let read_conn = open_read_conn(&db_path);

    insert_aggregate_stream(&read_conn, 1, &AGG_ID);
    for i in 1..=200 {
        let mut eid = [0u8; 16];
        eid[7..15].copy_from_slice(&(i as u64).to_be_bytes());
        insert_event(&read_conn, i, &eid, 1, &AGG_ID, b"data", i * 100);
    }

    let (session, first_page) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    // open_session returns up to 100 events
    assert_eq!(first_page.len(), 100);

    // read_page returns next events
    let page2 = store
        .read_page(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, 100)
        .await
        .unwrap();

    assert_eq!(page2.len(), 100);
    assert_eq!(page2[0].global_position, 101);
    assert_eq!(page2[99].global_position, 200);

    cleanup_db(&db_path);
}

// ── complete_catch_up ────────────────────────────────────────────────────

#[tokio::test]
async fn complete_catch_up_transitions_state() {
    let (db_path, store) = fresh_file_db("complete_catch_up");
    let read_conn = open_read_conn(&db_path);

    insert_aggregate_stream(&read_conn, 1, &AGG_ID);
    insert_event(&read_conn, 1, &[0x01; 16], 1, &AGG_ID, b"data", 1000);

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    assert_eq!(session.state, ReplayState::CatchingUp);

    let proof = b"catch-up-done";
    let updated = store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, proof)
        .await
        .unwrap();

    assert_eq!(updated.state, ReplayState::CatchUpComplete);
    assert_eq!(updated.catch_up_completion, Some(proof.to_vec()));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn complete_catch_up_fails_on_wrong_state() {
    let (db_path, store) = fresh_file_db("complete_catch_up_wrong_state");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    // Transition to catch_up_complete
    store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, b"proof")
        .await
        .unwrap();

    // Second call should fail — not in CatchingUp
    let err = store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, b"proof2")
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::InvalidState(_)));

    cleanup_db(&db_path);
}

// ── continue_live ────────────────────────────────────────────────────────

#[tokio::test]
async fn continue_live_cas() {
    let (db_path, store) = fresh_file_db("continue_live");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, b"proof")
        .await
        .unwrap();

    let updated = store
        .continue_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();

    assert_eq!(updated.state, ReplayState::Live);
    assert!(updated.live_delivery_id.is_some());

    cleanup_db(&db_path);
}

#[tokio::test]
async fn continue_live_fails_without_catch_up_complete() {
    let (db_path, store) = fresh_file_db("continue_live_without_catchup");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    // Should fail — state is CatchingUp, not CatchUpComplete
    let err = store
        .continue_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::InvalidState(_)));

    cleanup_db(&db_path);
}

// ── close_session ────────────────────────────────────────────────────────

#[tokio::test]
async fn close_session_transitions_to_closed() {
    let (db_path, store) = fresh_file_db("close_session");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, b"proof")
        .await
        .unwrap();

    store
        .close_session(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();

    // Verify state is 'closed' in DB
    let read_conn = open_read_conn(&db_path);
    let state: String = read_conn
        .query_row(
            "SELECT state FROM _replay_subscriptions WHERE session_id = ?1",
            params![session.session_id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "closed");

    cleanup_db(&db_path);
}

// ── poll_live ────────────────────────────────────────────────────────────

#[tokio::test]
async fn poll_live_returns_new_events() {
    let (db_path, store) = fresh_file_db("poll_live");
    let read_conn = open_read_conn(&db_path);

    insert_aggregate_stream(&read_conn, 1, &AGG_ID);

    // Insert one event before session open (high_water = 1)
    insert_event(&read_conn, 1, &[0x01; 16], 1, &AGG_ID, b"before", 1000);

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, b"proof")
        .await
        .unwrap();

    store
        .continue_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();

    // Insert new events after high_water
    insert_event(&read_conn, 2, &[0x02; 16], 1, &AGG_ID, b"after1", 2000);
    insert_event(&read_conn, 3, &[0x03; 16], 1, &AGG_ID, b"after2", 3000);

    let live_events = store
        .poll_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();

    // Should return events with global_position > high_water (1)
    assert_eq!(live_events.len(), 2);
    assert_eq!(live_events[0].global_position, 2);
    assert_eq!(live_events[1].global_position, 3);

    cleanup_db(&db_path);
}

#[tokio::test]
async fn poll_live_fails_on_non_live_state() {
    let (db_path, store) = fresh_file_db("poll_live_non_live");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    let err = store
        .poll_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::InvalidState(_)));

    cleanup_db(&db_path);
}

// ── Authorization ────────────────────────────────────────────────────────

#[tokio::test]
async fn forged_session_id_rejected() {
    let (db_path, store) = fresh_file_db("forged_session");

    let (_session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    // Use a random session_id that doesn't exist
    let fake_id = [0xFF; 16];
    let err = store
        .read_page(&fake_id, PRINCIPAL, 1, &AUTH_ID, 0, 100)
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::SessionNotFound));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn unauthorized_principal_rejected() {
    let (db_path, store) = fresh_file_db("unauth_principal");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    let err = store
        .read_page(&session.session_id, "evil-principal", 1, &AUTH_ID, 0, 100)
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::Unauthorized(_)));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn stale_generation_rejected() {
    let (db_path, store) = fresh_file_db("stale_gen");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    let err = store
        .read_page(&session.session_id, PRINCIPAL, 2, &AUTH_ID, 0, 100)
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::StaleGeneration));

    cleanup_db(&db_path);
}

#[tokio::test]
async fn wrong_authority_rejected() {
    let (db_path, store) = fresh_file_db("wrong_auth");

    let (session, _events) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();

    let other_auth = [0xDD; 16];
    let err = store
        .read_page(&session.session_id, PRINCIPAL, 1, &other_auth, 0, 100)
        .await
        .unwrap_err();

    assert!(matches!(err, ReplayError::Unauthorized(_)));

    cleanup_db(&db_path);
}

// ── HMAC ────────────────────────────────────────────────────────────────

#[test]
fn hmac_high_water_ref_deterministic() {
    let auth = [0x01u8; 16];
    let sess = [0x02u8; 16];
    let secret = [0x03u8; 32];

    let ref1 = build_test_high_water_ref(&auth, None, 42, &secret, &sess);
    let ref2 = build_test_high_water_ref(&auth, None, 42, &secret, &sess);

    assert_eq!(ref1, ref2);
    assert_eq!(ref1.len(), 77);
}

#[test]
fn hmac_high_water_ref_differs() {
    let auth = [0x01u8; 16];
    let sess = [0x02u8; 16];
    let secret = [0x03u8; 32];

    let ref1 = build_test_high_water_ref(&auth, None, 42, &secret, &sess);
    let ref2 = build_test_high_water_ref(&auth, None, 43, &secret, &sess);

    assert_ne!(ref1, ref2);
}

// ── Full lifecycle ───────────────────────────────────────────────────────

#[tokio::test]
async fn full_lifecycle_open_read_complete_live_poll_close() {
    let (db_path, store) = fresh_file_db("full_lifecycle");
    let read_conn = open_read_conn(&db_path);

    insert_aggregate_stream(&read_conn, 1, &AGG_ID);
    insert_event(&read_conn, 1, &[0x01; 16], 1, &AGG_ID, b"ev1", 1000);

    // 1. Open session
    let (session, page) = store
        .open_session(PRINCIPAL, 1, &AUTH_ID, 0, 1, &AGG_ID, &SECRET)
        .await
        .unwrap();
    assert_eq!(session.state, ReplayState::CatchingUp);
    assert_eq!(page.len(), 1);

    // 2. Read page
    let page2 = store
        .read_page(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, 100)
        .await
        .unwrap();
    assert!(page2.is_empty());

    // 3. Complete catch-up
    let session = store
        .complete_catch_up(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0, b"proof")
        .await
        .unwrap();
    assert_eq!(session.state, ReplayState::CatchUpComplete);

    // 4. Activate live
    let session = store
        .continue_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();
    assert_eq!(session.state, ReplayState::Live);

    // 5. Insert new event and poll
    insert_event(&read_conn, 2, &[0x02; 16], 1, &AGG_ID, b"ev2", 2000);
    let live = store
        .poll_live(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].global_position, 2);

    // 6. Close
    store
        .close_session(&session.session_id, PRINCIPAL, 1, &AUTH_ID, 0)
        .await
        .unwrap();

    // Verify closed
    let state: String = read_conn
        .query_row(
            "SELECT state FROM _replay_subscriptions WHERE session_id = ?1",
            params![session.session_id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "closed");

    cleanup_db(&db_path);
}
