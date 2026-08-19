use runne_domain::id::EventLogLineageId;
use runne_store::schema::{
    FirstActivationResumeState, LaunchAuthorityConsumptionError, apply_migrations,
    consume_protected_launch_authority, ensure_authority_id,
    ensure_exact_first_activation_identity, next_launch_generation,
    preflight_first_activation_resume, read_event_log_lineage_id,
    read_first_activation_preparation,
};
use rusqlite::Connection;

const LAUNCH_AUTHORITY_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 9,
];
const LINEAGE_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 8,
];
const PREPARATION_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 7,
];

#[test]
fn launch_authority_is_consumed_once_before_generation_allocation() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();

    consume_protected_launch_authority(&connection, &LAUNCH_AUTHORITY_ID).expect("first consume");
    assert_eq!(next_launch_generation(&connection).unwrap(), 1);
    assert_eq!(
        consume_protected_launch_authority(&connection, &LAUNCH_AUTHORITY_ID).unwrap_err(),
        LaunchAuthorityConsumptionError::AlreadyConsumed
    );
    assert_eq!(next_launch_generation(&connection).unwrap(), 2);

    let persisted: String = connection
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = ?1",
            [format!(
                "protected_launch_authority_v1:{}",
                uuid::Uuid::from_bytes(LAUNCH_AUTHORITY_ID)
            )],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted, "consumed");
}

#[test]
fn first_activation_identity_is_atomic_and_partial_pre_generation_state_is_resumable() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let lineage = EventLogLineageId::from_bytes(LINEAGE_ID);

    assert_eq!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            lineage,
            &PREPARATION_ID,
        )
        .unwrap(),
        FirstActivationResumeState::RecoverablePartial
    );

    ensure_authority_id(&connection, &LAUNCH_AUTHORITY_ID).unwrap();
    assert_eq!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            lineage,
            &PREPARATION_ID,
        )
        .unwrap(),
        FirstActivationResumeState::RecoverablePartial
    );

    ensure_exact_first_activation_identity(
        &connection,
        &LAUNCH_AUTHORITY_ID,
        lineage,
        &PREPARATION_ID,
    )
    .unwrap();
    assert_eq!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            lineage,
            &PREPARATION_ID,
        )
        .unwrap(),
        FirstActivationResumeState::RecoverablePrepared
    );
    consume_protected_launch_authority(&connection, &LAUNCH_AUTHORITY_ID).unwrap();
    next_launch_generation(&connection).unwrap();
    assert_eq!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            lineage,
            &PREPARATION_ID,
        )
        .unwrap(),
        FirstActivationResumeState::Prepared
    );
}

#[test]
fn conflicting_first_activation_identity_rolls_back_all_prepared_metadata() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let conflicting_authority = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
    ];
    ensure_authority_id(&connection, &conflicting_authority).unwrap();

    assert!(
        ensure_exact_first_activation_identity(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            EventLogLineageId::from_bytes(LINEAGE_ID),
            &PREPARATION_ID,
        )
        .is_err()
    );
    assert_eq!(read_event_log_lineage_id(&connection).unwrap(), None);
    assert_eq!(
        read_first_activation_preparation(&connection).unwrap(),
        None
    );
    assert!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            EventLogLineageId::from_bytes(LINEAGE_ID),
            &PREPARATION_ID,
        )
        .is_err()
    );
}

#[test]
fn consumed_or_generated_partial_first_activation_is_never_resumable() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    consume_protected_launch_authority(&connection, &LAUNCH_AUTHORITY_ID).unwrap();
    assert!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            EventLogLineageId::from_bytes(LINEAGE_ID),
            &PREPARATION_ID,
        )
        .is_err()
    );

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    next_launch_generation(&connection).unwrap();
    assert!(
        preflight_first_activation_resume(
            &connection,
            &LAUNCH_AUTHORITY_ID,
            EventLogLineageId::from_bytes(LINEAGE_ID),
            &PREPARATION_ID,
        )
        .is_err()
    );
}
