use super::super::*;
use super::support::{insert_v66_challenge, open_v66, seed_selection_and_receipt};

#[test]
fn v67_invalidates_pending_and_preserves_consumed_and_receipt_bytes() {
    let connection = open_v66();
    let pending = insert_v66_challenge(&connection, 0x51, 1);
    let consumed = insert_v66_challenge(&connection, 0x61, 2);
    let receipt_id = [0x75_u8; 16];
    seed_selection_and_receipt(&connection, &receipt_id);
    let before: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            "SELECT command_id,history_projection,authorization_revision,managed_policy_digest
             FROM permission_mode_command_receipts WHERE command_id=?1",
            [receipt_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();

    apply_migrations_internal(&connection, 67).unwrap();

    let phase: (i64, i64, i64) = connection
        .query_row(
            "SELECT state,confirmation_phase,digest_version FROM permission_mode_native_challenges
             WHERE challenge_id=?1",
            [pending.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(phase, (3, 3, 2));
    let after_consumed: (i64, i64, Vec<u8>, Option<i64>) = connection
        .query_row(
            "SELECT state,confirmation_phase,proof_identifier,consumed_at_unix_ms
             FROM permission_mode_native_challenges WHERE challenge_id=?1",
            [consumed.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(after_consumed, (2, 2, vec![0x6b; 32], Some(120)));
    let after: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            "SELECT command_id,history_projection,authorization_revision,managed_policy_digest
             FROM permission_mode_command_receipts WHERE command_id=?1",
            [receipt_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(schema_marker(&connection), 67);
}
