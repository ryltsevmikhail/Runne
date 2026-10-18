use super::super::*;

pub(super) const CHALLENGE_IDENTITY: &str = "permission_mode_native_challenge_managed_identity";
pub(super) const RECEIPT_IDENTITY: &str = "permission_mode_command_receipt_managed_identity";

pub(super) fn open_v66() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 66).unwrap();
    assert!(v66_matches(&connection, 66).unwrap());
    connection
}

pub(super) fn insert_v66_challenge(connection: &Connection, suffix: u8, state: i64) -> [u8; 16] {
    let challenge = [suffix; 16];
    let digest = [suffix.wrapping_add(10); 32];
    let command = [suffix.wrapping_add(20); 16];
    let proof = (state == 2).then_some(digest.as_slice());
    let consumed = (state == 2).then_some(120_i64);
    let phase = if state == 1 { 1_i64 } else { 2_i64 };
    connection
        .execute(
            "INSERT INTO permission_mode_native_challenges (
               challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
               runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,
               idempotency_key,store_authority_id,store_lineage_id,expected_authorization_revision,
               preset_version,managed_policy_instance_epoch,managed_policy_revision,
               managed_policy_status,managed_deny_mask,managed_policy_digest,mode_expires_at_unix_ms,
               launch_authority_id,desktop_host_instance_id,daemon_instance_id,launch_generation,
               native_key_epoch,protected_session_id,native_warning_version,issued_at_unix_ms,
               expires_at_unix_ms,state,proof_identifier,consumed_at_unix_ms,requested_mode,
               digest_version,public_request_digest,confirmation_phase
             ) VALUES (?1,?2,?3,?4,?5,'authority','principal',?6,?7,1,?8,?9,
               '00000000-0000-0000-0000-000000000000',0,1,1,0,1,0,?10,NULL,
               ?11,?12,?13,1,1,?14,1,100,200,?15,?16,?17,3,2,?18,?19)",
            rusqlite::params![
                challenge.as_slice(),
                [suffix.wrapping_add(1); 32].as_slice(),
                digest.as_slice(),
                [suffix.wrapping_add(2); 32].as_slice(),
                command.as_slice(),
                [suffix.wrapping_add(3); 16].as_slice(),
                [suffix.wrapping_add(4); 16].as_slice(),
                format!("key-{suffix}"),
                [0x31_u8; 16].as_slice(),
                [suffix.wrapping_add(5); 32].as_slice(),
                [0x41_u8; 16].as_slice(),
                [0x42_u8; 16].as_slice(),
                [0x43_u8; 16].as_slice(),
                [0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, suffix],
                state,
                proof,
                consumed,
                [suffix.wrapping_add(6); 32].as_slice(),
                phase,
            ],
        )
        .unwrap();
    challenge
}

pub(super) fn seed_selection_and_receipt(connection: &Connection, command_id: &[u8; 16]) {
    connection
        .execute(
            "INSERT INTO permission_mode_selections (
               runtime_authority_id,principal_id,workspace_id,project_id,selected_mode,
               preset_version,authorization_revision,managed_policy_version,managed_policy_digest,
               expires_at_unix_ms,last_command_id,intent_digest,updated_at_unix_ms
             ) VALUES ('authority','principal',zeroblob(16),zeroblob(16),1,1,1,0,
               zeroblob(32),NULL,?1,zeroblob(32),1)",
            [command_id.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO permission_mode_command_receipts (
               command_id,runtime_authority_id,principal_id,workspace_id,project_id,idempotency_key,
               intent_digest,selected_mode,preset_version,authorization_revision,managed_policy_version,
               managed_policy_digest,expires_at_unix_ms,history_projection,committed_at_unix_ms
             ) VALUES (?1,'authority','principal',zeroblob(16),zeroblob(16),'receipt',
               zeroblob(32),1,1,1,0,zeroblob(32),NULL,x'010203',1)",
            [command_id.as_slice()],
        )
        .unwrap();
}
