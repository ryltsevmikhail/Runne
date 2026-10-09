use rand::RngCore;
use rusqlite::{Connection, params};

use runne_application::project_trust::admin::{
    AdminError, CurrentPolicyAdmin, ManagedPolicyCommandState, ManagedPolicyCommandV1,
    ReservedManagedPolicyCommandV1, policy_admin_session_binding_digest,
};

use super::{
    command_rows::{command_matches, find_command_id, load_command, public_intent_matches},
    identity::AdminIdentity,
    model::{now_unix_ms, query_role, *},
    persistence::transact,
    receipts::load_receipt,
    validation,
};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn reserve(
    store: &ProjectTrustStore,
    current: &CurrentPolicyAdmin<'_>,
    request: &ManagedPolicyCommandV1,
) -> Result<ManagedPolicyCommandState, AdminError> {
    let identity = AdminIdentity::from_current(current);
    transact(store, |transaction| {
        if let Some(existing_id) = find_command_id(transaction, request, &identity)? {
            if existing_id != *request.command_id() {
                return Err(AdminError::Conflict);
            }
            let row = load_command(transaction, &existing_id)?.ok_or(AdminError::Unavailable)?;
            if !public_intent_matches(&row, request, &identity) {
                return Err(AdminError::Conflict);
            }
            if row.state == COMMAND_COMMITTED {
                return Ok(ManagedPolicyCommandState::Committed(
                    load_receipt(transaction, &existing_id, &identity, Some(&row.digest))?
                        .ok_or(AdminError::Unavailable)?,
                ));
            }
            if row.state == COMMAND_CANCELLED {
                return Ok(ManagedPolicyCommandState::Cancelled);
            }
            if row.state == COMMAND_EXPIRED {
                return Ok(ManagedPolicyCommandState::Expired);
            }
            if row.state == COMMAND_INVALIDATED {
                return Ok(ManagedPolicyCommandState::Invalidated);
            }
            let now = now_unix_ms()?;
            if now >= current.binding().session_expires_at_unix_ms() || now >= row.expires {
                set_terminal(transaction, &existing_id, COMMAND_EXPIRED)?;
                return Ok(ManagedPolicyCommandState::Expired);
            }
            let current_binding = policy_admin_session_binding_digest(current.binding());
            let active_generation = query_role(transaction)?.and_then(|(status, generation)| {
                (status == ROLE_ACTIVE)
                    .then(|| u64::try_from(generation).ok())
                    .flatten()
            });
            if row.launch != current_binding
                || active_generation != Some(request.admin_generation())
            {
                set_terminal(transaction, &existing_id, COMMAND_INVALIDATED)?;
                return Ok(ManagedPolicyCommandState::Invalidated);
            }
            let snapshot =
                validation::load_explicit_snapshot(transaction, store, request.project())?;
            if let Err(error) = validation::validate_command_snapshot(snapshot, request) {
                if matches!(error, AdminError::Stale | AdminError::Conflict) {
                    set_terminal(transaction, &existing_id, COMMAND_INVALIDATED)?;
                    return Ok(ManagedPolicyCommandState::Invalidated);
                }
                return Err(error);
            }
            let reserved = request.issued_by_store(
                row.challenge,
                row.nonce,
                row.issued,
                row.expires,
                i64::MAX,
            )?;
            if !command_matches(&row, &reserved, &identity) {
                return Err(AdminError::Conflict);
            }
            return Ok(ManagedPolicyCommandState::Pending(reserved));
        }

        validation::validate_request_context(current, request)?;
        let now = now_unix_ms()?;
        if now >= current.binding().session_expires_at_unix_ms() {
            return Err(AdminError::Expired);
        }
        let (registered, generation) = validation::validate_current_role(
            transaction,
            current,
            Some(request.admin_generation()),
        )?;
        let snapshot = validation::load_explicit_snapshot(transaction, store, request.project())?;
        validation::validate_command_snapshot(snapshot, request)?;
        let expiry = now
            .saturating_add(120_000)
            .min(current.binding().session_expires_at_unix_ms());
        let (challenge_id, nonce) = fresh_challenge();
        let reserved = request.issued_by_store(
            challenge_id,
            nonce,
            now,
            expiry,
            current.binding().session_expires_at_unix_ms(),
        )?;
        insert_pending(transaction, &registered, generation, request, &reserved)?;
        Ok(ManagedPolicyCommandState::Pending(reserved))
    })
}

fn insert_pending(
    connection: &Connection,
    identity: &AdminIdentity,
    generation: u64,
    request: &ManagedPolicyCommandV1,
    command: &ReservedManagedPolicyCommandV1,
) -> Result<(), AdminError> {
    if generation != command.admin_generation() {
        return Err(AdminError::Rejected);
    }
    let rules = command
        .rules()
        .decisions()
        .map(|value| i64::from(value.code()));
    connection
        .execute(
            "INSERT INTO managed_policy_admin_commands
         (command_id, idempotency_key, stable_subject_digest, authority_id, lineage_id,
          project_id, project_epoch, expected_revision, old_rules_digest, new_rules_digest,
          managed_version, source_policy_version, local_command_policy_version,
          fs_read, fs_create, fs_write, fs_delete, process_start, network_use,
          admin_generation, launch_binding_digest, challenge_id, challenge_nonce,
          warning_version, issued_at_unix_ms, expires_at_unix_ms, request_digest,
          semantic_digest, state, reserved_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 2, 1, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, 1, ?22)",
            params![
                request.command_id().as_slice(),
                request.idempotency_key(),
                identity.stable_digest.as_slice(),
                identity.authority_id.as_slice(),
                identity.lineage_id.as_slice(),
                request.project().as_bytes().as_slice(),
                i64::try_from(request.expected().instance_epoch)
                    .map_err(|_| AdminError::Rejected)?,
                i64::try_from(request.expected().revision).map_err(|_| AdminError::Rejected)?,
                request.old_rules_digest().as_slice(),
                request.new_rules_digest().as_slice(),
                rules[0],
                rules[1],
                rules[2],
                rules[3],
                rules[4],
                rules[5],
                i64::try_from(generation).map_err(|_| AdminError::Rejected)?,
                command.launch_binding_digest().as_slice(),
                command.challenge_id().as_slice(),
                command.challenge_nonce().as_slice(),
                i64::from(command.warning_version()),
                command.issued_at_unix_ms(),
                command.expires_at_unix_ms(),
                command.request_digest().as_slice(),
                command.semantic_digest().as_slice()
            ],
        )
        .map_err(|_| AdminError::Conflict)?;
    Ok(())
}

fn set_terminal(
    connection: &Connection,
    command_id: &[u8; 16],
    state: i64,
) -> Result<(), AdminError> {
    let changed = connection
        .execute(
            "UPDATE managed_policy_admin_commands SET state=?2 WHERE command_id=?1 AND state=1",
            params![command_id.as_slice(), state],
        )
        .map_err(|_| AdminError::Unavailable)?;
    if changed != 1 {
        return Err(AdminError::Unavailable);
    }
    Ok(())
}

fn fresh_challenge() -> ([u8; 16], [u8; 32]) {
    let mut id = [0; 16];
    let mut nonce = [0; 32];
    loop {
        rand::rngs::OsRng.fill_bytes(&mut id);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        if id != [0; 16] && nonce != [0; 32] {
            return (id, nonce);
        }
    }
}
