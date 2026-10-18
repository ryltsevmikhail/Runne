use runne_application::project_trust::admin::{
    AdminError, CurrentPolicyAdmin, ManagedPolicyCommandState, ReservedManagedPolicyCommandV1,
    VerifiedManagedPolicyConsentV1,
};
use rusqlite::{Connection, params};

use super::{
    command_rows::{command_matches, load_command},
    identity::AdminIdentity,
    model::{
        COMMAND_CANCELLED, COMMAND_COMMITTED, COMMAND_EXPIRED, COMMAND_INVALIDATED,
        COMMAND_PENDING, ROLE_ACTIVE, now_unix_ms, query_role,
    },
    persistence::transact,
    receipts::load_receipt,
    validation,
};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn commit(
    store: &ProjectTrustStore,
    current: &CurrentPolicyAdmin<'_>,
    command: &ReservedManagedPolicyCommandV1,
    consent: &VerifiedManagedPolicyConsentV1,
) -> Result<ManagedPolicyCommandState, AdminError> {
    let identity = AdminIdentity::from_current(current);
    transact(store, |transaction| {
        let row = load_command(transaction, command.command_id())?.ok_or(AdminError::Rejected)?;
        if !command_matches(&row, command, &identity) {
            return Err(AdminError::Conflict);
        }
        match row.state {
            COMMAND_COMMITTED => {
                return Ok(ManagedPolicyCommandState::Committed(
                    load_receipt(
                        transaction,
                        command.command_id(),
                        &identity,
                        Some(&row.digest),
                    )?
                    .ok_or(AdminError::Unavailable)?,
                ));
            }
            COMMAND_CANCELLED => return Ok(ManagedPolicyCommandState::Cancelled),
            COMMAND_EXPIRED => return Ok(ManagedPolicyCommandState::Expired),
            COMMAND_INVALIDATED => return Ok(ManagedPolicyCommandState::Invalidated),
            COMMAND_PENDING => {}
            _ => return Err(AdminError::Unavailable),
        }
        let now = now_unix_ms()?;
        if now >= current.binding().session_expires_at_unix_ms() || now >= row.expires {
            set_terminal(transaction, command.command_id(), COMMAND_EXPIRED)?;
            return Ok(ManagedPolicyCommandState::Expired);
        }
        let current_binding =
            runne_application::project_trust::admin::policy_admin_session_binding_digest(
                current.binding(),
            );
        let role = query_role(transaction)?;
        let active_generation = role.and_then(|(status, generation)| {
            (status == ROLE_ACTIVE)
                .then(|| u64::try_from(generation).ok())
                .flatten()
        });
        if row.launch != current_binding || active_generation != Some(command.admin_generation()) {
            set_terminal(transaction, command.command_id(), COMMAND_INVALIDATED)?;
            return Ok(ManagedPolicyCommandState::Invalidated);
        }
        validation::validate_reserved_context(current, command, now)?;
        verify_consent(command, consent, now)?;
        let (registered, generation) = validation::validate_current_role(
            transaction,
            current,
            Some(command.admin_generation()),
        )?;
        if registered != identity || generation != command.admin_generation() {
            return Err(AdminError::Rejected);
        }
        let snapshot = validation::load_explicit_snapshot(transaction, store, command.project())?;
        if let Err(error) = validation::validate_command_snapshot(snapshot, command.request()) {
            if matches!(error, AdminError::Stale | AdminError::Conflict) {
                set_terminal(transaction, command.command_id(), COMMAND_INVALIDATED)?;
                return Ok(ManagedPolicyCommandState::Invalidated);
            }
            return Err(error);
        }
        let next_revision = snapshot
            .record
            .revision
            .checked_add(1)
            .ok_or(AdminError::Unavailable)?;
        write_rules(transaction, command)?;
        let changed = transaction
            .execute(
                "UPDATE project_trust SET revision=?2, updated_at=strftime('%s','now')
             WHERE project_id=?1 AND revision=?3 AND status=?4 AND managed_deny_mask=?5",
                params![
                    command.project().as_bytes().as_slice(),
                    i64::try_from(next_revision).map_err(|_| AdminError::Unavailable)?,
                    i64::try_from(snapshot.record.revision).map_err(|_| AdminError::Unavailable)?,
                    super::super::persistence::status_to_int(snapshot.record.status),
                    i64::from(snapshot.record.managed_deny_mask)
                ],
            )
            .map_err(|_| AdminError::Unavailable)?;
        if changed != 1 {
            return Err(AdminError::Stale);
        }
        let terminal = transaction
            .execute(
                "UPDATE managed_policy_admin_commands SET state=?2
             WHERE command_id=?1 AND state=?3",
                params![
                    command.command_id().as_slice(),
                    COMMAND_COMMITTED,
                    COMMAND_PENDING
                ],
            )
            .map_err(|_| AdminError::Unavailable)?;
        if terminal != 1 {
            return Err(AdminError::Conflict);
        }
        insert_receipt(transaction, command, &identity, next_revision, now)?;
        transaction
            .execute(
                "UPDATE managed_policy_admin_commands SET state=5
             WHERE state=1 AND command_id<>?1",
                params![command.command_id().as_slice()],
            )
            .map_err(|_| AdminError::Unavailable)?;
        load_receipt(
            transaction,
            command.command_id(),
            &identity,
            Some(command.semantic_digest()),
        )?
        .map(ManagedPolicyCommandState::Committed)
        .ok_or(AdminError::Unavailable)
    })
}

fn set_terminal(
    connection: &Connection,
    command_id: &[u8; 16],
    state: i64,
) -> Result<(), AdminError> {
    let changed = connection
        .execute(
            "UPDATE managed_policy_admin_commands SET state=?2 WHERE command_id=?1 AND state=?3",
            params![command_id.as_slice(), state, COMMAND_PENDING],
        )
        .map_err(|_| AdminError::Unavailable)?;
    if changed != 1 {
        return Err(AdminError::Conflict);
    }
    Ok(())
}

fn verify_consent(
    command: &ReservedManagedPolicyCommandV1,
    consent: &VerifiedManagedPolicyConsentV1,
    now: i64,
) -> Result<(), AdminError> {
    if consent.command_id() != command.command_id()
        || consent.command_digest() != command.semantic_digest()
        || consent.challenge_id() != command.challenge_id()
        || consent.challenge_nonce() != command.challenge_nonce()
        || consent.admin_generation() != command.admin_generation()
        || consent.launch_binding_digest() != command.launch_binding_digest()
        || consent.verified_at_unix_ms() < command.issued_at_unix_ms()
        || consent.verified_at_unix_ms() >= command.expires_at_unix_ms()
        || consent.verified_at_unix_ms() > now
    {
        return Err(AdminError::Rejected);
    }
    Ok(())
}

fn write_rules(
    connection: &Connection,
    command: &ReservedManagedPolicyCommandV1,
) -> Result<(), AdminError> {
    let values = command
        .rules()
        .decisions()
        .map(|rule| i64::from(rule.code()));
    let changed = connection
        .execute(
            "UPDATE managed_effect_policies
         SET fs_read=?2, fs_create=?3, fs_write=?4, fs_delete=?5,
             process_start=?6, network_use=?7
         WHERE project_id=?1 AND policy_version=1",
            params![
                command.project().as_bytes().as_slice(),
                values[0],
                values[1],
                values[2],
                values[3],
                values[4],
                values[5]
            ],
        )
        .map_err(|_| AdminError::Unavailable)?;
    if changed != 1 {
        return Err(AdminError::Stale);
    }
    Ok(())
}

fn insert_receipt(
    connection: &Connection,
    command: &ReservedManagedPolicyCommandV1,
    identity: &AdminIdentity,
    revision: u64,
    now: i64,
) -> Result<(), AdminError> {
    connection
        .execute(
            "INSERT INTO managed_policy_admin_receipts
         (command_id, idempotency_key, stable_subject_digest, authority_id, lineage_id,
          project_id, instance_epoch, prior_revision, revision, old_rules_digest,
          new_rules_digest, command_digest, committed_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                command.command_id().as_slice(),
                command.idempotency_key(),
                identity.stable_digest.as_slice(),
                identity.authority_id.as_slice(),
                identity.lineage_id.as_slice(),
                command.project().as_bytes().as_slice(),
                i64::try_from(command.expected().instance_epoch)
                    .map_err(|_| AdminError::Unavailable)?,
                i64::try_from(command.expected().revision).map_err(|_| AdminError::Unavailable)?,
                i64::try_from(revision).map_err(|_| AdminError::Unavailable)?,
                command.old_rules_digest().as_slice(),
                command.new_rules_digest().as_slice(),
                command.semantic_digest().as_slice(),
                now
            ],
        )
        .map_err(|_| AdminError::Conflict)?;
    Ok(())
}
