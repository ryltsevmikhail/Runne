use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{TransactionBehavior, params};

use super::super::{challenge, clock, identity, managed_identity, model::*};
use super::{
    digest,
    persistence::{self, CeremonyRow},
};
use crate::store::StoreTransaction;

const MAX_PENDING: u32 = 16;

pub(in crate::store::permission_modes) fn begin(
    store: &StoreTransaction,
    request: NativeModeConfirmationRequestV2,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<PermissionModeCeremonyStatusV2, PermissionModeStoreError> {
    identity::check_scope_authority(store, &request.scope, authority.authenticated_principal)?;
    i64::try_from(request.expected_authorization_revision)
        .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?;
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let now = clock::unix_ms()?;
    if let Some(receipt) = super::super::command::readback_v2::lookup_v2_request(&tx, &request)? {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(PermissionModeCeremonyStatusV2::Committed(receipt));
    }
    if let Some(row) = persistence::find_existing(&tx, &request)? {
        let status = existing_status(&tx, &request, row, now, authority)?;
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(status);
    }
    if request
        .expires_at_unix_ms
        .is_some_and(|expiry| expiry <= now)
    {
        return Err(runne_application::permission_modes::PermissionModeError::Expired.into());
    }
    let launch = identity::native_launch_fields(authority)?;
    if launch.protected_session_id().is_none() {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let workspace = identity::owned_open_workspace(&tx, &request.scope)?;
    let managed = identity::managed_snapshot(authority, workspace.project_id)?;
    let closed_rules = managed_identity::lease::current(authority, workspace, managed)?;
    if challenge::persistence::current_revision(&tx, &request.scope)?
        != request.expected_authorization_revision
    {
        return Err(runne_application::permission_modes::PermissionModeError::StaleRevision.into());
    }
    let store_identity = identity::store_identity(&tx, &request.scope)?;
    let pending: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM permission_mode_native_challenges
         WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3
           AND state=1 AND expires_at_unix_ms>?4",
            params![
                request.scope.runtime_authority_id.0,
                request.scope.principal_id.as_str(),
                request.scope.workspace_id.as_bytes(),
                now
            ],
            |row| row.get(0),
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if u32::try_from(pending)
        .ok()
        .is_none_or(|count| count >= MAX_PENDING)
    {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let issued_at = now;
    let ttl_expiry = now
        .checked_add(challenge::CHALLENGE_TTL_MS)
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    let expires_at = request
        .expires_at_unix_ms
        .map_or(ttl_expiry, |mode| mode.min(ttl_expiry));
    if expires_at <= issued_at {
        return Err(runne_application::permission_modes::PermissionModeError::Expired.into());
    }
    let mut challenge_id = [0_u8; 16];
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut challenge_id);
    OsRng.fill_bytes(&mut nonce);
    if challenge_id.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let legacy_issued_digest = digest::issued_digest(
        &request,
        workspace,
        managed,
        store_identity,
        &launch,
        &challenge_id,
        &nonce,
        issued_at,
        expires_at,
        challenge::NATIVE_WARNING_VERSION,
    )?;
    if legacy_issued_digest
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let closed_rules =
        managed_identity::issue::bind_legacy_challenge(closed_rules, legacy_issued_digest);
    let envelope = closed_rules
        .challenge_binding
        .ok_or(PermissionModeStoreError::CorruptData)?
        .envelope_digest;
    persistence::insert(
        &tx,
        &request,
        workspace,
        managed,
        store_identity,
        &launch,
        &challenge_id,
        &nonce,
        envelope,
        issued_at,
        expires_at,
        challenge::NATIVE_WARNING_VERSION,
    )?;
    managed_identity::persistence::insert_challenge(&tx, &challenge_id, &closed_rules)?;
    let row = persistence::find_by_command_id(&tx, request.command_id)?
        .ok_or(PermissionModeStoreError::CorruptData)?;
    let issued = issued_from_row(&tx, &request, &row)?;
    tx.commit()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(PermissionModeCeremonyStatusV2::Pending(issued))
}

fn existing_status(
    tx: &rusqlite::Transaction<'_>,
    request: &NativeModeConfirmationRequestV2,
    row: CeremonyRow,
    now: i64,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<PermissionModeCeremonyStatusV2, PermissionModeStoreError> {
    if !row_matches_request(&row, request) {
        return Err(
            runne_application::permission_modes::PermissionModeError::IdempotencyConflict.into(),
        );
    }
    if row.digest_version != 2 {
        return if row.state == 3 && row.confirmation_phase == 3 {
            Ok(PermissionModeCeremonyStatusV2::Invalidated)
        } else {
            Err(
                runne_application::permission_modes::PermissionModeError::IdempotencyConflict
                    .into(),
            )
        };
    }
    match (row.state, row.confirmation_phase) {
        (2, 2) => super::super::command::readback_v2::lookup_by_scope_and_id(
            tx,
            request.command_id,
            &request.scope,
        )?
        .map(PermissionModeCeremonyStatusV2::Committed)
        .ok_or(PermissionModeStoreError::CorruptData),
        (3, 3) => Ok(PermissionModeCeremonyStatusV2::Invalidated),
        (3, 4) => Ok(PermissionModeCeremonyStatusV2::Cancelled),
        (3, 5) => Ok(PermissionModeCeremonyStatusV2::Expired),
        (1, 1)
            if row.expires_at <= now || row.mode_expires_at.is_some_and(|expiry| expiry <= now) =>
        {
            expire_pending(tx, &row)?;
            Ok(PermissionModeCeremonyStatusV2::Expired)
        }
        (1, 1) => {
            let launch = identity::native_launch_fields(authority)?;
            let current_session = launch
                .protected_session_id()
                .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
            if !super::lifecycle::launch_matches_row(&launch, &row)
                || row.protected_session_id.as_deref() != Some(current_session.as_slice())
            {
                invalidate_pending(tx, &row)?;
                return Ok(PermissionModeCeremonyStatusV2::Invalidated);
            }
            Ok(PermissionModeCeremonyStatusV2::Pending(issued_from_row(
                tx, request, &row,
            )?))
        }
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}

fn invalidate_pending(
    tx: &rusqlite::Transaction<'_>,
    row: &CeremonyRow,
) -> Result<(), PermissionModeStoreError> {
    let changed = tx
        .execute(
            "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=3
             WHERE challenge_id=?1 AND state=1 AND confirmation_phase=1",
            rusqlite::params![row.challenge_id.as_slice()],
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PermissionModeStoreError::CorruptData)
    }
}

pub(super) fn issued_from_row(
    tx: &rusqlite::Transaction<'_>,
    request: &NativeModeConfirmationRequestV2,
    row: &CeremonyRow,
) -> Result<IssuedNativeModeConfirmationV2, PermissionModeStoreError> {
    if row.digest_version != 2
        || row.state != 1
        || row.confirmation_phase != 1
        || row.public_request_digest.as_slice() != request.public_request_digest().as_bytes()
        || row.request_digest != row.challenge_digest
        || row.expires_at <= row.issued_at
        || row.warning_version != i64::from(challenge::NATIVE_WARNING_VERSION)
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let challenge_id = persistence::fixed::<16>(&row.challenge_id)?;
    let nonce = persistence::fixed::<32>(&row.nonce)?;
    let protected_session_id = persistence::fixed::<16>(
        row.protected_session_id
            .as_deref()
            .ok_or(PermissionModeStoreError::CorruptData)?,
    )?;
    runne_domain::id::validate_uuid_v7_bytes(&protected_session_id)
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let managed_identity = managed_identity::persistence::load_challenge(tx, &challenge_id)?;
    let binding = managed_identity::binding::native_binding(request, row, &managed_identity)?;
    Ok(IssuedNativeModeConfirmationV2::new(
        challenge_id,
        nonce,
        binding,
        managed_identity,
    ))
}

pub(super) fn row_matches_request(
    row: &CeremonyRow,
    request: &NativeModeConfirmationRequestV2,
) -> bool {
    row.command_id.as_slice() == request.command_id.as_bytes()
        && row.authority_id == request.scope.runtime_authority_id.0
        && row.principal_id == request.scope.principal_id.as_str()
        && row.workspace_id.as_slice() == request.scope.workspace_id.as_bytes()
        && row.idempotency_key == request.idempotency_key.as_str()
        && row.expected_revision
            == i64::try_from(request.expected_authorization_revision).unwrap_or(-1)
        && row.requested_mode == identity::mode_tag(request.requested_mode)
        && row.preset_version == i64::from(request.preset_version.as_u16())
        && row.mode_expires_at == request.expires_at_unix_ms
        && (row.digest_version != 2
            || row.public_request_digest.as_slice() == request.public_request_digest().as_bytes())
}

pub(super) fn expire_pending(
    tx: &rusqlite::Transaction<'_>,
    row: &CeremonyRow,
) -> Result<(), PermissionModeStoreError> {
    let changed = tx
        .execute(
            "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=5
         WHERE challenge_id=?1 AND state=1 AND confirmation_phase=1",
            params![row.challenge_id.as_slice()],
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if changed != 1 {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(())
}
