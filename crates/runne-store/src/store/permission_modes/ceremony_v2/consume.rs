use runne_application::permission_modes::{
    PermissionMode, SetPermissionModeCommand, VerifiedNativeModeConfirmationV2,
};
use rusqlite::{Transaction, params};

use super::super::{challenge, identity, managed_identity, model::*};
use super::{digest, issue, persistence};

#[allow(clippy::too_many_arguments)]
pub(in crate::store::permission_modes) fn consume_v2(
    tx: &Transaction<'_>,
    command: &SetPermissionModeCommand,
    confirmation: VerifiedNativeModeConfirmationV2,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
    current_identity: &managed_identity::ClosedRulesManagedIdentityV2,
    store: identity::StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
    now: i64,
) -> Result<bool, PermissionModeStoreError> {
    let request = NativeModeConfirmationRequestV2 {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        scope: command.scope.clone(),
        expected_authorization_revision: command.expected_authorization_revision,
        requested_mode: command.requested_mode,
        preset_version: command.preset_version,
        expires_at_unix_ms: command.expires_at_unix_ms,
    };
    let digest_id = confirmation.proof_identifier();
    let row = persistence::find_by_digest(tx, digest_id)?
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    let challenge_id = persistence::fixed::<16>(&row.challenge_id)?;
    let persisted_identity = managed_identity::persistence::load_challenge(tx, &challenge_id)?;
    let persisted_binding = persisted_identity
        .challenge_binding
        .ok_or(PermissionModeStoreError::CorruptData)?;
    if !issue::row_matches_request(&row, &request)
        || row.digest_version != 2
        || row.state != 1
        || row.confirmation_phase != 1
        || row.challenge_digest != digest_id
        || row.request_digest != digest_id
        || row.proof_identifier.is_some()
        || row.consumed_at.is_some()
        || row.public_request_digest.as_slice() != request.public_request_digest().as_bytes()
        || row.challenge_id.len() != 16
        || row.nonce.len() != 32
        || row.expires_at <= now
        || row.issued_at <= 0
        || row.issued_at > now
        || row
            .expires_at
            .checked_sub(row.issued_at)
            .is_none_or(|ttl| ttl <= 0 || ttl > challenge::CHALLENGE_TTL_MS)
        || row.mode_expires_at.is_some_and(|expiry| expiry <= now)
        || row.warning_version != i64::from(challenge::NATIVE_WARNING_VERSION)
        || row.project_id.as_slice() != workspace.project_id
        || workspace.project_version != persisted_identity.project_version
        || current_identity.project_version != workspace.project_version
        || !managed_identity::validation::same_rules(current_identity, &persisted_identity)
        || persisted_identity.canonical_digest != command.managed_policy_digest
        || row.challenge_digest != persisted_binding.envelope_digest
        || row.challenge_digest != digest_id
        || row.workspace_version != i64::try_from(workspace.workspace_version).unwrap_or(-1)
        || row.store_authority_id.as_slice() != store.authority_id
        || row.store_lineage_id != store.lineage_id.to_string()
        || row.managed_epoch != i64::try_from(managed.instance_epoch).unwrap_or(-1)
        || row.managed_revision != i64::try_from(managed.revision).unwrap_or(-1)
        || row.managed_status != identity::trust_status_tag(managed.status)
        || row.managed_deny_mask != i64::from(managed.deny_mask)
        || row.managed_digest.as_slice() != managed.digest.as_bytes()
        || row.launch_authority_id.as_slice() != launch.launch_authority_id()
        || row.desktop_host_instance_id.as_slice() != launch.desktop_host_instance_id()
        || row.daemon_instance_id.as_slice() != launch.daemon_instance_id()
        || row.launch_generation != i64::try_from(launch.launch_generation()).unwrap_or(-1)
        || row.native_key_epoch != i64::try_from(launch.key_epoch()).unwrap_or(-1)
        || row
            .protected_session_id
            .as_deref()
            .is_none_or(|session| !valid_session_id(session))
    {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let current_session = launch
        .protected_session_id()
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    if row.protected_session_id.as_deref() != Some(current_session.as_slice()) {
        let changed = tx
            .execute(
                "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=3
                 WHERE challenge_id=?1 AND state=1 AND confirmation_phase=1",
                params![row.challenge_id.as_slice()],
            )
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        if changed != 1 {
            return Err(PermissionModeStoreError::ReauthenticationUnavailable);
        }
        return Ok(false);
    }
    let nonce: [u8; 32] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let expected = digest::issued_digest(
        &request,
        workspace,
        managed,
        store,
        launch,
        &challenge_id,
        &nonce,
        row.issued_at,
        row.expires_at,
        challenge::NATIVE_WARNING_VERSION,
    )?;
    if expected != persisted_binding.legacy_issued_digest {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let issued = issue::issued_from_row(tx, &request, &row)?;
    if confirmation.binding_digest() != issued.binding().digest() {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    if command.requested_mode == PermissionMode::FullAccess {
        if command.challenge_binding_digest != Some(digest_id)
            || command
                .verified_native_challenge
                .map(|proof| proof.proof_identifier())
                != Some(digest_id)
        {
            return Err(
                runne_application::permission_modes::PermissionModeError::ReauthenticationRequired
                    .into(),
            );
        }
    } else if command.challenge_binding_digest.is_some()
        || command.challenge_expires_at_unix_ms.is_some()
        || command.verified_native_challenge.is_some()
    {
        return Err(runne_application::permission_modes::PermissionModeError::UnexpectedReauthenticationProof.into());
    }
    let changed = tx
        .execute(
            "UPDATE permission_mode_native_challenges SET state=2,proof_identifier=?1,
           consumed_at_unix_ms=?2,confirmation_phase=2
         WHERE challenge_id=?3 AND state=1 AND confirmation_phase=1 AND expires_at_unix_ms>?2",
            params![
                digest_id.as_bytes().as_slice(),
                now,
                challenge_id.as_slice()
            ],
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if changed != 1 {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    Ok(true)
}

fn valid_session_id(session: &[u8]) -> bool {
    let Ok(session) = <&[u8; 16]>::try_from(session) else {
        return false;
    };
    runne_domain::id::validate_uuid_v7_bytes(session).is_ok()
}
