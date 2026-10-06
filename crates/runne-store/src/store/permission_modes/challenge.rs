use rand::RngCore;
use rand::rngs::OsRng;
use runne_domain::id::ProjectId;
use rusqlite::{TransactionBehavior, params};

use super::model::*;
use super::{clock, identity};
use crate::store::StoreTransaction;

pub(super) mod consume;
mod digest;
pub(super) mod persistence;

use digest::{challenge_request_digest, issued_challenge_digest};
use persistence::{current_revision, find_existing, insert_challenge, sql_integer};

pub(super) const NATIVE_WARNING_VERSION: u16 = 1;
pub(super) const CHALLENGE_TTL_MS: i64 = 60_000;
const MAX_PENDING_CHALLENGES_PER_SCOPE: u32 = 16;

#[allow(clippy::too_many_arguments)]
pub(super) fn issue(
    store: &StoreTransaction,
    request: FullAccessChallengeRequest,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<IssuedFullAccessChallenge, PermissionModeStoreError> {
    identity::check_scope_authority(store, &request.scope, authority.authenticated_principal)?;
    sql_integer(request.expected_authorization_revision)?;
    let launch = identity::native_launch_fields(authority)?;
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let now_unix_ms = clock::unix_ms()?;
    let expires_at = now_unix_ms
        .checked_add(CHALLENGE_TTL_MS)
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    if request
        .mode_expires_at_unix_ms
        .is_some_and(|expiry| expiry <= now_unix_ms)
    {
        return Err(PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::Expired,
        ));
    }
    let owned = identity::owned_open_workspace(&tx, &request.scope)?;
    let managed = identity::managed_snapshot(authority, owned.project_id)?;
    let current_revision = current_revision(&tx, &request.scope)?;
    if current_revision != request.expected_authorization_revision {
        return Err(PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::StaleRevision,
        ));
    }
    let db_identity = identity::store_identity(&tx, &request.scope)?;
    let context = IssuedFullAccessChallengeContext {
        command_id: request.command_id,
        idempotency_key: request.idempotency_key.clone(),
        scope: request.scope.clone(),
        expected_authorization_revision: request.expected_authorization_revision,
        project_id: ProjectId::from_bytes(owned.project_id),
        project_version: owned.project_version,
        workspace_version: owned.workspace_version,
        store_authority_id: db_identity.authority_id,
        store_lineage_id: db_identity.lineage_id,
        managed_instance_epoch: managed.instance_epoch,
        managed_policy_revision: managed.revision,
        managed_status: managed.status,
        managed_deny_mask: managed.deny_mask,
        managed_policy_digest: managed.digest,
        mode_expires_at_unix_ms: request.mode_expires_at_unix_ms,
        native_launch: launch,
    };
    let request_digest = challenge_request_digest(&request, owned, managed, db_identity, &launch);
    if let Some(existing) = find_existing(&tx, &request)? {
        if existing.request_digest != request_digest {
            return Err(PermissionModeStoreError::Command(
                runne_application::permission_modes::PermissionModeError::IdempotencyConflict,
            ));
        }
        if existing.state != 1 || existing.expires_at <= now_unix_ms {
            return Err(PermissionModeStoreError::Command(
                runne_application::permission_modes::PermissionModeError::Expired,
            ));
        }
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(existing.into_public(context));
    }
    let pending: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM permission_mode_native_challenges
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3
               AND state=1 AND expires_at_unix_ms>?4",
            params![
                request.scope.runtime_authority_id.0,
                request.scope.principal_id.as_str(),
                request.scope.workspace_id.as_bytes(),
                now_unix_ms,
            ],
            |row| row.get(0),
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if u32::try_from(pending)
        .ok()
        .is_none_or(|count| count >= MAX_PENDING_CHALLENGES_PER_SCOPE)
    {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let mut challenge_id = [0_u8; 16];
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut challenge_id);
    OsRng.fill_bytes(&mut nonce);
    if challenge_id.iter().all(|byte| *byte == 0) || nonce.iter().all(|byte| *byte == 0) {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    let challenge_binding_digest = issued_challenge_digest(
        &challenge_id,
        &nonce,
        request_digest,
        now_unix_ms,
        expires_at,
    );
    if challenge_binding_digest
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    insert_challenge(
        &tx,
        &request,
        owned,
        managed,
        db_identity,
        &launch,
        challenge_id,
        nonce,
        request_digest,
        challenge_binding_digest,
        now_unix_ms,
        expires_at,
    )?;
    tx.commit()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(IssuedFullAccessChallenge {
        challenge_id,
        nonce,
        challenge_binding_digest,
        expires_at_unix_ms: expires_at,
        native_warning_version: NATIVE_WARNING_VERSION,
        context,
    })
}

pub(super) struct IssuedRow {
    request_digest: runne_domain::id::IntegrityDigest,
    state: i64,
    expires_at: i64,
    challenge_id: [u8; 16],
    nonce: [u8; 32],
    challenge_digest: runne_domain::id::IntegrityDigest,
}

impl IssuedRow {
    pub(super) fn into_public(
        self,
        context: IssuedFullAccessChallengeContext,
    ) -> IssuedFullAccessChallenge {
        IssuedFullAccessChallenge {
            challenge_id: self.challenge_id,
            nonce: self.nonce,
            challenge_binding_digest: self.challenge_digest,
            expires_at_unix_ms: self.expires_at,
            native_warning_version: NATIVE_WARNING_VERSION,
            context,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct IssuedChallengeRow {
    pub(super) challenge_id: [u8; 16],
    pub(super) nonce: [u8; 32],
    pub(super) digest: runne_domain::id::IntegrityDigest,
    pub(super) request_digest: runne_domain::id::IntegrityDigest,
    pub(super) command_id: Vec<u8>,
    pub(super) runtime_authority_id: String,
    pub(super) principal_id: String,
    pub(super) workspace_id: Vec<u8>,
    pub(super) project_id: Vec<u8>,
    pub(super) workspace_version: i64,
    pub(super) idempotency_key: String,
    pub(super) store_authority_id: Vec<u8>,
    pub(super) store_lineage_id: String,
    pub(super) expected_revision: i64,
    pub(super) preset_version: i64,
    pub(super) managed_epoch: i64,
    pub(super) managed_revision: i64,
    pub(super) managed_status: i64,
    pub(super) managed_deny_mask: i64,
    pub(super) managed_digest: Vec<u8>,
    pub(super) mode_expires_at: Option<i64>,
    pub(super) launch_authority_id: Vec<u8>,
    pub(super) desktop_host_instance_id: Vec<u8>,
    pub(super) daemon_instance_id: Vec<u8>,
    pub(super) launch_generation: i64,
    pub(super) native_key_epoch: i64,
    pub(super) warning_version: i64,
    pub(super) issued_at: i64,
    pub(super) expires_at: i64,
    pub(super) state: i64,
    pub(super) proof_identifier: Option<Vec<u8>>,
    pub(super) consumed_at: Option<i64>,
}

pub(super) fn consume_for_change(
    tx: &rusqlite::Transaction<'_>,
    command: &runne_application::permission_modes::SetPermissionModeCommand,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
    store: identity::StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
    now: i64,
) -> Result<(), PermissionModeStoreError> {
    consume::consume(tx, command, workspace, managed, store, launch, now)
}
