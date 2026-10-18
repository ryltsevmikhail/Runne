use super::model::ClosedRulesManagedIdentityV2;
use crate::store::permission_modes::{
    ceremony_v2::persistence::CeremonyRow,
    model::{NativeModeConfirmationRequestV2, PermissionModeStoreError},
};
use runne_application::permission_modes::NativeModeConfirmationBindingV2;

pub(in crate::store::permission_modes) fn native_binding(
    request: &NativeModeConfirmationRequestV2,
    row: &CeremonyRow,
    identity: &ClosedRulesManagedIdentityV2,
) -> Result<NativeModeConfirmationBindingV2, PermissionModeStoreError> {
    let envelope = identity
        .challenge_binding
        .ok_or(PermissionModeStoreError::CorruptData)?
        .envelope_digest;
    if row.challenge_digest != envelope
        || row.managed_revision != i64::try_from(identity.snapshot.record.revision).unwrap_or(-1)
        || row.managed_epoch != i64::try_from(identity.snapshot.record.instance_epoch).unwrap_or(-1)
        || row.managed_status != super::codec::status_tag(identity.snapshot.record.status)
        || row.managed_deny_mask != i64::from(identity.snapshot.record.managed_deny_mask)
        || row.project_id.as_slice() != identity.project_id
        || row.managed_digest.as_slice()
            != runne_application::permission_modes::managed_policy_semantics_digest(
                runne_application::project_trust::ProjectTrustProjectId::from_bytes(
                    identity.project_id,
                ),
                identity.snapshot.record,
            )
            .as_bytes()
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(NativeModeConfirmationBindingV2 {
        command_id: request.command_id,
        idempotency_key: request.idempotency_key.clone(),
        scope: request.scope.clone(),
        expected_authorization_revision: request.expected_authorization_revision,
        requested_mode: request.requested_mode,
        preset_version: request.preset_version,
        public_request_digest: request.public_request_digest(),
        managed_policy_version: u64::try_from(row.managed_revision)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        managed_policy_digest: identity.canonical_digest,
        challenge_binding_digest: envelope,
        protected_session_id: crate::store::permission_modes::ceremony_v2::persistence::fixed::<16>(
            row.protected_session_id
                .as_deref()
                .ok_or(PermissionModeStoreError::CorruptData)?,
        )?,
        expires_at_unix_ms: request.expires_at_unix_ms,
        challenge_expires_at_unix_ms: row.expires_at,
        native_warning_version: u16::try_from(row.warning_version)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
    })
}
