use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

use super::super::{identity, model::*};

const ISSUED_V2_DOMAIN: &[u8] = b"runne:d21:permission-mode:issued-confirmation:v2\0";

#[allow(clippy::too_many_arguments)]
pub(super) fn issued_digest(
    request: &NativeModeConfirmationRequestV2,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
    store: identity::StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
    challenge_id: &[u8; 16],
    nonce: &[u8; 32],
    issued_at: i64,
    expires_at: i64,
    warning_version: u16,
) -> Result<IntegrityDigest, PermissionModeStoreError> {
    let mut hash = Sha256::new();
    hash.update(ISSUED_V2_DOMAIN);
    hash.update(request.public_request_digest().as_bytes());
    put(&mut hash, request.scope.runtime_authority_id.0.as_bytes());
    put(&mut hash, request.scope.principal_id.as_str().as_bytes());
    put(&mut hash, request.idempotency_key.as_str().as_bytes());
    hash.update(request.scope.workspace_id.as_bytes());
    hash.update(request.command_id.as_bytes());
    hash.update(request.expected_authorization_revision.to_be_bytes());
    hash.update([identity::mode_tag(request.requested_mode) as u8]);
    hash.update(request.preset_version.as_u16().to_be_bytes());
    match request.expires_at_unix_ms {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
    hash.update(workspace.project_id);
    hash.update(workspace.workspace_version.to_be_bytes());
    hash.update(managed.project_id.as_bytes());
    hash.update(managed.instance_epoch.to_be_bytes());
    hash.update(managed.revision.to_be_bytes());
    hash.update(identity::trust_status_tag(managed.status).to_be_bytes());
    hash.update(managed.deny_mask.to_be_bytes());
    hash.update(managed.digest.as_bytes());
    hash.update(store.authority_id);
    put(&mut hash, store.lineage_id.to_string().as_bytes());
    hash.update(launch.launch_authority_id());
    hash.update(launch.desktop_host_instance_id());
    hash.update(launch.daemon_instance_id());
    hash.update(launch.launch_generation().to_be_bytes());
    hash.update(launch.key_epoch().to_be_bytes());
    hash.update(
        launch
            .protected_session_id()
            .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?,
    );
    hash.update(challenge_id);
    hash.update(nonce);
    hash.update(issued_at.to_be_bytes());
    hash.update(expires_at.to_be_bytes());
    hash.update(warning_version.to_be_bytes());
    Ok(IntegrityDigest::from_bytes(hash.finalize().into()))
}

fn put(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use runne_api::ApiPrincipalId;
    use runne_application::{
        permission_modes::{PermissionMode, PermissionScope, PresetVersion},
        ports::RuntimeAuthorityId,
        project_trust::{ProjectTrustProjectId, ProjectTrustStatus},
    };
    use runne_domain::id::{
        CommandId, EventLogLineageId, IdempotencyKey, IntegrityDigest, WorkspaceId,
    };

    use super::*;

    #[test]
    fn issued_confirmation_v2_digest_separates_split_variable_fields() {
        let base = request("ab", "c", PermissionMode::AskAlways, None);
        let split = request("a", "bc", PermissionMode::AskAlways, None);
        assert_ne!(issued(&base), issued(&split));

        let no_expiry = request("authority", "principal", PermissionMode::AskAlways, None);
        let explicit_zero = request("authority", "principal", PermissionMode::AskAlways, Some(0));
        assert_ne!(issued(&no_expiry), issued(&explicit_zero));

        let ask = request("authority", "principal", PermissionMode::AskAlways, None);
        let risk = request("authority", "principal", PermissionMode::RiskBased, None);
        assert_ne!(issued(&ask), issued(&risk));
    }

    fn request(
        authority: &str,
        principal: &str,
        requested_mode: PermissionMode,
        expires_at_unix_ms: Option<i64>,
    ) -> NativeModeConfirmationRequestV2 {
        NativeModeConfirmationRequestV2 {
            command_id: CommandId::from_bytes([1; 16]),
            idempotency_key: IdempotencyKey::new("permission-v2").unwrap(),
            scope: PermissionScope {
                runtime_authority_id: RuntimeAuthorityId(authority.into()),
                principal_id: ApiPrincipalId::new(principal).unwrap(),
                workspace_id: WorkspaceId::from_bytes([2; 16]),
            },
            expected_authorization_revision: 3,
            requested_mode,
            preset_version: PresetVersion::V1,
            expires_at_unix_ms,
        }
    }

    fn issued(request: &NativeModeConfirmationRequestV2) -> IntegrityDigest {
        let project_id = ProjectTrustProjectId::from_bytes([4; 16]);
        let workspace = identity::OwnedWorkspace {
            project_id: [4; 16],
            project_version: 1,
            workspace_version: 2,
        };
        let managed = ManagedSnapshot {
            project_id,
            instance_epoch: 1,
            revision: 0,
            status: ProjectTrustStatus::Managed,
            deny_mask: 0,
            digest: IntegrityDigest::from_bytes([5; 32]),
        };
        let store = identity::StoreIdentity {
            authority_id: [6; 16],
            lineage_id: EventLogLineageId::from_bytes([7; 16]),
        };
        let launch = ProtectedNativeLaunchContext::new([8; 16], [9; 16], [10; 16], 1, 1)
            .unwrap()
            .with_protected_session_id([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ])
            .unwrap();
        issued_digest(
            request, workspace, managed, store, &launch, &[11; 16], &[12; 32], 100, 200, 1,
        )
        .unwrap()
    }
}
