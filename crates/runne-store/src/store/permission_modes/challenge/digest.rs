use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

use super::super::identity::{OwnedWorkspace, StoreIdentity};
use super::super::model::{ManagedSnapshot, ProtectedNativeLaunchContext};
use super::super::{identity, model::FullAccessChallengeRequest};

const REQUEST_DOMAIN: &[u8] = b"runne:d21:permission-mode:challenge-request:v1\0";
const ISSUED_DOMAIN: &[u8] = b"runne:d21:permission-mode:issued-challenge:v1\0";

pub(super) fn challenge_request_digest(
    request: &FullAccessChallengeRequest,
    workspace: OwnedWorkspace,
    managed: ManagedSnapshot,
    store: StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(REQUEST_DOMAIN);
    hash.update(request.command_id.as_bytes());
    hash.update(request.idempotency_key.as_str().as_bytes());
    hash.update(request.scope.runtime_authority_id.0.as_bytes());
    hash.update(request.scope.principal_id.as_str().as_bytes());
    hash.update(request.scope.workspace_id.as_bytes());
    hash.update(request.expected_authorization_revision.to_be_bytes());
    hash.update(request.mode_expires_at_unix_ms.unwrap_or(0).to_be_bytes());
    hash.update(workspace.project_id);
    hash.update(workspace.project_version.to_be_bytes());
    hash.update(workspace.workspace_version.to_be_bytes());
    hash.update(managed.project_id.as_bytes());
    hash.update(managed.instance_epoch.to_be_bytes());
    hash.update(managed.revision.to_be_bytes());
    hash.update(identity::trust_status_tag(managed.status).to_be_bytes());
    hash.update(managed.deny_mask.to_be_bytes());
    hash.update(managed.digest.as_bytes());
    hash.update(store.authority_id);
    hash.update(store.lineage_id.to_string().as_bytes());
    hash.update(launch.launch_authority_id());
    hash.update(launch.desktop_host_instance_id());
    hash.update(launch.daemon_instance_id());
    hash.update(launch.launch_generation().to_be_bytes());
    hash.update(launch.key_epoch().to_be_bytes());
    hash.update(super::NATIVE_WARNING_VERSION.to_be_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}

pub(super) fn issued_challenge_digest(
    challenge_id: &[u8; 16],
    nonce: &[u8; 32],
    request_digest: IntegrityDigest,
    issued_at: i64,
    expires_at: i64,
) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(ISSUED_DOMAIN);
    hash.update(challenge_id);
    hash.update(nonce);
    hash.update(request_digest.as_bytes());
    hash.update(issued_at.to_be_bytes());
    hash.update(expires_at.to_be_bytes());
    hash.update(super::NATIVE_WARNING_VERSION.to_be_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}

#[allow(dead_code)]
fn _stable_mode_tag(mode: runne_application::permission_modes::PermissionMode) -> i64 {
    identity::mode_tag(mode)
}
