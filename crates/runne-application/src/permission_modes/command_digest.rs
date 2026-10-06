//! Canonical mode-change command intent digest.

use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

use super::model::{PermissionMode, SetPermissionModeCommand};

/// Return an opaque mode intent fingerprint over frozen semantic fields.
pub(super) fn mode_intent_digest(command: &SetPermissionModeCommand) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:permission-mode-command:v1\0");
    put_bytes(&mut hash, command.scope.runtime_authority_id.0.as_bytes());
    put_bytes(&mut hash, command.scope.principal_id.as_str().as_bytes());
    hash.update(command.scope.workspace_id.as_bytes());
    hash.update(command.expected_authorization_revision.to_be_bytes());
    hash.update([mode_tag(command.requested_mode)]);
    hash.update(command.preset_version.as_u16().to_be_bytes());
    hash.update(command.managed_policy_version.to_be_bytes());
    hash.update(command.managed_policy_digest.as_bytes());
    put_option_i64(&mut hash, command.expires_at_unix_ms);
    put_option_digest(&mut hash, command.challenge_binding_digest);
    put_option_i64(&mut hash, command.challenge_expires_at_unix_ms);
    IntegrityDigest::from_bytes(hash.finalize().into())
}

fn mode_tag(mode: PermissionMode) -> u8 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}

fn put_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}

fn put_option_i64(hash: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
}

fn put_option_digest(hash: &mut Sha256, value: Option<IntegrityDigest>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.as_bytes());
        }
        None => hash.update([0]),
    }
}
