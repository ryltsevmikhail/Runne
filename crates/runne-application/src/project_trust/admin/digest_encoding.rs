use sha2::{Digest, Sha256};

use super::model::{AuthenticatedPolicyAdminSubject, PolicyAdminSessionBinding};
use super::{digest::ManagedPolicyCommandV1, digest::ReservedManagedPolicyCommandV1};

const MANAGED_VERSION: u32 = 1;
const SOURCE_POLICY_VERSION: u64 = 2;
const LOCAL_COMMAND_POLICY_VERSION: u64 = 1;

/// Canonical stable public intent digest, excluding session and Store-minted fields.
pub fn managed_policy_request_digest_v1(command: &ManagedPolicyCommandV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne.managed-policy-admin-request.v1\0");
    hash.update(command.command_id());
    frame(&mut hash, command.idempotency_key().as_bytes());
    hash.update(command.project().as_bytes());
    hash.update(command.expected().instance_epoch.to_be_bytes());
    hash.update(command.expected().revision.to_be_bytes());
    hash.update(command.old_rules_digest());
    hash.update(command.new_rules_digest());
    let rules = command.rules();
    hash.update(rules.version.to_be_bytes());
    for rule in rules.decisions() {
        hash.update([rule.tag()]);
    }
    hash.update(command.warning_version().to_be_bytes());
    hash.update(MANAGED_VERSION.to_be_bytes());
    hash.update(SOURCE_POLICY_VERSION.to_be_bytes());
    hash.update(LOCAL_COMMAND_POLICY_VERSION.to_be_bytes());
    hash.finalize().into()
}

/// Canonical digest for a command and the exact Store-issued consent ceremony.
pub fn managed_policy_command_digest_v1(command: &ReservedManagedPolicyCommandV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne.managed-policy-admin-command.v1\0");
    hash.update(command.request_digest());
    hash.update(command.admin_generation().to_be_bytes());
    hash.update(command.launch_binding_digest());
    hash.update(command.challenge_id());
    hash.update(command.challenge_nonce());
    hash.update(command.issued_at_unix_ms().to_be_bytes());
    hash.update(command.expires_at_unix_ms().to_be_bytes());
    hash.finalize().into()
}

/// Digest for all stable+ephemeral runtime and protected launch/session-key fields.
pub fn policy_admin_session_binding_digest(binding: &PolicyAdminSessionBinding) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne.policy-admin-current-session.v1\0");
    hash.update(binding.runtime().canonical_digest());
    hash.update(binding.protected_launch_id());
    hash.update(binding.desktop_generation_key());
    hash.update(binding.session_key_epoch().to_be_bytes());
    hash.update(binding.session_expires_at_unix_ms().to_be_bytes());
    hash.finalize().into()
}

/// Digest retaining authority, principal, lineage, profile, schema and capability identity.
pub fn policy_admin_stable_identity_digest(
    subject: &AuthenticatedPolicyAdminSubject<'_>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne.policy-admin-stable-identity.v1\0");
    frame(&mut hash, subject.authority_id());
    frame(&mut hash, subject.principal_id().as_bytes());
    frame(&mut hash, subject.lineage_id());
    frame(&mut hash, subject.profile_id().as_bytes());
    frame(&mut hash, subject.schema_hash());
    frame(&mut hash, subject.capability_digest());
    hash.finalize().into()
}

fn frame(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}
