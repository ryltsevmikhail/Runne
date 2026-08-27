use sha2::{Digest as _, Sha256};

use super::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialProviderV2,
};
use crate::ProviderCredentialCommandContext;

const ACTION_BINDING_DOMAIN: &[u8] = b"runne/provider-credential/begin-action/v1\0";
const COMMAND_BINDING_DOMAIN: &[u8] = b"runne/provider-credential/begin-command/v1\0";

/// Canonical protected-envelope bindings for one V2 begin request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCredentialBeginIntentBinding {
    action_provider_revision: [u8; 32],
    command_identity: [u8; 32],
}

impl ProviderCredentialBeginIntentBinding {
    /// Derives the exact non-secret bindings checked by protected transport and daemon.
    #[must_use]
    pub fn new(
        command: &BeginProviderCredentialEnrollment,
        context: &ProviderCredentialCommandContext,
    ) -> Self {
        Self {
            action_provider_revision: action_binding(command),
            command_identity: command_binding(command, context),
        }
    }

    /// Returns the action/provider/revision envelope digest.
    #[must_use]
    pub const fn action_provider_revision_digest(&self) -> &[u8; 32] {
        &self.action_provider_revision
    }

    /// Returns the exact command and idempotency envelope digest.
    #[must_use]
    pub const fn command_identity_digest(&self) -> &[u8; 32] {
        &self.command_identity
    }
}

fn action_binding(command: &BeginProviderCredentialEnrollment) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACTION_BINDING_DOMAIN);
    hasher.update([action_byte(command.action())]);
    hasher.update([provider_byte(command.provider())]);
    hasher.update(command.expected_lifecycle_revision().to_be_bytes());
    hasher.finalize().into()
}

fn command_binding(
    command: &BeginProviderCredentialEnrollment,
    context: &ProviderCredentialCommandContext,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMAND_BINDING_DOMAIN);
    push(&mut hasher, command.command_identity().as_bytes());
    push(&mut hasher, command.idempotency_key().as_bytes());
    push(&mut hasher, context.command_id.as_bytes());
    push(&mut hasher, context.idempotency_key.as_str().as_bytes());
    hasher.finalize().into()
}

fn push(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded API field")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

const fn action_byte(action: ProviderCredentialEnrollmentActionV2) -> u8 {
    match action {
        ProviderCredentialEnrollmentActionV2::Pair => 1,
        ProviderCredentialEnrollmentActionV2::Revoke => 2,
        ProviderCredentialEnrollmentActionV2::MigrateLegacy => 3,
    }
}

const fn provider_byte(provider: ProviderCredentialProviderV2) -> u8 {
    match provider {
        ProviderCredentialProviderV2::OpenAi => 1,
        ProviderCredentialProviderV2::DeepSeek => 2,
    }
}
