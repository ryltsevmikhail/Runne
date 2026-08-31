use sha2::{Digest as _, Sha256};

use super::{
    ProviderCredentialProviderV2, ProviderCredentialVerificationKindV2, VerifyProviderCredential,
};
use crate::ProviderCredentialCommandContext;

const VERIFY_ACTION_DOMAIN: &[u8] = b"runne/provider-credential/verify-action/v1\0";
const VERIFY_COMMAND_DOMAIN: &[u8] = b"runne/provider-credential/verify-command/v1\0";

/// Canonical protected-envelope bindings for one V2 verification request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCredentialVerifyIntentBinding {
    action_provider_revision: [u8; 32],
    command_identity: [u8; 32],
}

impl ProviderCredentialVerifyIntentBinding {
    /// Derives exact non-secret bindings checked before a verification lease.
    #[must_use]
    pub fn new(
        command: &VerifyProviderCredential,
        context: &ProviderCredentialCommandContext,
    ) -> Self {
        Self {
            action_provider_revision: action_binding(command),
            command_identity: command_binding(command, context),
        }
    }

    /// Returns the action/provider/revision/kind envelope digest.
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

fn action_binding(command: &VerifyProviderCredential) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VERIFY_ACTION_DOMAIN);
    hasher.update([provider_byte(command.provider())]);
    hasher.update(command.expected_lifecycle_revision().to_be_bytes());
    hasher.update([kind_byte(command.verification_kind())]);
    hasher.finalize().into()
}

fn command_binding(
    command: &VerifyProviderCredential,
    context: &ProviderCredentialCommandContext,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VERIFY_COMMAND_DOMAIN);
    push(&mut hasher, command.command_identity().as_bytes());
    push(&mut hasher, command.native_intent_id().as_bytes());
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

const fn provider_byte(provider: ProviderCredentialProviderV2) -> u8 {
    match provider {
        ProviderCredentialProviderV2::OpenAi => 1,
        ProviderCredentialProviderV2::DeepSeek => 2,
    }
}

const fn kind_byte(kind: ProviderCredentialVerificationKindV2) -> u8 {
    match kind {
        ProviderCredentialVerificationKindV2::Local => 1,
        ProviderCredentialVerificationKindV2::Remote => 2,
    }
}
