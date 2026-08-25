use runne_domain::id::{CommandId, IdempotencyKey};
use serde::{Deserialize, Serialize};
use std::fmt;

mod ids;
mod operation;
mod snapshot;

pub use ids::ProviderCredentialOperationIdV2;
pub use operation::{
    ProviderCredentialOperationKindV2, ProviderCredentialOperationSnapshotV2,
    ProviderCredentialOperationStateV2,
};
pub use snapshot::{
    ProviderCredentialLastDispositionV2, ProviderCredentialPendingOperationV2,
    ProviderCredentialReadinessV2, ProviderCredentialSafeSnapshotV2, ProviderCredentialStateV2,
    ProviderCredentialVerificationStateV2,
};

/// Closed public enrollment actions. Cleanup and release migration stay internal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialEnrollmentActionV2 {
    Pair,
    Revoke,
    MigrateLegacy,
}

/// Closed provider identities accepted by protected enrollment V2.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderCredentialProviderV2 {
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "deepseek")]
    DeepSeek,
}

/// Explicit verification effect selected by a fresh native intent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCredentialVerificationKindV2 {
    Local,
    Remote,
}

/// Closed metadata-validation failures with no native or secret context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialValidationErrorV2 {
    InvalidRevision,
    InvalidCommandIdentity,
    InvalidIdempotencyKey,
    InvalidNativeIntent,
    InvalidSnapshot,
}

impl fmt::Display for ProviderCredentialValidationErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid provider credential enrollment metadata")
    }
}

impl std::error::Error for ProviderCredentialValidationErrorV2 {}

/// Metadata-only command accepted by protected V2 begin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", try_from = "BeginWire")]
pub struct BeginProviderCredentialEnrollment {
    action: ProviderCredentialEnrollmentActionV2,
    provider: ProviderCredentialProviderV2,
    expected_lifecycle_revision: u64,
    command_identity: String,
    idempotency_key: String,
    native_intent_id: String,
}

impl BeginProviderCredentialEnrollment {
    /// Constructs a validated metadata-only begin command.
    pub fn new(
        action: ProviderCredentialEnrollmentActionV2,
        provider: ProviderCredentialProviderV2,
        expected_lifecycle_revision: u64,
        command_identity: impl Into<String>,
        idempotency_key: impl Into<String>,
        native_intent_id: impl Into<String>,
    ) -> Result<Self, ProviderCredentialValidationErrorV2> {
        Self::try_from(BeginWire {
            action,
            provider,
            expected_lifecycle_revision,
            command_identity: command_identity.into(),
            idempotency_key: idempotency_key.into(),
            native_intent_id: native_intent_id.into(),
        })
    }

    pub const fn action(&self) -> ProviderCredentialEnrollmentActionV2 {
        self.action
    }
    pub const fn provider(&self) -> ProviderCredentialProviderV2 {
        self.provider
    }
    pub const fn expected_lifecycle_revision(&self) -> u64 {
        self.expected_lifecycle_revision
    }
    pub fn command_identity(&self) -> &str {
        &self.command_identity
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn native_intent_id(&self) -> &str {
        &self.native_intent_id
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BeginWire {
    action: ProviderCredentialEnrollmentActionV2,
    provider: ProviderCredentialProviderV2,
    expected_lifecycle_revision: u64,
    command_identity: String,
    idempotency_key: String,
    native_intent_id: String,
}

impl TryFrom<BeginWire> for BeginProviderCredentialEnrollment {
    type Error = ProviderCredentialValidationErrorV2;

    fn try_from(value: BeginWire) -> Result<Self, Self::Error> {
        if value.expected_lifecycle_revision == 0 {
            return Err(ProviderCredentialValidationErrorV2::InvalidRevision);
        }
        if !valid_command_identity(&value.command_identity) {
            return Err(ProviderCredentialValidationErrorV2::InvalidCommandIdentity);
        }
        if IdempotencyKey::new(value.idempotency_key.clone()).is_err() {
            return Err(ProviderCredentialValidationErrorV2::InvalidIdempotencyKey);
        }
        if !valid_opaque_id(&value.native_intent_id) {
            return Err(ProviderCredentialValidationErrorV2::InvalidNativeIntent);
        }
        Ok(Self {
            action: value.action,
            provider: value.provider,
            expected_lifecycle_revision: value.expected_lifecycle_revision,
            command_identity: value.command_identity,
            idempotency_key: value.idempotency_key,
            native_intent_id: value.native_intent_id,
        })
    }
}

fn valid_command_identity(value: &str) -> bool {
    CommandId::parse(value).is_ok_and(|command| command.to_string() == value)
}

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

/// Metadata-only command accepted by protected V2 verify.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", try_from = "VerifyWire")]
pub struct VerifyProviderCredential {
    provider: ProviderCredentialProviderV2,
    expected_lifecycle_revision: u64,
    verification_kind: ProviderCredentialVerificationKindV2,
    command_identity: String,
    native_intent_id: String,
}

impl VerifyProviderCredential {
    /// Constructs a validated explicit verification command.
    pub fn new(
        provider: ProviderCredentialProviderV2,
        expected_lifecycle_revision: u64,
        verification_kind: ProviderCredentialVerificationKindV2,
        command_identity: impl Into<String>,
        native_intent_id: impl Into<String>,
    ) -> Result<Self, ProviderCredentialValidationErrorV2> {
        Self::try_from(VerifyWire {
            provider,
            expected_lifecycle_revision,
            verification_kind,
            command_identity: command_identity.into(),
            native_intent_id: native_intent_id.into(),
        })
    }

    pub const fn provider(&self) -> ProviderCredentialProviderV2 {
        self.provider
    }
    pub const fn expected_lifecycle_revision(&self) -> u64 {
        self.expected_lifecycle_revision
    }
    pub const fn verification_kind(&self) -> ProviderCredentialVerificationKindV2 {
        self.verification_kind
    }
    pub fn command_identity(&self) -> &str {
        &self.command_identity
    }
    pub fn native_intent_id(&self) -> &str {
        &self.native_intent_id
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifyWire {
    provider: ProviderCredentialProviderV2,
    expected_lifecycle_revision: u64,
    verification_kind: ProviderCredentialVerificationKindV2,
    command_identity: String,
    native_intent_id: String,
}

impl TryFrom<VerifyWire> for VerifyProviderCredential {
    type Error = ProviderCredentialValidationErrorV2;

    fn try_from(value: VerifyWire) -> Result<Self, Self::Error> {
        if value.expected_lifecycle_revision == 0 {
            return Err(ProviderCredentialValidationErrorV2::InvalidRevision);
        }
        if !valid_command_identity(&value.command_identity) {
            return Err(ProviderCredentialValidationErrorV2::InvalidCommandIdentity);
        }
        if !valid_opaque_id(&value.native_intent_id) {
            return Err(ProviderCredentialValidationErrorV2::InvalidNativeIntent);
        }
        Ok(Self {
            provider: value.provider,
            expected_lifecycle_revision: value.expected_lifecycle_revision,
            verification_kind: value.verification_kind,
            command_identity: value.command_identity,
            native_intent_id: value.native_intent_id,
        })
    }
}
