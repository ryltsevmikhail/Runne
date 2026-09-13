use std::fmt;

use crate::{ProviderCredentialProviderV1, RunBinding};

pub const QUALIFICATION_CASE_CONTROL_DOMAIN: &str = "runne/qualification-case-control/v1";
pub const QUALIFICATION_CASE_CONTROL_VERSION: u8 = 1;
pub const MAX_QUALIFICATION_CASE_CONTROL_BYTES: usize = 8_192;
const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;

/// Immutable, sorted inventory mirrored from the qualification verifier.
pub const QUALIFICATION_CASE_SELECTORS: [&str; 54] = [
    "account_only_mismatch_denied",
    "ad_hoc_signature_denied",
    "clean_install",
    "crash_recovery",
    "duplicate_request_denied",
    "duplicate_version_denied",
    "hardlink_denied",
    "keychain_executable_acl_denied",
    "kill_after_lifecycle_cas",
    "kill_after_native_effect",
    "kill_after_readback",
    "kill_after_reply",
    "kill_after_service_consume",
    "kill_before_lifecycle_cas",
    "kill_before_native_effect",
    "kill_before_readback",
    "kill_before_reply",
    "kill_before_service_consume",
    "kill_desktop_process",
    "kill_registration_ack_loss",
    "kill_runtime_process",
    "kill_service_launchd_restart",
    "kill_writer_process",
    "local_verify_no_network",
    "mixed_child_manifest_denied",
    "n_to_n_plus_1",
    "package_skew_denied",
    "pair_create_readback",
    "pid_reuse_denied",
    "post_spawn_codesign_skew_denied",
    "post_spawn_executable_image_skew_denied",
    "remote_verify_after_local",
    "replay_denied",
    "revoke_fence_delete",
    "rollback",
    "rotation",
    "runtime_restart_old_session_denied",
    "same_uid_native_delete_denied",
    "same_uid_native_find_denied",
    "same_uid_native_read_denied",
    "same_uid_native_update_denied",
    "service_restart_persistence",
    "standalone_daemon_denied",
    "standalone_writer_denied",
    "stored_attributes_verified",
    "symlink_denied",
    "terminal_exact_namespace_cleanup",
    "third_process_broker_denied",
    "unsigned_package_denied",
    "wrong_desktop_endpoint_peer_denied",
    "wrong_peer_denied",
    "wrong_runtime_endpoint_peer_denied",
    "wrong_service_peer_denied",
    "wrong_writer_endpoint_peer_denied",
];

/// Shape failure for a qualification case-control frame. This is not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationCaseControlError {
    InvalidMessage,
}

impl fmt::Display for QualificationCaseControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid qualification case control message")
    }
}

impl std::error::Error for QualificationCaseControlError {}

/// An exact member of the immutable qualification selector inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationCaseSelector(&'static str);

impl QualificationCaseSelector {
    /// Parses one selector from the fixed verifier inventory.
    pub fn parse(value: &str) -> Result<Self, QualificationCaseControlError> {
        QUALIFICATION_CASE_SELECTORS
            .iter()
            .copied()
            .find(|selector| *selector == value)
            .map(Self)
            .ok_or(QualificationCaseControlError::InvalidMessage)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Closed operation names. Selector-to-operation authorization remains external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationCaseAction {
    Pair,
    Readback,
    Rotate,
    Revoke,
    VerifyLocal,
    VerifyRemote,
}

impl QualificationCaseAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::Readback => "readback",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
            Self::VerifyLocal => "verify_local",
            Self::VerifyRemote => "verify_remote",
        }
    }

    pub fn parse(value: &str) -> Result<Self, QualificationCaseControlError> {
        match value {
            "pair" => Ok(Self::Pair),
            "readback" => Ok(Self::Readback),
            "rotate" => Ok(Self::Rotate),
            "revoke" => Ok(Self::Revoke),
            "verify_local" => Ok(Self::VerifyLocal),
            "verify_remote" => Ok(Self::VerifyRemote),
            _ => Err(QualificationCaseControlError::InvalidMessage),
        }
    }
}

/// Unauthenticated, run-bound case request. It carries no authority or secret.
pub struct QualificationCaseControlRequest {
    binding: RunBinding,
    daemon_challenge: [u8; 32],
    session_id: [u8; 32],
    sequence: u64,
    selector: QualificationCaseSelector,
    provider: ProviderCredentialProviderV1,
    action: QualificationCaseAction,
    expected_credential_revision: Option<u64>,
    run_not_after: u64,
}

impl QualificationCaseControlRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: RunBinding,
        daemon_challenge: [u8; 32],
        session_id: [u8; 32],
        sequence: u64,
        selector: QualificationCaseSelector,
        provider: ProviderCredentialProviderV1,
        action: QualificationCaseAction,
        expected_credential_revision: Option<u64>,
        run_not_after: u64,
    ) -> Result<Self, QualificationCaseControlError> {
        let value = Self {
            binding,
            daemon_challenge,
            session_id,
            sequence,
            selector,
            provider,
            action,
            expected_credential_revision,
            run_not_after,
        };
        (nonzero(&value.daemon_challenge)
            && nonzero(&value.session_id)
            && value.sequence > 0
            && valid_revision(value.action, value.expected_credential_revision)
            && valid_time(value.run_not_after))
        .then_some(value)
        .ok_or(QualificationCaseControlError::InvalidMessage)
    }

    pub fn encode(&self) -> Result<Vec<u8>, QualificationCaseControlError> {
        super::wire::encode_request(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QualificationCaseControlError> {
        super::wire::decode_request(bytes)
    }

    #[must_use]
    pub const fn binding(&self) -> &RunBinding {
        &self.binding
    }
    #[must_use]
    pub const fn daemon_challenge(&self) -> [u8; 32] {
        self.daemon_challenge
    }
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Returns the nonzero wire sequence; retained session state enforces monotonicity.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn selector(&self) -> QualificationCaseSelector {
        self.selector
    }
    #[must_use]
    pub const fn provider(&self) -> ProviderCredentialProviderV1 {
        self.provider
    }
    #[must_use]
    pub const fn action(&self) -> QualificationCaseAction {
        self.action
    }
    #[must_use]
    pub const fn expected_credential_revision(&self) -> Option<u64> {
        self.expected_credential_revision
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }
}

/// Echo-only case reply. It conveys no validated or permitted state.
pub struct QualificationCaseControlReply {
    request: QualificationCaseControlRequest,
    expires_at: u64,
}

impl QualificationCaseControlReply {
    pub fn new(
        request: QualificationCaseControlRequest,
        expires_at: u64,
    ) -> Result<Self, QualificationCaseControlError> {
        (valid_time(expires_at) && expires_at <= request.run_not_after)
            .then_some(Self {
                request,
                expires_at,
            })
            .ok_or(QualificationCaseControlError::InvalidMessage)
    }

    pub fn encode(&self) -> Result<Vec<u8>, QualificationCaseControlError> {
        super::wire::encode_reply(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QualificationCaseControlError> {
        super::wire::decode_reply(bytes)
    }

    #[must_use]
    pub const fn request(&self) -> &QualificationCaseControlRequest {
        &self.request
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

pub(super) const fn valid_time(value: u64) -> bool {
    value > 0 && value <= MAX_SAFE_JS_INTEGER
}

fn valid_revision(action: QualificationCaseAction, revision: Option<u64>) -> bool {
    matches!(
        (action, revision),
        (QualificationCaseAction::Pair, None) | (_, Some(1..))
    )
}

fn nonzero<const N: usize>(value: &[u8; N]) -> bool {
    value != &[0; N]
}
