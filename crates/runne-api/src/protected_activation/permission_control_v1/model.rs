use super::{
    PermissionControlContextV1, PermissionControlManagedChallengeV1,
    PermissionControlManagedConsentV1, PermissionControlManagedRequestV1,
    PermissionControlModeChallengeV1, PermissionControlModeConsentV1,
    PermissionControlModeRequestV1, PermissionControlResultV1,
};

/// Independent transport key domain, selected by the protected endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionControlPurposeV1 {
    ModeControl,
    ManagedPolicyControl,
}

/// Canonical protected-channel endpoint direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionControlDirectionV1 {
    DesktopToDaemon,
    DaemonToDesktop,
}

/// Closed wire phases; each maps to exactly one payload variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionControlPhaseV1 {
    Request,
    Challenge,
    Consent,
    Cancel,
    Result,
}

/// Bounded transport failures that contain no key or attestation material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionControlErrorV1 {
    InvalidContract,
    MalformedFrame,
    AuthenticationFailed,
    ContextMismatch,
    PurposeMismatch,
    PhaseMismatch,
    DirectionMismatch,
    SequenceMismatch,
    Expired,
}

/// Closed payload union; no generic opaque bytes or serialization hooks.
#[derive(Clone, PartialEq, Eq)]
pub enum PermissionControlPayloadV1 {
    ModeRequest(PermissionControlModeRequestV1),
    ModeChallenge(PermissionControlModeChallengeV1),
    ModeConsent(PermissionControlModeConsentV1),
    ManagedRequest(PermissionControlManagedRequestV1),
    ManagedChallenge(PermissionControlManagedChallengeV1),
    ManagedConsent(PermissionControlManagedConsentV1),
    Cancel,
    Result(PermissionControlResultV1),
}

impl PermissionControlPayloadV1 {
    pub const fn phase(&self) -> PermissionControlPhaseV1 {
        match self {
            Self::ModeRequest(_) | Self::ManagedRequest(_) => PermissionControlPhaseV1::Request,
            Self::ModeChallenge(_) | Self::ManagedChallenge(_) => {
                PermissionControlPhaseV1::Challenge
            }
            Self::ModeConsent(_) | Self::ManagedConsent(_) => PermissionControlPhaseV1::Consent,
            Self::Cancel => PermissionControlPhaseV1::Cancel,
            Self::Result(_) => PermissionControlPhaseV1::Result,
        }
    }

    pub const fn direction(&self) -> PermissionControlDirectionV1 {
        match self.phase() {
            PermissionControlPhaseV1::Request
            | PermissionControlPhaseV1::Consent
            | PermissionControlPhaseV1::Cancel => PermissionControlDirectionV1::DesktopToDaemon,
            PermissionControlPhaseV1::Challenge | PermissionControlPhaseV1::Result => {
                PermissionControlDirectionV1::DaemonToDesktop
            }
        }
    }
}

/// Transport-authenticated bytes and claims. This is never a native proof receipt.
pub struct AuthenticatedPermissionControlFrameV1 {
    pub(super) purpose: PermissionControlPurposeV1,
    pub(super) direction: PermissionControlDirectionV1,
    pub(super) sequence: u64,
    pub(super) context: PermissionControlContextV1,
    pub(super) payload: PermissionControlPayloadV1,
}

impl AuthenticatedPermissionControlFrameV1 {
    pub const fn purpose(&self) -> PermissionControlPurposeV1 {
        self.purpose
    }
    pub const fn direction(&self) -> PermissionControlDirectionV1 {
        self.direction
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn context(&self) -> &PermissionControlContextV1 {
        &self.context
    }
    pub const fn payload(&self) -> &PermissionControlPayloadV1 {
        &self.payload
    }
}

impl std::fmt::Debug for AuthenticatedPermissionControlFrameV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "AuthenticatedPermissionControlFrameV1(<transport-authenticated; not native-verified>)",
        )
    }
}
