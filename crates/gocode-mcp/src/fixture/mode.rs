/// Sensitivity-safe fixture protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureMcpFailure {
    /// No explicit mode was selected.
    ModeRequired,
    /// The selected mode has no implementation.
    ModeUnsupported,
    /// Production MCP SDK composition remains disabled.
    ProductionSdkDisabled,
    /// External endpoints are never admitted by the fixture.
    ExternalEndpointUnsupported,
    /// Local process ownership is deferred to Task 7B.
    LocalProcessUnsupported,
    /// The protocol version is not the fixture version.
    ProtocolVersionUnsupported,
    /// The configured server identity did not match.
    ServerIdentityMismatch,
    /// The connection did not match the authenticated connection.
    ConnectionMismatch,
    /// The session did not match the authenticated session.
    SessionMismatch,
    /// The generation did not match the authenticated generation.
    GenerationMismatch,
    /// Discovery belongs to an old authenticated connection.
    DiscoveryStale,
    /// A tool is absent from the fixture allowlist.
    ToolNotAllowed,
    /// A fixture tool definition is malformed.
    ToolDefinitionInvalid,
    /// Input failed its closed schema subset.
    InputSchemaMismatch,
    /// Output failed its closed schema subset.
    OutputSchemaMismatch,
    /// An explicit approval is required.
    ApprovalRequired,
    /// Approval did not bind this exact call.
    ApprovalMismatch,
    /// No capability was supplied.
    CapabilityMissing,
    /// Capability lifetime elapsed.
    CapabilityExpired,
    /// Capability was already consumed.
    CapabilityConsumed,
    /// Invocation identity was reused with different immutable call data.
    InvocationConflict,
    /// Request bounds were exceeded.
    RequestTooLarge,
    /// Response bounds were exceeded.
    ResponseTooLarge,
    /// Sensitive material was detected before dispatch.
    SecretMaterialRejected,
    /// The request was cancelled before dispatch.
    Cancelled,
    /// The request timed out before dispatch.
    TimedOut,
    /// Dispatch may have crossed the effect boundary without terminal proof.
    DispatchUncertain,
    /// Synthetic fixture accounting denied the reservation.
    AccountingDenied,
    /// Synthetic fixture accounting did not match its reservation.
    AccountingMismatch,
    /// Lifecycle transition is not permitted from the current state.
    InvalidStateTransition,
    /// A process intent could not be represented by the closed process contract.
    ProcessIntentMalformed,
    /// Process input or output bounds were exceeded before issuance.
    ProcessInputBoundsExceeded,
    /// The exact process environment was not granted.
    ProcessEnvironmentNotGranted,
    /// A process environment name is denied.
    ProcessEnvironmentDenied,
    /// The process intent digest could not be encoded.
    ProcessDigestEncodingInvalid,
    /// Process capability issuance rejected the exact intent.
    ProcessCapabilityInvalid,
    /// Process executable verification did not match the exact intent.
    ProcessExecutableVerificationFailed,
    /// Process working-directory verification did not match the exact intent.
    ProcessCwdVerificationFailed,
    /// Process approval issuance rejected the exact intent.
    ProcessApprovalInvalid,
    /// A process-backed tool requires typed process issuance.
    ProcessIntentRequired,
    /// Typed process issuance targeted a protocol-only tool.
    ExecutionClassMismatch,
    /// A matching process call is already reserved or admitted.
    ProcessReservationBusy,
    /// No sealed process composition is available for the process-backed tool.
    ProcessSandboxUnavailable,
}

impl From<gocode_tools::ProcessContractError> for FixtureMcpFailure {
    fn from(error: gocode_tools::ProcessContractError) -> Self {
        match error {
            gocode_tools::ProcessContractError::IntentMalformed => Self::ProcessIntentMalformed,
            gocode_tools::ProcessContractError::InputBoundsExceeded => {
                Self::ProcessInputBoundsExceeded
            }
            gocode_tools::ProcessContractError::EnvironmentNotGranted => {
                Self::ProcessEnvironmentNotGranted
            }
            gocode_tools::ProcessContractError::EnvironmentDenied => Self::ProcessEnvironmentDenied,
            gocode_tools::ProcessContractError::DigestEncodingInvalid => {
                Self::ProcessDigestEncodingInvalid
            }
            gocode_tools::ProcessContractError::CapabilityInvalid => Self::ProcessCapabilityInvalid,
            gocode_tools::ProcessContractError::ExecutableVerificationFailed => {
                Self::ProcessExecutableVerificationFailed
            }
            gocode_tools::ProcessContractError::CwdVerificationFailed => {
                Self::ProcessCwdVerificationFailed
            }
            gocode_tools::ProcessContractError::ApprovalInvalid => Self::ProcessApprovalInvalid,
        }
    }
}

impl core::fmt::Display for FixtureMcpFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "fixture MCP rejected: {:?}", self)
    }
}

impl std::error::Error for FixtureMcpFailure {}

/// Explicit MCP activation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureMcpMode {
    /// The sole executable deterministic fixture mode.
    FixtureOnly,
    /// Deliberately unsupported external endpoint mode.
    ExternalEndpoint,
    /// Deliberately unsupported local-process mode.
    LocalProcess,
    /// Deliberately unavailable production SDK mode.
    Production,
}

impl FixtureMcpMode {
    /// Returns the stable mode label used in safe audit metadata.
    pub const fn label(self) -> &'static str {
        match self {
            Self::FixtureOnly => "FIXTURE_ONLY",
            Self::ExternalEndpoint => "EXTERNAL_ENDPOINT",
            Self::LocalProcess => "LOCAL_PROCESS",
            Self::Production => "PRODUCTION",
        }
    }

    /// Activates only the local deterministic fixture.
    pub const fn activate(self) -> Result<(), FixtureMcpFailure> {
        match self {
            Self::FixtureOnly => Ok(()),
            Self::ExternalEndpoint => Err(FixtureMcpFailure::ExternalEndpointUnsupported),
            Self::LocalProcess => Err(FixtureMcpFailure::LocalProcessUnsupported),
            Self::Production => Err(FixtureMcpFailure::ProductionSdkDisabled),
        }
    }
}

/// Safe profile state for fixture-only operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureProfile {
    /// Policy disabled activation.
    Disabled,
    /// No fixture was activated.
    NotActivated,
    /// Active deterministic fixture profile.
    FixtureOnly,
}

impl FixtureProfile {
    /// Returns the disabled profile state.
    pub const fn disabled() -> Self {
        Self::Disabled
    }

    /// Returns the unactivated profile state.
    pub const fn not_activated() -> Self {
        Self::NotActivated
    }

    /// Returns a safe fixed status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "DISABLED_BY_POLICY",
            Self::NotActivated => "NOT_ACTIVATED",
            Self::FixtureOnly => "FIXTURE_ONLY",
        }
    }
}
