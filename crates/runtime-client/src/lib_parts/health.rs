#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConnectionState {
    #[default]
    Unconfigured,
    Connecting,
    Authenticating,
    Reconciling,
    Live,
    Stale,
    Reconnecting,
    Incompatible,
    Revoked,
    Fatal,
}

impl RuntimeConnectionState {
    #[must_use]
    pub const fn allows_mutations(self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeHealth {
    Ready { version: String },
    RecoveryBlocked { version: String },
    IntegrityBlocked { version: String },
    ShuttingDown { version: String },
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeHealthError {
    #[error("runtime health payload is invalid")]
    InvalidPayload,
    #[error("runtime health status is unknown")]
    UnknownStatus,
    #[error("runtime health HTTP status does not match its payload")]
    StatusCodeMismatch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthPayload {
    status: String,
    version: String,
}

impl RuntimeHealth {
    /// Parses the public `/health` response observed at
    /// `HEALTH_CONTRACT_EVIDENCE_COMMIT`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed payloads, unknown states, invalid
    /// versions or HTTP status/payload mismatches.
    pub fn parse(status_code: u16, bytes: &[u8]) -> Result<Self, RuntimeHealthError> {
        let payload: HealthPayload =
            serde_json::from_slice(bytes).map_err(|_| RuntimeHealthError::InvalidPayload)?;
        if payload.version.is_empty()
            || payload.version.len() > 64
            || payload.version.chars().any(char::is_control)
        {
            return Err(RuntimeHealthError::InvalidPayload);
        }
        let (health, expected_code) = match payload.status.as_str() {
            "ok" => (
                Self::Ready {
                    version: payload.version,
                },
                200,
            ),
            "degraded" => (
                Self::RecoveryBlocked {
                    version: payload.version,
                },
                200,
            ),
            "unavailable" => (
                Self::IntegrityBlocked {
                    version: payload.version,
                },
                503,
            ),
            "shutting_down" => (
                Self::ShuttingDown {
                    version: payload.version,
                },
                503,
            ),
            _ => return Err(RuntimeHealthError::UnknownStatus),
        };
        if status_code != expected_code {
            return Err(RuntimeHealthError::StatusCodeMismatch);
        }
        Ok(health)
    }
}
