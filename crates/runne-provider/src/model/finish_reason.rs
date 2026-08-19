/// Normalized terminal reason for a provider stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFinishReason {
    /// Normal stop.
    Stop,
    /// Provider requested tool execution.
    ToolCalls,
    /// Output limit reached.
    Length,
    /// Provider content filter stopped output.
    ContentFilter,
    /// Provider reported an error.
    Error,
    /// Runtime cancellation reached the provider.
    Cancelled,
    /// Unrecognized reason retained for diagnostics and fail-closed handling.
    Unknown {
        /// Bounded raw provider value.
        raw: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawProviderFinishReason {
    Stop,
    ToolCalls,
    Length,
    ContentFilter,
    Error,
    Cancelled,
    Unknown { raw: String },
}

impl<'de> Deserialize<'de> for ProviderFinishReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderFinishReason::deserialize(deserializer)?;
        let reason = match raw {
            RawProviderFinishReason::Stop => Self::Stop,
            RawProviderFinishReason::ToolCalls => Self::ToolCalls,
            RawProviderFinishReason::Length => Self::Length,
            RawProviderFinishReason::ContentFilter => Self::ContentFilter,
            RawProviderFinishReason::Error => Self::Error,
            RawProviderFinishReason::Cancelled => Self::Cancelled,
            RawProviderFinishReason::Unknown { raw } => {
                Self::unknown(raw).map_err(<D::Error as serde::de::Error>::custom)?
            }
        };
        Ok(reason)
    }
}

impl ProviderFinishReason {
    /// Constructs a bounded unknown reason without treating it as success.
    pub fn unknown(raw: impl Into<String>) -> Result<Self, InvalidProviderId> {
        Ok(Self::Unknown {
            raw: bounded_identifier(raw.into())?,
        })
    }
}
