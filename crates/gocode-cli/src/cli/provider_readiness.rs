// Best-effort provider readiness probes shared by `doctor` and `status`.
//
// Everything here is metadata-only: the non-secret external daemon config and
// credential *status* from the native secure store. No credential bytes are
// read, and no probe error text embeds user input. The daemon remains
// authoritative for the exact selection (`gocode-daemon doctor` is the
// source of truth); this module mirrors it for CLI diagnostics.
//
// Shared namespace note: this file is `include!`-composed into `main.rs`,
// so `Path`, `PathBuf` and all `gocode_secure_store` types are imported at
// the `main.rs` top level and must not be re-imported here.

/// Mirrors the daemon's fixed external config location.
#[must_use]
pub fn external_config_path() -> PathBuf {
    dirs::config_local_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| {
            dirs::runtime_dir()
                .or_else(dirs::data_local_dir)
                .or_else(|| dirs::home_dir().map(|home| home.join(".local").join("share")))
                .unwrap_or_else(|| PathBuf::from("."))
        })
        .join("gocode-daemon")
        .join("config.toml")
}

/// Mirrors the daemon's bounded external config read.
pub(crate) const MAX_EXTERNAL_CONFIG_BYTES: u64 = 16 * 1024;

/// Mirrors the daemon's exact `SystemConfig` shape: every field optional,
/// unknown keys rejected, schema version pinned to 2.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Fields exist to mirror the daemon's exact config shape.
struct ExternalConfigWire {
    schema_version: i64,
    db_path: Option<String>,
    http_bind: Option<String>,
    replay_integrity_key_path: Option<String>,
    max_in_flight: Option<u32>,
    shutdown_timeout_ms: Option<u64>,
    provider_activation: Option<ExternalProviderActivationWire>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalProviderActivationWire {
    mode: String,
    profile_id: String,
    profile_digest: String,
}

/// Result of reading the active provider selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveProviderProbe {
    /// No live provider selected (deterministic default or explicit mode).
    Deterministic,
    /// Exact live provider selection.
    Live(ActiveProviderLive),
    /// The config exists but cannot be interpreted exactly.
    Unavailable(String),
}

/// Non-secret description of the exact live provider selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProviderLive {
    pub mode: &'static str,
    pub provider: &'static str,
    pub profile_id: String,
    pub model_id: String,
    pub model_revision: String,
    pub config_path: PathBuf,
}

/// Probing status is strictly best-effort: any deviation from the exact daemon
/// interpretation is reported as `Unavailable`, never guessed.
#[must_use]
pub fn probe_active_provider() -> ActiveProviderProbe {
    read_active_provider(&external_config_path())
}

/// Visible to `provider_checks` tests only.
pub(crate) fn read_active_provider(config_path: &Path) -> ActiveProviderProbe {
    let unavailable = |message: &str| ActiveProviderProbe::Unavailable(message.to_owned());
    let bytes = match std::fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ActiveProviderProbe::Deterministic;
        }
        Err(_) => return unavailable("external config is unreadable"),
    };
    if bytes.len() as u64 > MAX_EXTERNAL_CONFIG_BYTES {
        return unavailable("external config exceeds size limit");
    }
    let Ok(wire) = toml::from_str::<ExternalConfigWire>(
        std::str::from_utf8(&bytes).unwrap_or_default(),
    ) else {
        return unavailable("external config is not valid TOML");
    };
    if wire.schema_version != 2 {
        return unavailable("external config schema version is not 2");
    }
    let Some(activation) = wire.provider_activation else {
        return ActiveProviderProbe::Deterministic;
    };
    let (mode, provider) = match activation.mode.as_str() {
        "deterministic_v1" => return ActiveProviderProbe::Deterministic,
        "openai_responses_text_v1" => ("openai_responses_text_v1", "openai"),
        "deepseek_responses_text_v1" => ("deepseek_responses_text_v1", "deepseek"),
        _ => return unavailable("invalid provider activation mode"),
    };
    if hex::decode(&activation.profile_digest)
        .ok()
        .is_none_or(|digest| digest.len() != 32)
    {
        return unavailable("invalid provider activation digest");
    }
    let Some(model) = model_for_mode(mode) else {
        return unavailable("provider profile artifact unavailable");
    };
    if model.profile_id != activation.profile_id {
        return unavailable("provider profile binding mismatch");
    }
    ActiveProviderProbe::Live(ActiveProviderLive {
        mode,
        provider,
        profile_id: model.profile_id,
        model_id: model.model_id,
        model_revision: model.model_revision,
        config_path: config_path.to_path_buf(),
    })
}

struct ModelIdentity {
    profile_id: String,
    model_id: String,
    model_revision: String,
}

/// Reads the same profile JSON artifacts the daemon embeds, keyed by mode.
fn model_for_mode(mode: &str) -> Option<ModelIdentity> {
    let bytes: &[u8] = match mode {
        "openai_responses_text_v1" => {
            include_bytes!("../../../../docs/profiles/openai-responses-text-v1.json")
        }
        "deepseek_responses_text_v1" => {
            include_bytes!("../../../../docs/profiles/deepseek-responses-text-v1.json")
        }
        _ => return None,
    };
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let model = value.get("model")?;
    Some(ModelIdentity {
        profile_id: value.get("profile_id")?.as_str()?.to_owned(),
        model_id: model.get("model_id")?.as_str()?.to_owned(),
        model_revision: model.get("revision")?.as_str()?.to_owned(),
    })
}

/// Metadata-only credential disposition for one provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialProbe {
    Configured,
    Missing,
    Unsupported,
    AccessDenied,
    IdentityMismatch,
    Unavailable,
}

impl CredentialProbe {
    /// Stable non-secret display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
            Self::AccessDenied => "access denied",
            Self::IdentityMismatch => "identity mismatch",
            Self::Unavailable => "unavailable",
        }
    }

    #[must_use]
    pub const fn is_configured(self) -> bool {
        matches!(self, Self::Configured)
    }
}

/// Stable non-secret name of the native credential backend on this platform.
#[must_use]
pub const fn credential_source() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS keychain"
    } else {
        "unsupported on this platform"
    }
}

/// Resolves the same writer/reader credential identity pair the CLI uses for
/// credential commands: the running `gocode` executable writes, the sibling
/// `gocode-daemon` executable reads.
#[must_use]
pub fn credential_access_policy() -> Option<ProviderCredentialAccessPolicy> {
    let writer = std::env::current_exe().ok()?;
    let writer = std::fs::canonicalize(writer).ok()?;
    let reader = writer.parent()?.join("gocode-daemon");
    ProviderCredentialAccessPolicy::new(&writer, &reader).ok()
}

/// Probes credential metadata only; never loads credential bytes.
#[must_use]
pub fn probe_credential(id: ProviderCredentialId) -> CredentialProbe {
    let Some(access) = credential_access_policy() else {
        return CredentialProbe::Unavailable;
    };
    let store = NativeProviderCredentialStore::new();
    match store.provider_credential_status(id, &access) {
        Ok(ProviderCredentialStatus::Configured) => CredentialProbe::Configured,
        Ok(ProviderCredentialStatus::Missing) => CredentialProbe::Missing,
        Ok(ProviderCredentialStatus::Unsupported) => CredentialProbe::Unsupported,
        Err(SecureStoreError::CredentialAccessDenied) => CredentialProbe::AccessDenied,
        Err(SecureStoreError::CredentialIdentityMismatch) => CredentialProbe::IdentityMismatch,
        Err(_) => CredentialProbe::Unavailable,
    }
}

/// Maps the stable provider name back to the exact credential id.
#[must_use]
pub fn credential_id_for(provider: &str) -> ProviderCredentialId {
    match provider {
        "deepseek" => ProviderCredentialId::DeepSeek,
        _ => ProviderCredentialId::OpenAi,
    }
}
