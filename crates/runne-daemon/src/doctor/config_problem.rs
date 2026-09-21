//! Closed classification of external-config load problems for `runned doctor`.
//!
//! The report never carries the config location or any fragment of its
//! content: [`classify_config_error`] maps a [`DaemonError`] onto a fixed
//! (`id`, `reason`) pair. `reason` is only ever a closed static literal —
//! either one of the exact static validation messages of the config layer
//! (allowlisted below) or a fixed phrase from this module. TOML parse
//! snippets, schema version values, raw io error text and any unrecognized
//! message are withheld entirely. Stable `[config.*]` ids keep failure causes
//! distinguishable without the raw text; unknown input degrades fail-closed
//! to `config.invalid`.

use crate::error::DaemonError;

/// One closed config-load problem: stable id plus a safe reason phrase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigProblem {
    /// Stable bracketed id (e.g. `config.not_owner_private`).
    pub id: &'static str,
    /// Safe closed reason; never echoes config content or its location.
    pub reason: &'static str,
}

impl ConfigProblem {
    /// Single-line rendering with the stable id suffix (`[check.id]` style).
    #[must_use]
    pub fn render(&self) -> String {
        format!("config problem: {} [{}]", self.reason, self.id)
    }
}

/// Exact static messages of the config layer, paired with their ids. If the
/// layer's texts change outside this slice, classification degrades
/// fail-closed to `config.invalid` — safe, less distinguishable; the table
/// test pins this inventory as a contract.
const STATIC_CONFIG_MESSAGES: &[(&str, &str)] = &[
    // config/load.rs — closed filesystem/format gates.
    (
        "external config is not owner-private",
        "config.not_owner_private",
    ),
    ("external config exceeds size limit", "config.too_large"),
    ("external config is not UTF-8", "config.not_utf8"),
    (
        "external config validation is unsupported",
        "config.unsupported_platform",
    ),
    // config/merge.rs — activation validation literals.
    ("invalid provider activation mode", "config.activation"),
    ("invalid provider activation digest", "config.activation"),
    ("Responses profile digest mismatch", "config.activation"),
    ("invalid provider activation profile", "config.activation"),
    ("Radius catalog snapshot is required", "config.activation"),
    ("Radius catalog snapshot is invalid", "config.activation"),
    ("Radius model is required", "config.activation"),
    ("Radius catalog revision is required", "config.activation"),
    (
        "token-plan accounting is not valid for Radius",
        "config.activation",
    ),
    (
        "Radius model is not in the bound catalog",
        "config.activation",
    ),
    // config/provider_settings.rs — pricing/accounting literals.
    ("invalid provider pricing digest", "config.activation"),
    ("invalid provider accounting mode", "config.activation"),
    // provider_activation.rs `validate_settings` — closed &'static str checks.
    (
        "Radius settings are not valid for native provider",
        "config.activation",
    ),
    (
        "Vertex settings do not match selected native provider",
        "config.activation",
    ),
    (
        "Vertex accounting mode is fixed by its trusted profile",
        "config.activation",
    ),
    (
        "MiniMax accounting mode must be explicit",
        "config.activation",
    ),
    (
        "Accounting mode is not valid for selected native provider",
        "config.activation",
    ),
    (
        "Radius settings are incomplete or mixed with Vertex settings",
        "config.activation",
    ),
    (
        "Responses settings are mixed with another provider family",
        "config.activation",
    ),
    ("Azure Responses settings are required", "config.activation"),
    (
        "Cloud settings are mixed with another provider family",
        "config.activation",
    ),
    (
        "provider settings are inappropriate for selected mode",
        "config.activation",
    ),
];

/// Classifies a config-load failure into a closed (`id`, `reason`) pair.
#[must_use]
pub fn classify_config_error(error: &DaemonError) -> ConfigProblem {
    match error {
        DaemonError::Config(message) => classify_config_message(message),
        DaemonError::Io(error) => ConfigProblem {
            id: "config.io_access",
            reason: io_reason(error),
        },
        DaemonError::Schema(_) => ConfigProblem {
            id: "config.schema_version",
            reason: "schema version is not supported by this daemon",
        },
        DaemonError::Lock(_) | DaemonError::Bootstrap(_) | DaemonError::StoreOpenRejection(_) => {
            ConfigProblem {
                id: "config.invalid",
                reason: "configuration state rejected (cause withheld)",
            }
        }
    }
}

/// Closed std-level cause name for an io failure. `ErrorKind::name()` and the
/// `FilesystemLoop` variant are unstable on the pinned toolchain, so the
/// closed names come from stable kind matches plus the errno for the loop
/// case. The raw io error text is never used.
fn io_reason(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "PermissionDenied",
        std::io::ErrorKind::NotFound => "NotFound",
        _ => {
            #[cfg(unix)]
            if error.raw_os_error() == Some(libc::ELOOP) {
                return "FilesystemLoop";
            }
            "unavailable"
        }
    }
}

/// Maps one `Config` message: allowlisted static literals keep their exact
/// text as the reason; a toml parse error and anything unknown are withheld.
fn classify_config_message(message: &str) -> ConfigProblem {
    if message.starts_with("TOML parse error") {
        return ConfigProblem {
            id: "config.parse",
            reason: "configuration file could not be parsed",
        };
    }
    for (text, id) in STATIC_CONFIG_MESSAGES {
        if *text == message {
            return ConfigProblem { id, reason: text };
        }
    }
    ConfigProblem {
        id: "config.invalid",
        reason: "configuration rejected (cause withheld)",
    }
}
