// Redacted diagnostics builders for the `doctor` command.
//
// Every check message ends with a stable bracketed check id (`[profile.ok]`,
// `[runtime.unreachable]`, ...) so failure causes stay distinguishable in both
// output channels while local file system paths never enter the report:
// profile locations are reduced to non-committal descriptions before any
// `message`/`details` value is built. No raw profile, config, endpoint or
// credential data passes through these builders.
//
// Shared namespace note: `include!`-composed into `main.rs` (from
// `doctor.rs`); `Path`, `DiagnosticCheck`, `CheckStatus` and the profile /
// probe types come from earlier root-level includes — no re-imports here.

/// Human-readable, path-free description of a client profile location.
///
/// The default daemon-owned location is reported as such (it is not
/// user-identifying beyond "this machine uses the default"); every other
/// location — including an explicit `--profile` argument — is withheld.
#[must_use]
pub fn redacted_profile_location(path: &Path) -> String {
    match default_local_profile_path() {
        Ok(default) if path.as_os_str() == default.as_os_str() => {
            "default client profile location".to_owned()
        }
        _ => "profile location withheld (directory omitted)".to_owned(),
    }
}

/// Tags a builder-produced check with its stable bracketed check id.
///
/// Used for checks whose constructors build a bare `message` — the active
/// provider selection and the credential checks, both in
/// `provider_checks.rs`: only the `message` value is amended.
#[must_use]
pub fn with_check_id(mut check: DiagnosticCheck, id: &'static str) -> DiagnosticCheck {
    check.message = format!("{} [{id}]", check.message);
    check
}

/// Stable check id for the active provider selection outcome.
#[must_use]
pub const fn active_provider_check_id(probe: &ActiveProviderProbe) -> &'static str {
    match probe {
        ActiveProviderProbe::Deterministic => "provider.deterministic",
        ActiveProviderProbe::Live(_) => "provider.live",
        ActiveProviderProbe::Unavailable(_) => "provider.unavailable",
    }
}

/// Stable check id for one credential probe outcome.
#[must_use]
pub const fn credential_check_id(probe: CredentialProbe, active: bool) -> &'static str {
    match probe {
        CredentialProbe::Configured => "credential.configured",
        CredentialProbe::Missing if active => "credential.missing_active",
        CredentialProbe::Missing => "credential.missing",
        CredentialProbe::Unsupported => "credential.unsupported",
        CredentialProbe::AccessDenied => "credential.access_denied",
        CredentialProbe::IdentityMismatch => "credential.identity_mismatch",
        CredentialProbe::Unavailable => "credential.status_unavailable",
    }
}

/// Profile check: valid and readable.
#[must_use]
pub fn profile_check_ok(profile_path: &Path) -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Profile".to_owned(),
        status: CheckStatus::Ok,
        message: "Valid and readable [profile.ok]".to_owned(),
        details: Some(redacted_profile_location(profile_path)),
    }
}

/// Profile check: file missing or unreadable.
#[must_use]
pub fn profile_check_unavailable(profile_path: &Path) -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Profile".to_owned(),
        status: CheckStatus::Error,
        message: "Profile not found [profile.unavailable]".to_owned(),
        details: Some(redacted_profile_location(profile_path)),
    }
}

/// Profile check: permissions are not owner-only.
#[must_use]
pub fn profile_check_insecure_permissions(profile_path: &Path) -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Profile".to_owned(),
        status: CheckStatus::Error,
        message: "Insecure permissions [profile.insecure_permissions]".to_owned(),
        details: Some(format!(
            "{}; owner-only permissions (0600) required",
            redacted_profile_location(profile_path)
        )),
    }
}

/// Profile check: content fails strict validation.
#[must_use]
pub fn profile_check_invalid(profile_path: &Path) -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Profile".to_owned(),
        status: CheckStatus::Error,
        message: "Invalid or incompatible profile [profile.invalid]".to_owned(),
        details: Some(redacted_profile_location(profile_path)),
    }
}

/// Profile check: stored credential material fails validation.
#[must_use]
pub fn profile_check_invalid_credential(profile_path: &Path) -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Profile".to_owned(),
        status: CheckStatus::Error,
        message: "Invalid credential in profile [profile.invalid_credential]".to_owned(),
        details: Some(redacted_profile_location(profile_path)),
    }
}

/// Display form of the daemon-reported `/health` version.
///
/// The wire format only bounds the version (non-empty, ≤64 bytes, no control
/// characters), so path- and token-like strings parse fine. Only a
/// semver-shaped value — the format the daemon actually sends
/// (`env!("CARGO_PKG_VERSION")`) — is rendered verbatim: it starts with the
/// numeric major version, carries at least one dot and stays inside the
/// ASCII semver charset `[A-Za-z0-9.+-]` and the wire length bound. Every
/// other value is replaced by a fixed placeholder that echoes no part of the
/// input.
#[must_use]
fn display_version(version: &str) -> String {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-');
    if version.len() <= 64
        && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && version.contains('.')
        && version.bytes().all(allowed)
    {
        version.to_owned()
    } else {
        "withheld (unexpected format)".to_owned()
    }
}

/// Runtime check with daemon-reported health status and format-gated version
/// display (see `display_version`).
fn runtime_health_check(
    status: CheckStatus,
    wire_status: &'static str,
    message: &'static str,
    id: &'static str,
    version: &str,
) -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Runtime".to_owned(),
        status,
        message: format!("{message} [{id}]"),
        details: Some(format!(
            "Status: {wire_status}\nVersion: {}",
            display_version(version)
        )),
    }
}

/// Runtime check: healthy.
#[must_use]
pub fn runtime_check_ok(version: &str) -> DiagnosticCheck {
    runtime_health_check(CheckStatus::Ok, "ok", "Runtime is healthy", "runtime.ok", version)
}

/// Runtime check: degraded (recovery blocked).
#[must_use]
pub fn runtime_check_degraded(version: &str) -> DiagnosticCheck {
    runtime_health_check(
        CheckStatus::Warning,
        "degraded",
        "Runtime is degraded (recovery blocked)",
        "runtime.degraded",
        version,
    )
}

/// Runtime check: unavailable (integrity blocked).
#[must_use]
pub fn runtime_check_unavailable(version: &str) -> DiagnosticCheck {
    runtime_health_check(
        CheckStatus::Error,
        "unavailable",
        "Runtime is unavailable (integrity blocked)",
        "runtime.unavailable",
        version,
    )
}

/// Runtime check: daemon is shutting down.
#[must_use]
pub fn runtime_check_shutting_down(version: &str) -> DiagnosticCheck {
    runtime_health_check(
        CheckStatus::Warning,
        "shutting_down",
        "Runtime is shutting down",
        "runtime.shutting_down",
        version,
    )
}

/// Runtime check: daemon reported an unrecognized status; the raw status
/// string is deliberately withheld because it is daemon-controlled content.
#[must_use]
pub fn runtime_check_unknown_status() -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Runtime".to_owned(),
        status: CheckStatus::Error,
        message: "Unknown runtime status [runtime.unknown_status]".to_owned(),
        details: None,
    }
}

/// Runtime check: probe failed before transport (profile load, validation,
/// connection); the underlying error is deliberately not rendered.
#[must_use]
pub fn runtime_check_unreachable() -> DiagnosticCheck {
    DiagnosticCheck {
        name: "Runtime".to_owned(),
        status: CheckStatus::Error,
        message: "Cannot connect to runtime [runtime.unreachable]".to_owned(),
        details: Some("Runtime daemon may not be running".to_owned()),
    }
}
