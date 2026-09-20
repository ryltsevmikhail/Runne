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
/// characters), so arbitrary daemon-controlled strings parse fine. Only a
/// *verified numeric core* is rendered: the value must split at the first
/// `-`/`+` into exactly three non-empty ASCII-digit components and keep the
/// same ≤64-byte wire bound; a prerelease/build tail, when present, must be
/// non-empty and stay inside the ASCII version charset `[A-Za-z0-9.+-]`. The
/// output is rebuilt from the verified digit components (`major.minor.patch`)
/// — the tail is never rendered and no input fragment is ever echoed. Every
/// other value is replaced wholesale by a fixed placeholder that echoes no
/// part of the input.
///
/// Deliberate deviation from strict semver: this is a display allowlist, not
/// a semver validator — leading zeros and arbitrary component lengths are
/// accepted, and the tail is never parsed into prerelease/build identifiers.
/// The daemon's real `env!("CARGO_PKG_VERSION")` value renders unchanged.
#[must_use]
fn display_version(version: &str) -> String {
    const WITHHELD: &str = "withheld (unexpected format)";
    // Same ceiling the wire parser enforces; the display allowlist never
    // widens the `RuntimeHealth::parse` bounds.
    if version.len() > 64 {
        return WITHHELD.to_owned();
    }
    let in_version_charset =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-');
    let numeric = |component: &str| {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    };
    let (core, tail) = version
        .find(['-', '+'])
        .map_or((version, None), |end| (&version[..end], Some(&version[end + 1..])));
    let tail_ok = tail.is_none_or(|tail| !tail.is_empty() && tail.bytes().all(in_version_charset));
    let mut parts = core.split('.');
    let shape = (parts.next(), parts.next(), parts.next(), parts.next());
    if tail_ok
        && let (Some(major), Some(minor), Some(patch), None) = shape
        && numeric(major)
        && numeric(minor)
        && numeric(patch)
    {
        return format!("{major}.{minor}.{patch}");
    }
    WITHHELD.to_owned()
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
