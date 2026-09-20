//! Regression coverage for the load-time capability gate: a profile whose
//! declared capabilities fall outside the closed set of published capability
//! profiles must be rejected by `LocalRuntimeProfile::load` with the redacted
//! `InvalidProfile` error, even when the declared digest is consistent with
//! the mutated capability list.

#[path = "local_profile/support.rs"]
mod support;

use runne_runtime_client::{LocalProfileError, LocalRuntimeProfile, REQUIRED_RUNTIME_CAPABILITIES};

use support::{ordered_capability_digest, rewrite_profile, write_profile};

/// Replaces the profile capabilities and recomputes the declared digest, so
/// the digest consistency check inside `load` stays satisfied and the
/// assertion below isolates the closed-set capability gate.
fn set_declared_capabilities(profile: &mut serde_json::Value, capabilities: &[&str]) {
    profile["capabilities"] = serde_json::json!(capabilities);
    profile["capabilityDigest"] =
        serde_json::json!(hex::encode(ordered_capability_digest(capabilities)));
}

#[cfg(unix)]
#[test]
fn profile_with_capabilities_outside_the_closed_set_is_rejected() {
    let directory = tempfile::tempdir().expect("temp directory");

    // Positive control: the untouched fixture must load, so the rejections
    // below are attributable to the capability mutations alone.
    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    assert!(LocalRuntimeProfile::load(&profile_path).is_ok());

    // An extraneous capability appended to the required profile.
    rewrite_profile(&profile_path, |profile| {
        let mut capabilities = REQUIRED_RUNTIME_CAPABILITIES.to_vec();
        capabilities.push("arbitrary.capability.v1");
        set_declared_capabilities(profile, &capabilities);
    });
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("extraneous capability"),
        LocalProfileError::InvalidProfile
    );

    // Reordering keeps the capability set but breaks exact ordinal equality
    // with the published capability profiles.
    rewrite_profile(&profile_path, |profile| {
        let mut capabilities = REQUIRED_RUNTIME_CAPABILITIES.to_vec();
        capabilities.swap(0, 1);
        set_declared_capabilities(profile, &capabilities);
    });
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("reordered capabilities"),
        LocalProfileError::InvalidProfile
    );
}

#[cfg(not(unix))]
#[test]
fn capability_gate_variants_stay_behind_the_unix_acl_gate() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");

    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("unsupported ACL validation"),
        LocalProfileError::InsecurePermissions
    );
}
