// Hermetic canary suite for the doctor `Version` display gate (slice A,
// narrowed to numeric-core-only rendering in slice C).
//
// The `/health` wire parser only bounds the version (non-empty, ≤64 bytes,
// no control characters), so path- and token-like strings parse fine; the
// display gate in `runtime_health_check` is what keeps them out of the
// report by rendering only a verified numeric core (`major.minor.patch`)
// and replacing every other value with a fixed placeholder. These tests
// drive the REAL parsing path (`RuntimeHealth::parse`) and the REAL report
// formatter for both output channels, using synthetic private canaries only.
// No network, no host state, no real daemon.

use super::*;

const PATH_LIKE_VERSION: &str = "/home/alice/.runne/private";
const TOKEN_LIKE_VERSION: &str = "sk-canary-invalid-token-0123456789abcdef";
const PLACEHOLDER: &str = "withheld (unexpected format)";

fn payload(status: &str, version: &str) -> Vec<u8> {
    format!(r#"{{"status":"{status}","version":"{version}"}}"#).into_bytes()
}

/// The canaries pass the wire parser unchanged: the display gate, not the
/// parser, is the guard the report relies on.
#[test]
fn wire_parser_accepts_path_and_token_like_versions() {
    for version in [PATH_LIKE_VERSION, TOKEN_LIKE_VERSION] {
        let health =
            RuntimeHealth::parse(200, &payload("ok", version)).expect("bounds do not reject");
        match health {
            RuntimeHealth::Ready { version: parsed } => assert_eq!(parsed, version),
            other => panic!("expected Ready, got {other:?}"),
        }
    }
}

/// Runs one builder output through the real formatter for both channels.
fn channels(check: DiagnosticCheck) -> (DiagnosticReport, String, String) {
    let mut report = DiagnosticReport::new();
    report.add_check(check);
    let text = format_diagnostic_report(&report, OutputFormat::Text);
    let json = format_diagnostic_report(&report, OutputFormat::Json);
    let envelope =
        serde_json::to_string(&SuccessEnvelope::new(json.data_value())).expect("envelope");
    (report, text.render_text().to_owned(), envelope)
}

fn all_runtime_builders(version: &str) -> Vec<DiagnosticCheck> {
    vec![
        runtime_check_ok(version),
        runtime_check_degraded(version),
        runtime_check_unavailable(version),
        runtime_check_shutting_down(version),
    ]
}

#[test]
fn canary_versions_are_withheld_in_details_text_and_json() {
    for canary in [PATH_LIKE_VERSION, TOKEN_LIKE_VERSION] {
        for check in all_runtime_builders(canary) {
            let (report, text, json) = channels(check);
            let details = report.checks[0]
                .details
                .as_deref()
                .expect("runtime details present");
            assert!(!details.contains(canary), "details disclosed {canary}");
            assert!(details.contains(PLACEHOLDER), "details carry placeholder");
            assert!(details.contains("Status: "), "wire status stays visible");
            assert!(!text.contains(canary), "text channel disclosed {canary}");
            assert!(text.contains(PLACEHOLDER));
            assert!(!json.contains(canary), "json channel disclosed {canary}");
            assert!(json.contains(PLACEHOLDER));
        }
    }
}

#[test]
fn gated_checks_keep_their_ids_and_status_tiers() {
    let expected = [
        ("runtime.ok", CheckStatus::Ok),
        ("runtime.degraded", CheckStatus::Warning),
        ("runtime.unavailable", CheckStatus::Error),
        ("runtime.shutting_down", CheckStatus::Warning),
    ];
    for (check, (id, status)) in all_runtime_builders(TOKEN_LIKE_VERSION)
        .into_iter()
        .zip(expected)
    {
        let suffix = format!("[{id}]");
        assert_eq!(check.status, status);
        assert!(check.message.ends_with(&suffix), "{}", check.message);
    }
}

#[test]
fn tailed_versions_render_numeric_core_only_in_both_channels() {
    // Slice C: only the numeric core renders; prerelease/build tails are
    // never echoed even though the wire parser accepts the full value.
    assert!(RuntimeHealth::parse(200, &payload("ok", "0.0.0-test")).is_ok());
    for check in all_runtime_builders("0.0.0-test") {
        let (_, text, json) = channels(check);
        assert!(text.contains("Version: 0.0.0"), "text lost numeric core");
        assert!(json.contains("Version: 0.0.0"), "json lost numeric core");
        assert!(!text.contains("-test"), "text echoed prerelease tail");
        assert!(!json.contains("-test"), "json echoed prerelease tail");
    }
    assert!(RuntimeHealth::parse(200, &payload("ok", "1.2.3-canary.0+build")).is_ok());
    for check in all_runtime_builders("1.2.3-canary.0+build") {
        let (_, text, json) = channels(check);
        assert!(text.contains("Version: 1.2.3"), "text lost numeric core");
        assert!(json.contains("Version: 1.2.3"), "json lost numeric core");
        assert!(!text.contains("canary.0"), "text echoed prerelease tail");
        assert!(!text.contains("+build"), "text echoed build tail");
        assert!(!json.contains("canary.0"), "json echoed prerelease tail");
        assert!(!json.contains("+build"), "json echoed build tail");
    }
}

#[test]
fn gate_mirrors_wire_bounds_and_tightens_the_shape() {
    // Parser-rejected bounds are withheld by the gate too.
    assert!(RuntimeHealth::parse(200, &payload("ok", "")).is_err());
    let details = runtime_check_ok("").details.expect("details");
    assert!(details.contains(PLACEHOLDER));
    let long = "a".repeat(65);
    assert!(RuntimeHealth::parse(200, &payload("ok", &long)).is_err());
    let details = runtime_check_ok(&long).details.expect("details");
    assert!(!details.contains(&long));
    let control = "1.2.3\nx";
    assert!(RuntimeHealth::parse(200, &payload("ok", control)).is_err());
    assert!(!runtime_check_ok(control).details.as_deref().unwrap().contains(control));
    // 64 bytes of wire-bounded shape: parser accepts, display renders only
    // the numeric core — build metadata never enters the report (regression
    // on the slice-A leak).
    let exact_64 = format!("1.2.3+{}", "a".repeat(58));
    assert_eq!(exact_64.len(), 64);
    assert!(RuntimeHealth::parse(200, &payload("ok", &exact_64)).is_ok());
    let details = runtime_check_ok(&exact_64).details.expect("details");
    assert!(details.contains("Version: 1.2.3"));
    assert!(!details.contains(&exact_64));
    // Semver shape is required, not only the charset: a parser-accepted
    // value without a leading digit or without a dot stays withheld.
    for shaped in ["no-leading-digit.1.2", "nodots-1-2-3", "1.2.3 with spaces"] {
        assert!(RuntimeHealth::parse(200, &payload("ok", shaped)).is_ok());
        assert!(!runtime_check_ok(shaped).details.as_deref().unwrap().contains(shaped));
    }
}
