// Hermetic canary suite for the numeric-core-only `Version` display (slice C).
//
// Slice C narrowed the doctor `Version` display gate: only the verified
// numeric core (`major.minor.patch`) is rendered, prerelease/build tails are
// never echoed, and any other value is replaced wholesale by a fixed
// placeholder. These tests drive the REAL parsing path (`RuntimeHealth::parse`)
// and the REAL report formatter (`format_diagnostic_report`) for both output
// channels (text plus JSON wrapped in `SuccessEnvelope`), using synthetic
// private canaries only. No network, no host state, no real daemon.

use super::*;

const PLACEHOLDER: &str = "withheld (unexpected format)";

fn payload(status: &str, version: &str) -> Vec<u8> {
    format!(r#"{{"status":"{status}","version":"{version}"}}"#).into_bytes()
}

/// Runs one builder output through the real formatter for both channels.
fn channels(check: DiagnosticCheck) -> (DiagnosticReport, String, String) {
    let mut report = DiagnosticReport::new();
    report.add_check(check);
    let text = format_diagnostic_report(&report, OutputFormat::Text);
    let json = format_diagnostic_report(&report, OutputFormat::Json);
    let envelope =
        serde_json::to_string(&SuccessEnvelope::new(json.data_value())).expect("envelope");
    (report, text.render_text(), envelope)
}

fn all_runtime_builders(version: &str) -> Vec<DiagnosticCheck> {
    vec![
        runtime_check_ok(version),
        runtime_check_degraded(version),
        runtime_check_unavailable(version),
        runtime_check_shutting_down(version),
    ]
}

/// The token-bearing canary passes the wire parser unchanged: the display
/// gate, not the parser, is what withholds it (its dotted prefix is not a
/// numeric core). No surface carries the value or any of its fragments.
#[test]
fn non_numeric_dotted_core_passes_wire_and_is_withheld() {
    let canary = "1.sk-canary-secret";
    let health = RuntimeHealth::parse(200, &payload("ok", canary)).expect("bounds do not reject");
    match health {
        RuntimeHealth::Ready { version: parsed } => assert_eq!(parsed, canary),
        other => panic!("expected Ready, got {other:?}"),
    }
    for check in all_runtime_builders(canary) {
        let (report, text, json) = channels(check);
        let details = report.checks[0]
            .details
            .as_deref()
            .expect("runtime details present");
        for surface in [details, text.as_str(), json.as_str()] {
            assert!(!surface.contains(canary), "surface disclosed {canary}");
            assert!(!surface.contains("sk-canary-secret"), "disclosed token fragment");
            assert!(!surface.contains("1.sk"), "disclosed dotted fragment");
            assert!(surface.contains(PLACEHOLDER), "surface lacks placeholder");
        }
        assert!(details.contains("Status: "), "wire status stays visible");
    }
}

/// Prerelease/build tails are never echoed: every surface renders only the
/// numeric core while the wire parser accepts the full value.
#[test]
fn tails_are_never_rendered_numeric_core_only_in_both_channels() {
    for (canary, fragment) in [
        ("1.2.3-sk-canary-secret", "sk-canary-secret"),
        ("1.2.3+private.canary", "private.canary"),
    ] {
        assert!(RuntimeHealth::parse(200, &payload("ok", canary)).is_ok());
        for check in all_runtime_builders(canary) {
            let (report, text, json) = channels(check);
            let details = report.checks[0]
                .details
                .as_deref()
                .expect("runtime details present");
            let needle = "Version: 1.2.3";
            for surface in [details, text.as_str(), json.as_str()] {
                assert!(surface.contains(needle), "surface lost {needle}");
                assert!(!surface.contains(fragment), "surface disclosed {fragment}");
                assert!(!surface.contains(canary), "surface disclosed {canary}");
            }
        }
    }
}

/// Plain numeric versions — the shape the real daemon sends
/// (`env!("CARGO_PKG_VERSION")`) — render exactly as before.
#[test]
fn plain_versions_render_as_before() {
    for version in ["0.1.0", "1.2.3"] {
        assert!(RuntimeHealth::parse(200, &payload("ok", version)).is_ok());
        for check in all_runtime_builders(version) {
            let (_, text, json) = channels(check);
            let needle = format!("Version: {version}");
            assert!(text.contains(&needle), "text lost {needle}");
            assert!(json.contains(&needle), "json lost {needle}");
        }
    }
}
