// Canary and numeric-core regressions for the `health` command output.
//
// The `health` command renders the daemon-reported `/health` version through
// the shared numeric-core display gate (`display_version` — the same helper
// as the doctor Runtime checks): only a verified `major.minor.patch` core
// reaches either channel (text and the typed JSON payload); prerelease and
// build tails, and any non-conforming value, are withheld wholesale. These
// tests drive the REAL parsing path (`RuntimeHealth::parse`) and the REAL
// formatters (`HealthInfo::from_runtime_health`, `format_health`,
// `health_command_output`, `process_outcome`) with synthetic private
// canaries only. No network, no host state, no real daemon.

use super::*;

const PLACEHOLDER: &str = "withheld (unexpected format)";

/// Wire payloads in the exact shape the runtime client parses.
fn payload(status: &str, version: &str) -> Vec<u8> {
    format!(r#"{{"status":"{status}","version":"{version}"}}"#).into_bytes()
}

/// Builds `HealthInfo` for one of the four wire states through the real
/// mapping (`from_runtime_health`), not through string surgery.
fn info(status: &str, version: &str) -> HealthInfo {
    let version = version.to_owned();
    let health = match status {
        "ok" => RuntimeHealth::Ready { version },
        "degraded" => RuntimeHealth::RecoveryBlocked { version },
        "unavailable" => RuntimeHealth::IntegrityBlocked { version },
        "shutting_down" => RuntimeHealth::ShuttingDown { version },
        _ => unreachable!(),
    };
    HealthInfo::from_runtime_health(&health)
}

/// The state-to-exit contract of the `health` command.
const STATES: [(&str, i32); 4] = [
    ("ok", 0),
    ("degraded", 1),
    ("unavailable", 1),
    ("shutting_down", 1),
];

/// The token-bearing canary passes the wire parser unchanged: the display
/// gate, not the parser, is what withholds it. Neither channel carries the
/// value or any of its fragments, in every health state, with exact text
/// and JSON payloads and the per-state exit contract (0/1) intact.
#[test]
fn token_core_canary_is_withheld_in_both_channels_across_all_states() {
    let canary = "1.sk-canary-secret";
    let parsed = RuntimeHealth::parse(200, &payload("ok", canary)).expect("wire accepts");
    let wire_version = match parsed {
        RuntimeHealth::Ready { version } => version,
        other => panic!("expected Ready, got {other:?}"),
    };
    assert_eq!(wire_version, canary, "wire must keep the raw value");

    for (status, expected_exit) in STATES {
        let text =
            process_outcome(health_command_output(&info(status, canary)), OutputFormat::Text);
        assert_eq!(text.exit_code, expected_exit, "{status}");
        assert_eq!(text.stderr, "", "{status}");
        assert_eq!(
            text.stdout,
            format!("{status} (version {PLACEHOLDER})\n"),
            "{status}"
        );

        let json =
            process_outcome(health_command_output(&info(status, canary)), OutputFormat::Json);
        assert_eq!(json.exit_code, expected_exit, "{status}");
        assert_eq!(json.stderr, "", "{status}");
        let envelope: serde_json::Value = serde_json::from_str(&json.stdout).expect("envelope");
        assert_eq!(envelope["ok"], true, "{status}");
        assert_eq!(envelope["data"]["status"], status);
        assert_eq!(envelope["data"]["healthy"], status == "ok", "{status}");
        assert_eq!(envelope["data"]["version"], PLACEHOLDER, "{status}");

        for surface in [text.stdout.as_str(), json.stdout.as_str()] {
            assert!(!surface.contains(canary), "surface disclosed {canary}");
            assert!(!surface.contains("sk-canary-secret"), "disclosed token fragment");
            assert!(!surface.contains("1.sk"), "disclosed dotted fragment");
        }
    }
}

/// Prerelease/build tails are never echoed: every channel of every state
/// renders only the numeric core while the wire parser accepts the full
/// value and the status/exit contract of each state stays intact.
#[test]
fn tails_numeric_core_only_in_both_channels_across_all_states() {
    for (canary, fragment) in [
        ("1.2.3-sk-canary-secret", "sk-canary-secret"),
        ("1.2.3+private.canary", "private.canary"),
    ] {
        assert!(
            RuntimeHealth::parse(200, &payload("ok", canary)).is_ok(),
            "wire accepts the full value"
        );
        for (status, expected_exit) in STATES {
            let text =
                process_outcome(health_command_output(&info(status, canary)), OutputFormat::Text);
            assert_eq!(text.exit_code, expected_exit, "{status}/{canary}");
            assert_eq!(text.stderr, "", "{status}/{canary}");
            assert_eq!(text.stdout, format!("{status} (version 1.2.3)\n"), "{canary}");

            let json =
                process_outcome(health_command_output(&info(status, canary)), OutputFormat::Json);
            assert_eq!(json.exit_code, expected_exit, "{status}/{canary}");
            assert_eq!(json.stderr, "", "{status}/{canary}");
            let envelope: serde_json::Value =
                serde_json::from_str(&json.stdout).expect("envelope");
            assert_eq!(envelope["ok"], true, "{status}");
            assert_eq!(envelope["data"]["status"], status, "{canary}");
            assert_eq!(envelope["data"]["healthy"], status == "ok", "{canary}");
            assert_eq!(envelope["data"]["version"], "1.2.3", "{canary}");

            for surface in [text.stdout.as_str(), json.stdout.as_str()] {
                assert!(!surface.contains(fragment), "disclosed {fragment}");
                assert!(!surface.contains(canary), "disclosed {canary}");
            }
        }
    }
}

/// Plain numeric versions — the shape the real daemon sends
/// (`env!("CARGO_PKG_VERSION")`) — render exactly as before, in both
/// channels and across all four states.
#[test]
fn plain_versions_render_as_before_across_all_states() {
    for version in ["0.1.0", "1.2.3"] {
        assert!(RuntimeHealth::parse(200, &payload("ok", version)).is_ok());
        for (status, expected_exit) in STATES {
            let text =
                process_outcome(health_command_output(&info(status, version)), OutputFormat::Text);
            assert_eq!(text.exit_code, expected_exit, "{status}/{version}");
            assert_eq!(text.stderr, "", "{status}/{version}");
            assert_eq!(text.stdout, format!("{status} (version {version})\n"));

            let json =
                process_outcome(health_command_output(&info(status, version)), OutputFormat::Json);
            assert_eq!(json.exit_code, expected_exit, "{status}/{version}");
            assert_eq!(json.stderr, "", "{status}/{version}");
            let envelope: serde_json::Value =
                serde_json::from_str(&json.stdout).expect("envelope");
            assert_eq!(envelope["data"]["version"], version, "{status}");
        }
    }
}

/// The exit-code contract of the `health` command is untouched by the
/// display gate: runtime outcomes exit 1, profile outcomes exit 3.
#[test]
fn health_error_exit_codes_unchanged() {
    assert_eq!(HealthError::ConnectionFailed.exit_code(), 1);
    assert_eq!(HealthError::HealthCheckFailed.exit_code(), 1);
    assert_eq!(HealthError::ProfileUnavailable.exit_code(), 3);
    assert_eq!(HealthError::ProfileIncompatible.exit_code(), 3);
}
