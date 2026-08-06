use std::{fs, process::Command};

use gocode_provider_openai::canary::{
    AccountingDisposition, CanaryCandidate, CanaryIdentity, CanaryOverlay, TerminalUsage,
};

use super::fence::{Checkpoint, FenceError, Observation, OfflineCanaryFence};
use super::report::{CanaryLifecycle, LifecycleDisposition, REPORT_STATUS, ReportDisposition};
use super::tests_authority::{rendered_authority_fence_types, reserved_fence};
use super::tests_dispatch::dispatching_fence;
use super::tests_redaction::assert_markers_absent;

pub(super) const BASE: &str = "49d3bb4efb097af336c534b8c1277c49bb97e18c";
const PRICING: &str = "openai-gpt-5.5-standard-short-context-2026-07-31/1";

#[test]
fn checkpoints_are_four_distinct_pre_boundary_checks() {
    #[rustfmt::skip]
    let checkpoints = [Checkpoint::CredentialMaterialization, Checkpoint::NetworkAuthorityClaim, Checkpoint::BudgetReservationClaim, Checkpoint::PossibleDispatchBoundary];
    for (index, checkpoint) in checkpoints.iter().enumerate() {
        assert!(!checkpoints[..index].contains(checkpoint));
    }
}

#[test]
#[rustfmt::skip]
fn terminal_reconciliation_is_single_exact_and_conflict_is_permanently_uncertain() {
    let usage = TerminalUsage::new(256, 16, 0);
    let mut lifecycle = CanaryLifecycle::default();
    let mut fence = dispatching_fence();
    lifecycle.observe_terminal_after_possible_dispatch(&mut fence).expect("reserved fence is consumed before pure observation");
    let settled = lifecycle.reconcile(Some(usage), PRICING, 17_600).expect("terminal usage settles");
    assert_eq!(settled.disposition(), AccountingDisposition::Reconciled);
    assert_eq!(settled.input_tokens(), 256);
    assert_eq!(settled.output_tokens(), 16);
    assert_eq!(settled.cached_input_tokens(), 0);
    assert_eq!(settled.expected_cost_tenths(), 17_600);
    assert_eq!(settled.reserved_tenths(), 17_600);
    assert_eq!(settled.settled_tenths(), 17_600);
    assert_eq!(settled.remaining_tenths(), 0);
    assert_eq!(settled.pricing_revision(), PRICING);
    assert_eq!(settled.settlement_count(), 1);
    assert_eq!(lifecycle.disposition(), LifecycleDisposition::Terminal);
    assert_eq!(lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600).unwrap().settlement_count(), 1);
    assert!(matches!(CanaryLifecycle::default().reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600), Err(ReportDisposition::Uncertain)));
    assert!(matches!(lifecycle.reconcile(Some(TerminalUsage::new(1, 1, 0)), PRICING, 350), Err(ReportDisposition::Uncertain)));
    assert_eq!(lifecycle.disposition(), LifecycleDisposition::Uncertain);
    assert!(matches!(lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600), Err(ReportDisposition::Uncertain)));
}

#[test]
#[rustfmt::skip]
fn reconciliation_rejects_only_closed_terminal_failures() {
    for result in [reconcile_once(None, PRICING, 0), reconcile_once(Some(TerminalUsage::new(1, 1, 2)), PRICING, 0), reconcile_once(Some(TerminalUsage::new(1, 1, 0)), "other", 350), reconcile_once(Some(TerminalUsage::new(1, 1, 0)), PRICING, 351), reconcile_once(Some(TerminalUsage::new(257, 1, 0)), PRICING, 0), CanaryLifecycle::default().reject_nonterminal()] {
        assert!(matches!(result, Err(ReportDisposition::MissingUsage | ReportDisposition::NonterminalUsage | ReportDisposition::CachedUnderflow | ReportDisposition::PricingMismatch | ReportDisposition::SettlementMismatch | ReportDisposition::OverCap | ReportDisposition::Overflow | ReportDisposition::Underflow)));
    }
}

#[rustfmt::skip]
fn reconcile_once(usage: Option<TerminalUsage>, pricing: &str, reported: u64) -> Result<super::report::LifecycleReport, ReportDisposition> {
    let mut lifecycle = CanaryLifecycle::default();
    let mut fence = dispatching_fence();
    lifecycle.observe_terminal_after_possible_dispatch(&mut fence).unwrap();
    lifecycle.reconcile(usage, pricing, reported)
}

#[test]
#[rustfmt::skip]
fn ambiguous_observations_consume_witnesses_and_stay_uncertain() {
    for observation in [Observation::Cancelled, Observation::TimedOut, Observation::Disconnected, Observation::TlsAmbiguity, Observation::HttpAmbiguity, Observation::MalformedSse, Observation::MissingTerminalUsage, Observation::MissingTerminalResponse, Observation::TransportError] {
        let mut lifecycle = CanaryLifecycle::default();
        let mut fence = dispatching_fence();
        let outcome = lifecycle.observe_after_possible_dispatch(&mut fence, observation).expect("reserved fence is consumed before pure ambiguity observation");
        assert!(outcome.approvals_consumed() && outcome.attempt_consumed());
        assert_eq!(outcome.disposition(), LifecycleDisposition::Uncertain);
        assert!(!outcome.retry() && !outcome.redispatch() && !outcome.second_reservation() && !outcome.settlement());
        assert!(outcome.manual_reconciliation() && outcome.reservation_held());
        assert_eq!(lifecycle.disposition(), LifecycleDisposition::Uncertain);
        assert!(matches!(lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600), Err(ReportDisposition::Uncertain)));
    }
}

#[test]
#[rustfmt::skip]
fn second_terminal_observation_preserves_a_new_reserved_fence() {
    let mut lifecycle = CanaryLifecycle::default();
    let mut first = dispatching_fence();
    lifecycle.observe_terminal_after_possible_dispatch(&mut first).unwrap();
    let mut second = reserved_fence();
    assert!(matches!(lifecycle.observe_terminal_after_possible_dispatch(&mut second), Err(FenceError::InvalidTransition)));
    assert_eq!(second.state(), OfflineCanaryFence::BudgetReserved);
    let outcome = second.abort().unwrap();
    assert!(outcome.reservation_released() && outcome.approvals_unconsumed());
}

#[test]
fn uncertain_lifecycle_rejects_all_new_observations_before_their_fences() {
    let mut lifecycle = CanaryLifecycle::default();
    let mut first = dispatching_fence();
    lifecycle
        .observe_after_possible_dispatch(&mut first, Observation::Cancelled)
        .unwrap();
    let mut terminal = reserved_fence();
    let mut ambiguous = reserved_fence();
    assert!(matches!(
        lifecycle.observe_terminal_after_possible_dispatch(&mut terminal),
        Err(FenceError::InvalidTransition)
    ));
    assert!(matches!(
        lifecycle.observe_after_possible_dispatch(&mut ambiguous, Observation::TimedOut),
        Err(FenceError::InvalidTransition)
    ));
    assert_eq!(terminal.state(), OfflineCanaryFence::BudgetReserved);
    assert_eq!(ambiguous.state(), OfflineCanaryFence::BudgetReserved);
}

#[test]
#[rustfmt::skip]
fn settled_terminal_rejects_new_observations_without_consuming_fences() {
    let mut lifecycle = CanaryLifecycle::default();
    let mut first = dispatching_fence();
    lifecycle.observe_terminal_after_possible_dispatch(&mut first).unwrap();
    lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600).unwrap();
    let mut terminal = reserved_fence();
    let mut ambiguous = reserved_fence();
    assert!(matches!(lifecycle.observe_terminal_after_possible_dispatch(&mut terminal), Err(FenceError::InvalidTransition)));
    assert!(matches!(lifecycle.observe_after_possible_dispatch(&mut ambiguous, Observation::TimedOut), Err(FenceError::InvalidTransition)));
    assert_eq!(terminal.state(), OfflineCanaryFence::BudgetReserved);
    assert_eq!(ambiguous.state(), OfflineCanaryFence::BudgetReserved);
}

#[test]
fn one_fence_cannot_observe_two_lifecycles() {
    let mut fence = dispatching_fence();
    CanaryLifecycle::default()
        .observe_terminal_after_possible_dispatch(&mut fence)
        .unwrap();
    assert!(matches!(
        CanaryLifecycle::default().observe_terminal_after_possible_dispatch(&mut fence),
        Err(FenceError::InvalidTransition)
    ));
    assert_eq!(fence.state(), OfflineCanaryFence::Terminal);
}

#[test]
#[rustfmt::skip]
fn every_conflicting_repeat_is_sticky_but_first_invalid_evidence_is_typed() {
    for (usage, pricing, reported) in [(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_599), (Some(TerminalUsage::new(1, 1, 0)), PRICING, 350), (Some(TerminalUsage::new(256, 16, 0)), "other", 17_600), (None, PRICING, 17_600)] {
        let mut lifecycle = CanaryLifecycle::default();
        let mut fence = dispatching_fence();
        lifecycle.observe_terminal_after_possible_dispatch(&mut fence).unwrap();
        lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600).unwrap();
        assert!(matches!(lifecycle.reconcile(usage, pricing, reported), Err(ReportDisposition::Uncertain)));
        assert!(matches!(lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600), Err(ReportDisposition::Uncertain)));
    }
    assert!(matches!(
        reconcile_once(None, PRICING, 0),
        Err(ReportDisposition::MissingUsage)
    ));
}

#[test]
#[rustfmt::skip]
fn report_is_closed_offline_and_redacted() {
    assert_eq!(REPORT_STATUS, ("NOT_RUN", "NOT_ACTIVATED", "NOT_ACCESSED"));
    let mut lifecycle = CanaryLifecycle::default();
    let mut observation_fence = dispatching_fence();
    let observation = lifecycle.observe_after_possible_dispatch(&mut observation_fence, Observation::Cancelled).unwrap();
    let candidate = CanaryCandidate::prepare(CanaryIdentity::canonical(), CanaryOverlay::approved()).unwrap();
    let mut terminal_lifecycle = CanaryLifecycle::default();
    let mut terminal_fence = dispatching_fence();
    terminal_lifecycle.observe_terminal_after_possible_dispatch(&mut terminal_fence).unwrap();
    let report = terminal_lifecycle.reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 17_600).unwrap();
    let rendered = format!("{lifecycle:?}{observation:?}{report:?}{candidate:?}{:?}{:?}{:?}{:?}{:?}{}", candidate.evidence(), [Checkpoint::CredentialMaterialization, Checkpoint::NetworkAuthorityClaim, Checkpoint::BudgetReservationClaim, Checkpoint::PossibleDispatchBoundary], [LifecycleDisposition::NotRun, LifecycleDisposition::Terminal, LifecycleDisposition::Uncertain], [ReportDisposition::MissingUsage, ReportDisposition::NonterminalUsage, ReportDisposition::CachedUnderflow, ReportDisposition::Overflow, ReportDisposition::Underflow, ReportDisposition::PricingMismatch, ReportDisposition::SettlementMismatch, ReportDisposition::OverCap, ReportDisposition::Uncertain], [Observation::Cancelled, Observation::TimedOut, Observation::Disconnected, Observation::TlsAmbiguity, Observation::HttpAmbiguity, Observation::MalformedSse, Observation::MissingTerminalUsage, Observation::MissingTerminalResponse, Observation::TransportError], rendered_authority_fence_types());
    let accounting = [AccountingDisposition::MissingUsage, AccountingDisposition::NonterminalUsage, AccountingDisposition::CachedUnderflow, AccountingDisposition::Overflow, AccountingDisposition::Underflow, AccountingDisposition::PricingMismatch, AccountingDisposition::SettlementMismatch, AccountingDisposition::OverCap, AccountingDisposition::Reconciled, AccountingDisposition::Uncertain];
    assert_markers_absent(&format!("{rendered}{accounting:?}"));
}

#[test]
fn template_and_traceability_are_offline_and_contain_no_rendered_markers() {
    let template = read("docs/evidence/TASK5_OPENAI_L4_CANARY_EVIDENCE_TEMPLATE.md");
    for status in [REPORT_STATUS.0, REPORT_STATUS.1, REPORT_STATUS.2] {
        assert!(template.contains(status));
    }
    assert!(
        template
            .contains("sha256:5ebaed5023f8fe209364c76138be83f219edd9b26fd05fd010df068a0e20a72f")
    );
    assert!(!template.contains("VERIFIED"));
    assert_markers_absent(&template);
    let traceability = read("docs/traceability/TASK5_OPENAI_L4_CANARY.md");
    for requirement in 1..=31 {
        assert!(traceability.contains(&format!("| {requirement} |")));
    }
    assert_markers_absent(&traceability);
}

#[test]
#[rustfmt::skip]
fn runtime_canary_sources_have_no_dangerous_api() {
    let paths = ["crates/gocode-provider-openai/src/canary.rs", "crates/gocode-provider-openai/src/canary/contract.rs", "crates/gocode-provider-openai/src/canary/accounting.rs", "crates/gocode-daemon-openai-effect/src/offline_canary.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/authority.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/approvals.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/fence.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/report.rs"];
    let forbidden = ["reqwest::Client", "std::net", "tokio::net", "std::fs", "std::env", "NativeProviderCredentialStore", "secure_store", "keychain", ".materialize(", "production_effect(", "DispatchRequest", "ProviderEffectStartReceipt", "OpenAiEffect", "TcpStream", "TlsConnector", "LiveCallAuthorization"];
    for path in paths { for token in forbidden { assert!(!read(path).contains(token), "forbidden runtime API"); } }
}

#[test]
#[rustfmt::skip]
fn working_tree_scope_and_protected_bytes_are_exact_and_fail_closed() {
    let mut paths = git_paths(&["diff", "--name-only", BASE, "--"]);
    paths.extend(git_paths(&["ls-files", "--others", "--exclude-standard"]));
    paths.sort();
    paths.dedup();
    let mut allowed = vec!["crates/gocode-provider-openai/src/lib.rs", "crates/gocode-provider-openai/src/canary.rs", "crates/gocode-provider-openai/src/canary/contract.rs", "crates/gocode-provider-openai/src/canary/accounting.rs", "crates/gocode-provider-openai/tests/openai_l4_canary_contract.rs", "crates/gocode-daemon-openai-effect/src/lib.rs", "crates/gocode-daemon-openai-effect/src/offline_canary.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/authority.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/approvals.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/fence.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/report.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/tests_authority.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/tests_lifecycle.rs", "crates/gocode-daemon-openai-effect/src/offline_canary/tests_dispatch.rs", "docs/superpowers/specs/2026-08-05-openai-l4-canary-offline-design.md", "docs/superpowers/plans/2026-08-05-openai-l4-canary-offline.md", "docs/evidence/TASK5_OPENAI_L4_CANARY_EVIDENCE_TEMPLATE.md", "docs/traceability/TASK5_OPENAI_L4_CANARY.md", "crates/gocode-daemon-openai-effect/src/offline_canary/tests_redaction.rs"];
    allowed.sort();
    assert_eq!(paths, allowed);
    assert_registered_bytes("crates/gocode-provider-openai/src/lib.rs", "pub mod canary;\n");
    assert_registered_bytes("crates/gocode-daemon-openai-effect/src/lib.rs", "mod offline_canary;\n");
}

pub(super) fn read(path: &str) -> String {
    fs::read_to_string(format!("../../{path}")).expect("closed fixture exists")
}
fn git_paths(arguments: &[&str]) -> Vec<String> {
    let output = git(arguments);
    assert!(output.stdout.len() <= 16_384);
    let stdout = String::from_utf8(output.stdout).expect("bounded UTF-8 paths");
    let paths: Vec<_> = stdout.lines().map(ToOwned::to_owned).collect();
    assert!(
        paths.len() <= 32
            && paths
                .iter()
                .all(|path| !path.is_empty() && path.len() <= 256)
    );
    paths
}
pub(super) fn git(arguments: &[&str]) -> std::process::Output {
    let output = Command::new("git")
        .args(arguments)
        .current_dir("../..")
        .output()
        .expect("git starts");
    assert!(output.status.success() && output.stderr.is_empty());
    output
}
fn assert_registered_bytes(path: &str, registration: &str) {
    let current = read(path);
    assert_eq!(current.match_indices(registration).count(), 1);
    let normalized = current.replacen(registration, "", 1);
    let spec = format!("{BASE}:{path}");
    assert_eq!(normalized.as_bytes(), git(&["show", &spec]).stdout);
}
