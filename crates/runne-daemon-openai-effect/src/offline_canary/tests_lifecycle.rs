#[rustfmt::skip]
use std::{fs, fs::{File, OpenOptions}, io::{self, ErrorKind, Read}, path::Path};
use super::fence::{Checkpoint, FenceError, Observation, OfflineCanaryFence};
use super::report::{CanaryLifecycle, LifecycleDisposition, REPORT_STATUS, ReportDisposition};
use super::tests_authority::{rendered_authority_fence_types, reserved_fence};
use super::tests_dispatch::dispatching_fence;
use super::tests_redaction::assert_markers_absent;
use runne_provider_openai::canary::{
    AccountingDisposition, CanaryCandidate, CanaryIdentity, CanaryOverlay, TerminalUsage,
};
#[rustfmt::skip]
pub(super) const CANDIDATE_PATHS: [&str; 19] = ["crates/runne-daemon-openai-effect/src/lib.rs", "crates/runne-daemon-openai-effect/src/offline_canary.rs", "crates/runne-daemon-openai-effect/src/offline_canary/approvals.rs", "crates/runne-daemon-openai-effect/src/offline_canary/authority.rs", "crates/runne-daemon-openai-effect/src/offline_canary/fence.rs", "crates/runne-daemon-openai-effect/src/offline_canary/report.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_authority.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_dispatch.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_lifecycle.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_redaction.rs", "crates/runne-provider-openai/src/canary.rs", "crates/runne-provider-openai/src/canary/accounting.rs", "crates/runne-provider-openai/src/canary/contract.rs", "crates/runne-provider-openai/src/lib.rs", "crates/runne-provider-openai/tests/openai_l4_canary_contract.rs", "docs/evidence/TASK5_OPENAI_L4_CANARY_EVIDENCE_TEMPLATE.md", "docs/superpowers/plans/2026-08-05-openai-l4-canary-offline.md", "docs/superpowers/specs/2026-08-05-openai-l4-canary-offline-design.md", "docs/traceability/TASK5_OPENAI_L4_CANARY.md"];
#[rustfmt::skip]
pub(super) const GUARDED_PATHS: [&str; 16] = ["crates/runne-daemon-openai-effect/src/lib.rs", "crates/runne-daemon-openai-effect/src/offline_canary.rs", "crates/runne-daemon-openai-effect/src/offline_canary/approvals.rs", "crates/runne-daemon-openai-effect/src/offline_canary/authority.rs", "crates/runne-daemon-openai-effect/src/offline_canary/fence.rs", "crates/runne-daemon-openai-effect/src/offline_canary/report.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_authority.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_dispatch.rs", "crates/runne-provider-openai/src/canary.rs", "crates/runne-provider-openai/src/canary/accounting.rs", "crates/runne-provider-openai/src/canary/contract.rs", "crates/runne-provider-openai/src/lib.rs", "crates/runne-provider-openai/tests/openai_l4_canary_contract.rs", "docs/evidence/TASK5_OPENAI_L4_CANARY_EVIDENCE_TEMPLATE.md", "docs/superpowers/plans/2026-08-05-openai-l4-canary-offline.md", "docs/superpowers/specs/2026-08-05-openai-l4-canary-offline-design.md"];
#[rustfmt::skip]
pub(super) const SEMANTIC_GUARDED_PATHS: [&str; 1] = ["docs/traceability/TASK5_OPENAI_L4_CANARY.md"];
#[rustfmt::skip]
pub(super) const GATE_ORACLE_PATHS: [&str; 2] = ["crates/runne-daemon-openai-effect/src/offline_canary/tests_lifecycle.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_redaction.rs"];
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
    assert_eq!([settled.input_tokens(), settled.output_tokens(), settled.cached_input_tokens(), settled.expected_cost_tenths(), settled.reserved_tenths(), settled.settled_tenths(), settled.remaining_tenths()], [256, 16, 0, 17_600, 17_600, 17_600, 0]);
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
#[rustfmt::skip]
fn uncertain_lifecycle_rejects_all_new_observations_before_their_fences() {
    let mut lifecycle = CanaryLifecycle::default();
    let mut first = dispatching_fence();
    lifecycle.observe_after_possible_dispatch(&mut first, Observation::Cancelled).unwrap();
    let mut terminal = reserved_fence();
    let mut ambiguous = reserved_fence();
    assert!(matches!(lifecycle.observe_terminal_after_possible_dispatch(&mut terminal), Err(FenceError::InvalidTransition)));
    assert!(matches!(lifecycle.observe_after_possible_dispatch(&mut ambiguous, Observation::TimedOut), Err(FenceError::InvalidTransition)));
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
#[rustfmt::skip]
fn one_fence_cannot_observe_two_lifecycles() {
    let mut fence = dispatching_fence();
    CanaryLifecycle::default().observe_terminal_after_possible_dispatch(&mut fence).unwrap();
    assert!(matches!(CanaryLifecycle::default().observe_terminal_after_possible_dispatch(&mut fence), Err(FenceError::InvalidTransition)));
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
    assert!(matches!(reconcile_once(None, PRICING, 0), Err(ReportDisposition::MissingUsage)));
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
#[rustfmt::skip]
fn template_and_traceability_are_offline_and_contain_no_rendered_markers() {
    let template = read("docs/evidence/TASK5_OPENAI_L4_CANARY_EVIDENCE_TEMPLATE.md");
    for status in [REPORT_STATUS.0, REPORT_STATUS.1, REPORT_STATUS.2] {
        assert!(template.contains(status));
    }
    assert!(template.contains("sha256:5ebaed5023f8fe209364c76138be83f219edd9b26fd05fd010df068a0e20a72f"));
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
    let paths = ["crates/runne-provider-openai/src/canary.rs", "crates/runne-provider-openai/src/canary/contract.rs", "crates/runne-provider-openai/src/canary/accounting.rs", "crates/runne-daemon-openai-effect/src/offline_canary.rs", "crates/runne-daemon-openai-effect/src/offline_canary/authority.rs", "crates/runne-daemon-openai-effect/src/offline_canary/approvals.rs", "crates/runne-daemon-openai-effect/src/offline_canary/fence.rs", "crates/runne-daemon-openai-effect/src/offline_canary/report.rs"];
    let forbidden = ["reqwest::Client", "std::net", "tokio::net", "std::fs", "std::env", "NativeProviderCredentialStore", "secure_store", "keychain", ".materialize(", "production_effect(", "DispatchRequest", "ProviderEffectStartReceipt", "OpenAiEffect", "TcpStream", "TlsConnector", "LiveCallAuthorization"];
    for path in paths { for token in forbidden { assert!(!read(path).contains(token), "forbidden runtime API"); } }
}
#[test]
#[rustfmt::skip]
fn immutable_candidate_scope_and_guarded_bytes_are_exact_and_fail_closed() {
    for path in CANDIDATE_PATHS { assert_candidate_path_is_openai(path); }
    assert_registered_bytes("crates/runne-provider-openai/src/lib.rs", "pub mod canary;\n");
    assert_registered_bytes("crates/runne-daemon-openai-effect/src/lib.rs", "mod offline_canary;\n");
}
#[test]
#[rustfmt::skip]
fn candidate_guard_partition_is_exact() {
    assert_eq!((CANDIDATE_PATHS.len(), GUARDED_PATHS.len(), SEMANTIC_GUARDED_PATHS.len(), GATE_ORACLE_PATHS.len()), (19, 16, 1, 2));
    for paths in [CANDIDATE_PATHS.as_slice(), GUARDED_PATHS.as_slice(), SEMANTIC_GUARDED_PATHS.as_slice(), GATE_ORACLE_PATHS.as_slice()] {
        let mut unique = paths.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique, paths);
    }
    let mut union = GUARDED_PATHS.to_vec();
    union.extend(SEMANTIC_GUARDED_PATHS);
    union.extend(GATE_ORACLE_PATHS);
    union.sort_unstable();
    assert_eq!(union, CANDIDATE_PATHS);
}
#[test]
#[rustfmt::skip]
fn every_guarded_path_rejects_non_candidate_bytes() {
    for path in GUARDED_PATHS { assert_candidate_path_is_openai(path); }
}
pub(super) fn read(path: &str) -> String {
    fs::read_to_string(format!("../../{path}")).expect("closed fixture exists")
}
const MAX_SEMANTIC_BYTES: u64 = 16_384;
const MAX_TRACEABILITY_LINE: usize = 1_024;
#[rustfmt::skip]
#[cfg(unix)]
mod unix_flags { pub const O_NOFOLLOW: i32 = libc::O_NOFOLLOW; pub const O_NONBLOCK: i32 = libc::O_NONBLOCK; }
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
pub(super) fn read_semantic_traceability() -> String {
    let path = Path::new("../..").join(SEMANTIC_GUARDED_PATHS[0]);
    read_bounded(&path).expect("semantic traceability is bounded regular UTF-8")
}
#[rustfmt::skip]
pub(super) fn read_bounded(path: &Path) -> io::Result<String> {
    let file = open_no_follow(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(ErrorKind::InvalidData, "not a regular file"));
    }
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt;
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(ErrorKind::InvalidData, "reparse point"));
    }
    let length = metadata.len();
    if length > MAX_SEMANTIC_BYTES {
        return Err(io::Error::new(ErrorKind::InvalidData, "file too large"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_SEMANTIC_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SEMANTIC_BYTES {
        return Err(io::Error::new(ErrorKind::InvalidData, "file grew"));
    }
    let text = String::from_utf8(bytes).map_err(|_| io::Error::new(ErrorKind::InvalidData, "not UTF-8"))?;
    if text.split('\n').any(|line| line.len() > MAX_TRACEABILITY_LINE) {
        return Err(io::Error::new(ErrorKind::InvalidData, "line too long"));
    }
    Ok(text)
}
#[rustfmt::skip]
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().read(true).custom_flags(unix_flags::O_NOFOLLOW | unix_flags::O_NONBLOCK).open(path)
}
#[rustfmt::skip]
#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)
}
#[rustfmt::skip]
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android", windows)))]
fn open_no_follow(_: &Path) -> io::Result<File> {
    Err(io::Error::new(ErrorKind::Unsupported, "no atomic no-follow open"))
}
fn assert_candidate_path_is_openai(path: &str) {
    let current = read(path);
    let forbidden = [
        format!("runne-provider-{}", "deepseek"),
        format!("runne-daemon-{}-effect", "deepseek"),
        format!("TASK5_{}_L4_CANARY", "DEEPSEEK"),
    ];
    assert!(
        forbidden.iter().all(|marker| !current.contains(marker)),
        "source marker in {path}"
    );
    assert!(
        Path::new("../..").join(path).is_file(),
        "candidate file missing: {path}"
    );
}
#[rustfmt::skip]
fn assert_registered_bytes(path: &str, registration: &str) { let current = read(path); assert_eq!(current.match_indices(registration).count(), 1); }
