use super::super::analyzer::{GuardVerdict, analyze_source};
use super::super::semantic_acceptance_support::assert_compiles;

const PRELUDE: &str = r"
use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
use runne_macos_process_identity::MacOsCredentialServicePackageObservationError as Error;
type Capture = fn() -> Result<Pending, Error>;
";

fn assert_non_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert!(
        !matches!(analyze_source(&source), GuardVerdict::Clean),
        "{name}: {:?}",
        analyze_source(&source)
    );
}

fn assert_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert_eq!(analyze_source(&source), GuardVerdict::Clean, "{name}");
}

#[test]
fn nested_binding_and_multi_element_pattern_macros_preserve_calls() {
    assert_non_clean(
        r"macro_rules! bind { ($pattern:pat) => { Some($pattern) } }
          fn production() {
              if let _whole @ bind!(capture) = Some(Pending::capture_current) {
                  let _ = capture();
              }
          }",
        "round6_binding_at_macro",
    );
    assert_non_clean(
        r"macro_rules! bind { ($pattern:pat) => { $pattern } }
          fn production() {
              let (bind!(first), bind!(second)) =
                  (Pending::capture_current, Pending::capture_current);
              let _ = first();
              let _ = second();
              let [bind!(third), bind!(fourth)] =
                  [Pending::capture_current, Pending::capture_current];
              let _ = third();
              let _ = fourth();
          }",
        "round6_multi_element_patterns",
    );
    assert_clean(
        r"macro_rules! bind { ($pattern:pat) => { Some($pattern) } }
          fn production() {
              if let _whole @ bind!(_stored) = Some(Pending::capture_current) {}
          }",
        "round6_binding_at_control",
    );
}

#[test]
fn dependent_let_chains_preserve_previous_binding_facts() {
    assert_non_clean(
        "fn production() { if let Some(first) = Some(Pending::capture_current) && let Some(second) = Some(first) { let _ = second(); } }",
        "round6_if_let_chain",
    );
    assert_non_clean(
        "fn production() { let mut once = Some(Pending::capture_current); while let Some(first) = once.take() && let Some(second) = Some(first) { let _ = second(); break; } }",
        "round6_while_let_chain",
    );
    assert_clean(
        "fn production() { if let Some(_first) = Some(Pending::capture_current) && let Some(_second) = Some(()) {} }",
        "round6_let_chain_control",
    );
}

#[test]
fn unresolved_local_value_carriers_fail_closed() {
    assert_non_clean(
        r"mod helper { use super::Capture; pub fn invoke(callback: Capture) { let _ = callback(); } }
          mod reexport { pub use super::helper::invoke; }
          use reexport::invoke;
          fn production() { invoke(Pending::capture_current); }",
        "round6_reexported_callback",
    );
    assert_non_clean(
        r"macro_rules! generate { () => { fn invoke(callback: Capture) { let _ = callback(); } } }
          generate!();
          fn production() { invoke(Pending::capture_current); }",
        "round6_generated_function_callback",
    );
    assert_non_clean(
        r"macro_rules! generate { () => { const CAPTURE: Capture = Pending::capture_current; } }
          generate!();
          fn production() { let _ = CAPTURE(); }",
        "round6_generated_const_carrier",
    );
    assert_clean(
        r"macro_rules! generate { () => { const STORED: Capture = Pending::capture_current; } }
          generate!();
          fn production() {}",
        "round6_generated_store_control",
    );
}

#[test]
fn local_glob_reexports_of_receivers_fail_closed() {
    let source = r"
use runne_api::VerifiedSignedInstalledReleaseV2 as Release;
mod identities {
    pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
}
use identities::*;
pub fn production(pending: Pending, release: &Release) { let _ = pending.verify_exact(release); }
";
    assert_compiles(source, "round6_globbed_receiver");
    assert!(
        !matches!(analyze_source(source), GuardVerdict::Clean),
        "round6_globbed_receiver: {:?}",
        analyze_source(source)
    );
}
