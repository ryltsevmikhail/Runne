//! Audits the audited writer-stage diagnostics capacity: the emission
//! allowance is bound to the exact feature-gated live twin, the vocabulary
//! stays closed and argument-free, and the silent twin stays sink-free.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{Item, ItemFn, ItemMod};

use super::BROKER_SOURCE;
use super::disclosure_sink_audit::{
    audited_stage_module_sink_violations, broker_disclosure_sink_violations,
    disclosure_sink_violations,
};
use super::disclosure_stage_binding::{audited_stage_emissions, stage_module_binding};

const LIVE_SOURCE: &str =
    include_str!("../../src/cli/provider_credential_broker/writer_stage_live.rs");
const SILENT_SOURCE: &str =
    include_str!("../../src/cli/provider_credential_broker/writer_stage_silent.rs");
const LIVE_DECLARATION: &str = "#[cfg(feature = \"local-native-enrollment-test\")]\n#[path = \"provider_credential_broker/writer_stage_live.rs\"]\nmod writer_stage;";
const SILENT_DECLARATION: &str = "#[cfg(not(feature = \"local-native-enrollment-test\"))]\n#[path = \"provider_credential_broker/writer_stage_silent.rs\"]\nmod writer_stage;";

fn replace_once(source: &str, old: &str, new: &str) -> String {
    assert_eq!(source.matches(old).count(), 1, "fixture drift for {old}");
    source.replacen(old, new, 1)
}

#[test]
fn live_stage_module_is_clean_under_its_binding() {
    assert!(
        audited_stage_module_sink_violations(
            "provider_credential_broker/writer_stage_live.rs",
            LIVE_SOURCE
        )
        .is_empty()
    );
}

#[test]
fn silent_stage_module_has_no_sink_at_all() {
    assert!(!SILENT_SOURCE.contains("eprintln"));
    assert!(
        disclosure_sink_violations(
            "provider_credential_broker/writer_stage_silent.rs",
            SILENT_SOURCE
        )
        .is_empty()
    );
}

#[test]
fn audited_literals_stay_rejected_outside_the_audited_module() {
    for literal in audited_stage_emissions() {
        let source = format!("fn unrelated() {{ eprintln!(\"{literal}\"); }}");
        let violations =
            disclosure_sink_violations("provider_credential_broker/channel.rs", &source);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("print macro")),
            "audited literal escaped outside the audited module: {violations:#?}"
        );
    }
}

#[test]
fn emission_mutations_are_rejected_even_inside_the_audited_module() {
    for source in [
        "fn f(stage: &str) { eprintln!(\"writer-stage={stage}\"); }",
        "fn f() { eprintln!(\"writer-stage=attacker-stage\"); }",
        "fn f() { println!(\"writer-stage=secret-inspect\"); }",
        "fn f() { eprintln!(); }",
        "fn f() { eprintln!(\"writer-stage=secret-inspect\", 1); }",
        "fn f() { eprintln!(concat!(\"writer-stage=\", \"secret-inspect\")); }",
    ] {
        let violations = audited_stage_module_sink_violations("writer_stage_live.rs", source);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("print macro")),
            "emission mutation escaped the audited module scan: {violations:#?}"
        );
    }
}

#[test]
fn broken_cfg_or_path_binding_disables_the_allowance() {
    let cases = [
        replace_once(
            BROKER_SOURCE,
            "#[cfg(feature = \"local-native-enrollment-test\")]",
            "#[cfg(any())]",
        ),
        replace_once(
            BROKER_SOURCE,
            "#[cfg(not(feature = \"local-native-enrollment-test\"))]",
            "#[cfg(feature = \"local-native-enrollment-test\")]",
        ),
        replace_once(
            BROKER_SOURCE,
            "#[path = \"provider_credential_broker/writer_stage_live.rs\"]",
            "#[path = \"provider_credential_broker/writer_stage_silent.rs\"]",
        ),
        BROKER_SOURCE.replace(SILENT_DECLARATION, ""),
        replace_once(
            BROKER_SOURCE,
            LIVE_DECLARATION,
            &LIVE_DECLARATION.replace("mod writer_stage;", "mod stage_diag;"),
        ),
    ];
    for source in cases {
        let (violations, bound) = stage_module_binding(&source);
        assert!(
            !violations.is_empty() && bound.is_none(),
            "broken writer_stage binding passed: {violations:#?}"
        );
    }
}

#[test]
fn stage_marker_moved_into_an_unrelated_production_module_is_rejected() {
    let directory = tempfile::tempdir().expect("policy fixture");
    let root = directory.path().join("broker.rs");
    let modules = directory.path().join("broker");
    std::fs::create_dir(&modules).expect("module directory");
    std::fs::write(
        &root,
        format!("{LIVE_DECLARATION}\n{SILENT_DECLARATION}\nmod other;"),
    )
    .expect("broker fixture");
    std::fs::write(
        modules.join("writer_stage_live.rs"),
        "pub(super) fn secret_inspect() { eprintln!(\"writer-stage=secret-inspect\"); }",
    )
    .expect("live fixture");
    std::fs::write(modules.join("writer_stage_silent.rs"), "").expect("silent fixture");
    std::fs::write(
        modules.join("other.rs"),
        "pub(super) fn unrelated() { eprintln!(\"writer-stage=secret-inspect\"); }",
    )
    .expect("unrelated fixture");

    let violations = broker_disclosure_sink_violations(&root);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("other.rs") && violation.contains("print macro")),
        "marker moved into an unrelated module escaped: {violations:#?}"
    );
}

#[test]
fn audited_vocabulary_matches_the_live_module_exactly() {
    let mut emissions = Vec::new();
    EmissionCollector {
        literals: &mut emissions,
    }
    .visit_file(&syn::parse_file(LIVE_SOURCE).expect("live twin parses"));
    assert_eq!(emissions.len(), audited_stage_emissions().len());
    let live: BTreeSet<String> = emissions.iter().cloned().collect();
    let audited: BTreeSet<String> = audited_stage_emissions()
        .iter()
        .map(|literal| (*literal).to_owned())
        .collect();
    assert_eq!(live, audited, "live twin vocabulary drifted from the audit");
}

#[test]
fn live_and_silent_twins_expose_identical_stage_functions() {
    let live = stage_function_names(LIVE_SOURCE);
    let silent = stage_function_names(SILENT_SOURCE);
    assert_eq!(live.len(), 8, "live twin must expose eight stage functions");
    assert_eq!(live, silent, "twins must stay call-compatible");
}

struct EmissionCollector<'a> {
    literals: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for EmissionCollector<'_> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("eprintln") {
            self.literals.push(
                syn::parse2::<syn::LitStr>(node.tokens.clone())
                    .map(|literal| literal.value())
                    .unwrap_or_default(),
            );
        }
        visit::visit_macro(self, node);
    }
}

fn stage_function_names(source: &str) -> BTreeSet<String> {
    let file = syn::parse_file(source).expect("stage twin parses");
    let mut names: Vec<String> = Vec::new();
    for item in &file.items {
        if let Item::Fn(ItemFn { sig, .. }) = item {
            names.push(sig.ident.to_string());
        } else if let Item::Mod(ItemMod {
            content: Some((_, items)),
            ..
        }) = item
        {
            for nested in items {
                if let Item::Fn(ItemFn { sig, .. }) = nested {
                    names.push(sig.ident.to_string());
                }
            }
        }
    }
    names.sort();
    names.into_iter().collect()
}
