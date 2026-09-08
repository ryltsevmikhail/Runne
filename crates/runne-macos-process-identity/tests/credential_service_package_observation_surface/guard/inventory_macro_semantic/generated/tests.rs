use std::path::{Path, PathBuf};

use super::*;

#[test]
fn generated_invocation_uses_preceding_lexical_definition() {
    let (definitions, parent) = parent("macro_rules! outer { () => {} } outer!();");
    let file =
        syn::parse_file("macro_rules! inner { () => { include!(\"payload.inc\"); } } inner!();")
            .unwrap();
    let invocation = item_macro(&file.items[1]);

    assert!(matches!(
        definitions.resolve_generated_invocation(&parent, &file.items, invocation),
        MacroResolution::Workspace(_)
    ));
}

#[test]
fn generated_invocation_never_uses_later_definition() {
    let (definitions, parent) = parent("macro_rules! outer { () => {} } outer!();");
    let file =
        syn::parse_file("inner!(); macro_rules! inner { () => { include!(\"payload.inc\"); } }")
            .unwrap();
    let invocation = item_macro(&file.items[0]);

    assert!(matches!(
        definitions.resolve_generated_invocation(&parent, &file.items, invocation),
        MacroResolution::Unresolved(UnresolvedReason::MissingDefinition)
    ));
}

#[test]
fn unqualified_generated_invocation_uses_exact_call_site() {
    let (definitions, parent, caller) = cross_source_parent();
    let file = syn::parse_file("inner!();").unwrap();
    let invocation = item_macro(&file.items[0]);

    let MacroResolution::Workspace(resolved) =
        definitions.resolve_generated_invocation(&parent, &file.items, invocation)
    else {
        panic!("caller macro was not resolved");
    };
    assert_eq!(resolved.definition_source, caller);
}

#[test]
fn definition_crate_marker_resolves_only_the_parent_definition_crate() {
    let (definitions, parent, _) = cross_source_parent();
    let file = syn::parse_file("__runne_definition_crate::inner!();").unwrap();
    let invocation = item_macro(&file.items[0]);

    let MacroResolution::Workspace(resolved) =
        definitions.resolve_generated_invocation(&parent, &file.items, invocation)
    else {
        panic!("definition-crate macro was not resolved");
    };
    assert_eq!(resolved.definition_source, Path::new("/helper/src/lib.rs"));
}

fn parent(source: &str) -> (MacroDefinitions, ResolvedMacroInvocation) {
    let path = Path::new("/fixture/src/lib.rs");
    let mut definitions = MacroDefinitions::default();
    definitions.extend(path, source);
    let invocation: syn::Macro = syn::parse_str("outer!()").unwrap();
    let MacroResolution::Workspace(parent) =
        definitions.resolve_invocation(path, &[], &invocation.path, &invocation.tokens)
    else {
        panic!("outer macro was not resolved");
    };
    (definitions, parent)
}

fn cross_source_parent() -> (MacroDefinitions, ResolvedMacroInvocation, PathBuf) {
    let helper = Path::new("/helper/src/lib.rs");
    let caller = PathBuf::from("/caller/src/lib.rs");
    let mut definitions = MacroDefinitions::default();
    definitions.extend(
        helper,
        "macro_rules! inner { () => {} } macro_rules! outer { () => {} }",
    );
    definitions.extend(
        &caller,
        "macro_rules! inner { () => { include!(\"caller.inc\"); } } outer!();",
    );
    let invocation: syn::Macro = syn::parse_str("outer!()").unwrap();
    let position = crate::guard::inventory_macro_collection::invocation_position(
        &definitions,
        &caller,
        &[],
        &invocation.path,
        &invocation.tokens,
    )
    .unwrap();
    let outer = definitions.items["outer"].first().unwrap();
    let MacroResolution::Workspace(parent) = MacroDefinitions::resolve_known_definition(
        outer,
        &invocation.tokens,
        &caller,
        &[],
        position,
    ) else {
        panic!("outer macro was not resolved");
    };
    (definitions, parent, caller)
}

fn item_macro(item: &syn::Item) -> &syn::Macro {
    let syn::Item::Macro(item) = item else {
        panic!("expected macro item");
    };
    &item.mac
}
