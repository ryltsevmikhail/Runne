use crate::guard::semantic_index::{Resolution, SemanticIndex};
use crate::guard::source_edge_macros::MacroResolution;
use crate::guard::symbols::{BodySyntax, TypeKind, ValueKind};

#[test]
fn production_duplicate_macro_keeps_definition_scope_and_target_alias() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        macro_rules! emit { () => { let _ = Pending::capture_current(); } }
        fn hidden() { #[cfg(test)] emit!(); }
        fn production() { #[cfg(not(test))] emit!(); }
    ";
    let index = SemanticIndex::from_source(source).unwrap();
    let body = index
        .values()
        .find_map(|value| {
            (value.name == "production")
                .then_some(&value.kind)
                .and_then(|kind| match kind {
                    ValueKind::Function { body } => body.and_then(|id| index.body_record(id)),
                    ValueKind::Const { .. } | ValueKind::Static { .. } => None,
                })
        })
        .unwrap();
    let BodySyntax::Function { block, .. } = body.syntax_tree.as_ref() else {
        panic!("production must have a function body");
    };
    let syn::Stmt::Macro(statement) = &block.stmts[0] else {
        panic!("production must invoke emit");
    };
    let MacroResolution::Workspace(resolved) = index.resolve_macro(body.scope, &statement.mac)
    else {
        panic!("production emit must resolve");
    };
    let scope = resolved.analysis_scope.expect("definition scope");
    let path: syn::Path = syn::parse_str("Pending").unwrap();
    let Resolution::Exact(id) = index.resolve_type(scope, &path) else {
        panic!("Pending alias must resolve exactly");
    };
    assert!(matches!(
        index.type_record(id).unwrap().kind,
        TypeKind::CanonicalTarget
    ));
}

#[test]
fn indistinguishable_active_invocations_fail_closed_across_redefinition() {
    let source = r"
        macro_rules! emit { () => {} }
        fn first() { emit!(); }
        macro_rules! emit { () => { let _ = 1; } }
        fn second() { emit!(); }
    ";
    let index = SemanticIndex::from_source(source).unwrap();
    let resolutions = index
        .values()
        .filter(|value| matches!(value.name.as_str(), "first" | "second"))
        .map(|value| {
            let ValueKind::Function { body: Some(id) } = value.kind else {
                panic!("fixture function omitted its body");
            };
            let body = index.body_record(id).unwrap();
            let BodySyntax::Function { block, .. } = body.syntax_tree.as_ref() else {
                panic!("fixture value must be a function");
            };
            let syn::Stmt::Macro(statement) = &block.stmts[0] else {
                panic!("fixture function must invoke emit");
            };
            index.resolve_macro(body.scope, &statement.mac)
        })
        .collect::<Vec<_>>();
    assert_eq!(resolutions.len(), 2);
    assert!(resolutions.iter().all(|resolution| matches!(
        resolution,
        MacroResolution::Unresolved(
            crate::guard::source_edge_macros::UnresolvedReason::MissingDefinition
        )
    )));
}
