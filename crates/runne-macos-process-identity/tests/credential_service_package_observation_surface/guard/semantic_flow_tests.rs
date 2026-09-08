use std::collections::BTreeMap;

use super::analyzer::{GuardVerdict, analyze_source};
use super::patterns::BindingEnvironment;
use super::provenance::{ShapeFact, TargetMethod, UnresolvedReason, ValueFact};
use super::source_model::{
    BindingId, BodyId, DefId, ModuleId, Namespace, PackageId, ScopeId, SyntaxId, TargetId,
    TypeDefId,
};
use super::symbols::MemberKey;

#[path = "semantic_flow_final_p1_tests.rs"]
mod final_p1_tests;
#[path = "semantic_flow_native_p1_tests.rs"]
mod native_p1_tests;
#[path = "semantic_flow_review_control_tests.rs"]
mod review_control_tests;
#[path = "semantic_flow_review_macro_tests.rs"]
mod review_macro_tests;
#[path = "semantic_flow_round6_tests.rs"]
mod round6_tests;

const fn owner(syntax: u32) -> TypeDefId {
    TypeDefId(DefId {
        package: PackageId(0),
        target: TargetId(0),
        module: ModuleId(0),
        namespace: Namespace::Type,
        syntax: SyntaxId(syntax),
    })
}

fn pattern(source: &str) -> syn::Pat {
    if let Ok(syn::Stmt::Local(local)) = syn::parse_str::<syn::Stmt>(&format!("let {source};")) {
        return local.pat;
    }
    let expression =
        syn::parse_str::<syn::ExprMatch>(&format!("match value {{ {source} => {{}} }}"))
            .expect("pattern must parse as a match arm");
    let Some(arm) = expression.arms.into_iter().next() else {
        panic!("pattern did not produce a match arm")
    };
    arm.pat
}

#[test]
fn recursive_pattern_projection_binds_every_supported_leaf() {
    let pending = ValueFact::TargetObject(owner(1));
    let callable = ValueFact::TargetCallable(TargetMethod::Capture);
    let holder = ValueFact::Aggregate(ShapeFact::Record {
        owner: Some(owner(2)),
        fields: BTreeMap::from([
            (MemberKey::Named("pending".into()), pending.clone()),
            (
                MemberKey::Named("parts".into()),
                ValueFact::Aggregate(ShapeFact::Tuple {
                    owner: None,
                    items: vec![callable.clone(), ValueFact::NonTarget],
                }),
            ),
        ]),
    });
    let mut environment = BindingEnvironment::new(BodyId(7), ScopeId(11));

    environment.bind_pattern(
        &pattern("Holder { pending: ref observed, parts: (invoke, _) }: Holder"),
        &holder,
    );

    assert_eq!(environment.lookup("observed"), Some(&pending));
    assert_eq!(environment.lookup("invoke"), Some(&callable));
}

#[test]
fn tuple_struct_slice_and_or_patterns_share_one_projection_rule() {
    let pending = ValueFact::TargetObject(owner(3));
    let callable = ValueFact::TargetCallable(TargetMethod::Capture);
    let tuple = ValueFact::Aggregate(ShapeFact::Tuple {
        owner: Some(owner(4)),
        items: vec![pending.clone(), callable.clone()],
    });
    let sequence = ValueFact::Aggregate(ShapeFact::Sequence {
        items: vec![tuple.clone(), tuple],
    });
    let mut environment = BindingEnvironment::new(BodyId(8), ScopeId(12));

    environment.bind_pattern(
        &pattern("[Holder(value, run), ..] | [Holder(value, run)]"),
        &sequence,
    );

    assert_eq!(environment.lookup("value"), Some(&pending));
    assert_eq!(environment.lookup("run"), Some(&callable));
}

#[test]
fn lexical_shadowing_allocates_distinct_binding_ids() {
    let mut environment = BindingEnvironment::new(BodyId(9), ScopeId(13));
    environment.bind_pattern(&pattern("holder"), &ValueFact::TargetObject(owner(5)));
    let outer = environment.binding("holder").expect("outer binding");
    environment.push_scope(ScopeId(14));
    environment.bind_pattern(&pattern("holder"), &ValueFact::NonTarget);
    let inner = environment.binding("holder").expect("inner binding");

    assert_ne!(outer, inner);
    assert_eq!(environment.lookup("holder"), Some(&ValueFact::NonTarget));
    assert_eq!(
        outer,
        BindingId {
            body: BodyId(9),
            scope: ScopeId(13),
            ordinal: 0,
        }
    );
    environment.pop_scope();
    assert!(matches!(
        environment.lookup("holder"),
        Some(ValueFact::TargetObject(_))
    ));
}

#[test]
fn branch_join_preserves_uncertainty_at_a_relevant_boundary() {
    let target = ValueFact::TargetObject(owner(6));

    assert_eq!(
        target.join(&ValueFact::NonTarget),
        ValueFact::MaybeTarget(UnresolvedReason::DivergentBranch)
    );
}

#[test]
fn recursive_unrelated_type_is_bounded_and_clean() {
    let source =
        "struct Node { next: Option<Box<Node>> } fn production(node: Node) { drop(node); }";

    assert_eq!(analyze_source(source), GuardVerdict::Clean);
}

#[test]
fn recursive_holder_back_edge_does_not_erase_target_provenance() {
    let direct = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        struct Holder { pending: Pending, next: Option<Box<Holder>> }
        fn production(holder: Holder, release: &Release) {
            let _ = holder.pending.verify_exact(release);
        }
    ";
    let recursive = direct.replace(
        "holder.pending.verify_exact",
        "holder.next.unwrap().pending.verify_exact",
    );

    assert!(matches!(analyze_source(direct), GuardVerdict::Calls(_)));
    assert!(!matches!(analyze_source(&recursive), GuardVerdict::Clean));
}

#[test]
fn mutually_recursive_type_facts_are_source_order_invariant() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        struct First { second: Box<Second> }
        struct Second { first: Box<First>, pending: Pending }
        fn production(first: First, release: &Release) {
            let _ = first.second.pending.verify_exact(release);
        }
    ";
    let reversed = source.replace(
        "struct First { second: Box<Second> }\n        struct Second { first: Box<First>, pending: Pending }",
        "struct Second { first: Box<First>, pending: Pending }\n        struct First { second: Box<Second> }",
    );

    assert!(matches!(analyze_source(source), GuardVerdict::Calls(_)));
    assert_eq!(analyze_source(source), analyze_source(&reversed));
}

#[test]
fn function_item_reference_becomes_a_call_only_at_invocation() {
    let reference = "fn production() { let _capture = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current; }";
    let invocation = reference.replace("capture_current;", "capture_current();");

    assert_eq!(analyze_source(reference), GuardVerdict::Clean);
    assert!(matches!(analyze_source(&invocation), GuardVerdict::Calls(sites) if sites.len() == 1));
}

#[test]
fn opaque_external_target_shaped_invocation_is_inconclusive() {
    let source =
        "use opaque::HiddenPending; fn production() { let _ = HiddenPending::capture_current(); }";

    assert!(matches!(
        analyze_source(source),
        GuardVerdict::Inconclusive(sites) if !sites.is_empty()
    ));
}

#[test]
fn opaque_external_receiver_invocation_is_inconclusive() {
    let source = "use opaque::HiddenPending; fn production(pending: HiddenPending, release: &runne_api::VerifiedSignedInstalledReleaseV2) { let _ = pending.verify_exact(release); }";

    assert!(matches!(
        analyze_source(source),
        GuardVerdict::Inconclusive(sites) if !sites.is_empty()
    ));
}

#[test]
fn unresolved_item_macro_with_target_argument_is_inconclusive() {
    let target = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        opaque!(Pending::capture_current);
    ";
    let unrelated = "opaque!(42);";

    assert!(matches!(
        analyze_source(target),
        GuardVerdict::Inconclusive(sites) if !sites.is_empty()
    ));
    assert!(matches!(
        analyze_source(unrelated),
        GuardVerdict::Inconclusive(sites) if !sites.is_empty()
    ));
}

#[test]
fn unresolved_expression_macro_with_opaque_unrelated_argument_is_clean() {
    let source = r"
        enum State { Live }
        fn production(state: Result<State, ()>) {
            let _ = matches!(state, Ok(State::Live));
        }
    ";

    assert_eq!(analyze_source(source), GuardVerdict::Clean);
}

#[test]
fn qself_and_expression_macro_bindings_keep_target_provenance() {
    let capture = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        macro_rules! capture { ($path:path) => { <$path>::capture_current() } }
        fn production() { let _ = capture!(Pending); }
    ";
    let verify = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        type Alias = Pending;
        macro_rules! verify { ($pending:expr, $release:expr) => { $pending.verify_exact($release) } }
        fn production(pending: Alias, release: &Release) { let _ = verify!(pending, release); }
    ";
    let capture_verdict = analyze_source(capture);
    assert!(
        matches!(&capture_verdict, GuardVerdict::Calls(calls) if calls.len() == 1),
        "{capture_verdict:?}"
    );
    let verdict = analyze_source(verify);
    assert!(
        matches!(&verdict, GuardVerdict::Calls(calls) if calls.len() == 1),
        "{verdict:?}"
    );
}
