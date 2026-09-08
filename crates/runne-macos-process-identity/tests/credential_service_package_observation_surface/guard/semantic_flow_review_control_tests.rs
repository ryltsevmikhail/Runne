use super::super::analyzer::{GuardVerdict, analyze_source};
use super::super::semantic_acceptance_support::assert_compiles;

const PRELUDE: &str = r"
use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
use runne_macos_process_identity::MacOsCredentialServicePackageObservationError as Error;
use runne_api::VerifiedSignedInstalledReleaseV2 as Release;
type Capture = fn() -> Result<Pending, Error>;
";

fn assert_calls(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    let verdict = analyze_source(&source);
    assert!(
        matches!(verdict, GuardVerdict::Calls(ref calls) if !calls.is_empty()),
        "{name} must preserve the protected invocation: {verdict:?}"
    );
}

fn assert_non_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert!(!matches!(analyze_source(&source), GuardVerdict::Clean));
}

fn assert_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert_eq!(analyze_source(&source), GuardVerdict::Clean, "{name}");
}

#[test]
fn let_else_diverge_and_async_descendants_are_analyzed() {
    assert_calls(
        r"fn production(value: Option<()>) {
            let Some(()) = value else { let _ = Pending::capture_current(); return; };
        }",
        "flow_review_let_else",
    );
    assert_calls(
        "fn production() { let _future = async move { let _ = Pending::capture_current(); }; }",
        "flow_review_async",
    );
}

#[test]
fn early_return_is_not_overwritten_by_unreachable_tail() {
    assert_calls(
        r"#[allow(unreachable_code)]
        fn pick() -> Capture { return Pending::capture_current; unreachable!() }
        fn production() { let _ = pick()(); }",
        "flow_review_early_return",
    );
}

#[test]
fn if_and_while_let_shadowing_do_not_erase_outer_callable() {
    assert_calls(
        r"fn production() {
            let capture = Pending::capture_current;
            if let Some(capture) = Some(|| ()) { capture(); }
            let _ = capture();
        }",
        "flow_review_if_let_shadow",
    );
    assert_calls(
        r"fn production(mut item: Option<fn()>) {
            let capture = Pending::capture_current;
            while let Some(capture) = item.take() { capture(); }
            let _ = capture();
        }",
        "flow_review_while_let_shadow",
    );
}

#[test]
fn rest_patterns_project_suffix_from_the_source_end() {
    assert_calls(
        r"fn production() {
            let values = (0_u8, 1_u16, || (), Pending::capture_current);
            let (_, .., capture) = values;
            let _ = capture();
        }",
        "flow_review_tuple_rest",
    );
    assert_calls(
        r"fn production() {
            fn unrelated() -> Result<Pending, Error> { panic!() }
            let values: [Capture; 3] = [unrelated, unrelated, Pending::capture_current];
            let [_, .., capture] = values;
            let _ = capture();
        }",
        "flow_review_slice_rest",
    );
}

#[test]
fn callable_effects_survive_aliases_closures_and_methods() {
    assert_calls(
        r"fn invoke(capture: Capture) { let _ = capture(); }
        fn production() { let alias = invoke; alias(Pending::capture_current); }",
        "flow_review_callable_alias",
    );
    assert_calls(
        r"fn production() {
            let invoke = |capture: Capture| { let _ = capture(); };
            invoke(Pending::capture_current);
        }",
        "flow_review_closure",
    );
    assert_calls(
        r"struct Runner;
        impl Runner { fn invoke(self, capture: Capture) { let _ = capture(); } }
        fn production() { Runner.invoke(Pending::capture_current); }",
        "flow_review_method",
    );
}

#[test]
fn generic_identity_and_method_transformations_preserve_carriers() {
    assert_calls(
        r"fn identity<T>(value: T) -> T { value }
        fn production(pending: Pending, release: &Release) {
            let _ = identity(pending).verify_exact(release);
        }",
        "flow_review_generic_identity",
    );
    assert_non_clean(
        r"fn production(pending: Pending, release: &Release) {
            let mut values = Some(pending).into_iter();
            let _ = values.next().unwrap().verify_exact(release);
        }",
        "flow_review_method_transform",
    );
}

#[test]
fn rootless_recursive_scc_is_clean_at_macro_boundary() {
    let source = r"
        struct Node { next: Option<Box<Node>> }
        fn inspect(node: Node) { let _ = matches!(node.next, None); }
    ";
    assert_compiles(source, "flow_review_rootless_scc");
    assert_eq!(analyze_source(source), GuardVerdict::Clean);
}

#[test]
fn callable_effects_cover_direct_closure_associated_field_and_recursion() {
    assert_calls(
        "fn production() { let _deferred = || { let _ = Pending::capture_current(); }; }",
        "flow_review_direct_closure_body",
    );
    assert_calls(
        r"struct Runner;
        impl Runner { fn invoke(capture: Capture) { let _ = capture(); } }
        fn production() { Runner::invoke(Pending::capture_current); }",
        "flow_review_associated_function",
    );
    assert_calls(
        r"struct Runner { invoke: fn(Capture) }
        fn invoke(capture: Capture) { let _ = capture(); }
        fn production() {
            let runner = Runner { invoke };
            let _ = (runner.invoke)(Pending::capture_current);
        }",
        "flow_review_callable_field",
    );
    assert_calls(
        r"fn invoke(capture: Capture, depth: usize) {
            if depth == 0 { let _ = capture(); } else { invoke(capture, depth - 1); }
        }
        fn production() { invoke(Pending::capture_current, 1); }",
        "flow_review_recursive_callable",
    );
}

#[test]
fn storing_or_returning_callable_parameters_does_not_fabricate_calls() {
    assert_clean(
        r"fn store(capture: Capture) -> Capture { capture }
        fn production() { let _stored = store(Pending::capture_current); }",
        "flow_review_store_parameter",
    );
    assert_clean(
        r"fn production() {
            let store = |capture: Capture| capture;
            let _stored = store(Pending::capture_current);
        }",
        "flow_review_store_closure_parameter",
    );
    assert_clean(
        r"struct Runner;
        impl Runner { fn store(self, capture: Capture) -> Capture { capture } }
        fn production() { let _stored = Runner.store(Pending::capture_current); }",
        "flow_review_store_method_parameter",
    );
}
