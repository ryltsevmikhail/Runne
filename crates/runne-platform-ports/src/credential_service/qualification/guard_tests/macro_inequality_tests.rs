use super::{find_production_callers, fixture};

#[test]
fn inequality_operator_is_not_treated_as_a_bare_macro_invocation() {
    let source = fixture(
        "src/inequality_macro.rs",
        "macro_rules! compare { ($left:expr, $right:expr) => { if $left != $right { () } }; } fn run() { compare!(left, right); }",
        false,
    );

    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn qualified_left_operand_inequality_is_not_a_nested_macro_path() {
    let mut source = fixture(
        "src/qualified_inequality.rs",
        "fn run() { tokio::select! { _ = async {} => { if crate::VALUE != value { () } } } }",
        false,
    );
    source.trusted_external_roots.insert("tokio".to_owned());

    assert!(find_production_callers(&[source]).is_empty());
}
