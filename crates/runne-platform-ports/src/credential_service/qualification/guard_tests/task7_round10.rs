use super::{find_production_callers, fixture};

#[test]
fn macro_bodies_cannot_generate_imports_that_spoof_trusted_roots() {
    let qualified_macro = fixture(
        "src/generated_macro_import.rs",
        "macro_rules! outer { () => {{ use external_proc as serde_json; serde_json::json!(); }} } fn release() { outer!(); }",
        false,
    );
    let qualified_derive = fixture(
        "src/generated_derive_import.rs",
        "macro_rules! outer { () => {{ use external_proc as serde; #[derive(serde::Serialize)] struct Generated; }} } fn release() { outer!(); }",
        false,
    );
    assert_eq!(
        find_production_callers(&[qualified_macro, qualified_derive]).len(),
        2
    );
}
#[test]
fn macro_import_keywords_from_metavariables_fail_closed() {
    let mut ident = fixture(
        "src/ident_import.rs",
        "macro_rules! outer { ($keyword:ident) => {{ $keyword external_proc as serde_json; serde_json::json!(); }} } fn release() { outer!(use); }",
        false,
    );
    ident.trusted_external_roots.insert("serde_json".to_owned());
    let mut token_tree = fixture(
        "src/tt_import.rs",
        "macro_rules! outer { ($($items:tt)*) => {{ $($items)* serde_json::json!(); }} } fn release() { outer!(use external_proc as serde_json;); }",
        false,
    );
    token_tree
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let mut absolute = fixture(
        "src/absolute_import.rs",
        "macro_rules! outer { ($keyword:ident) => {{ $keyword ::external_proc as serde_json; serde_json::json!(); }} } fn release() { outer!(use); }",
        false,
    );
    absolute
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let mut nested = fixture(
        "src/nested_group_import.rs",
        "macro_rules! outer { ($keyword:ident) => {{ $keyword { external_proc::{self as serde_json} }; serde_json::json!(); }} } fn release() { outer!(use); }",
        false,
    );
    nested
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let mut composed = fixture(
        "src/composed_import.rs",
        "macro_rules! outer { ($keyword:ident, $path:path) => {{ $keyword $path as serde_json; serde_json::json!(); }} } fn release() { outer!(use, external_proc); }",
        false,
    );
    composed
        .trusted_external_roots
        .insert("serde_json".to_owned());
    assert_eq!(
        find_production_callers(&[ident, token_tree, absolute, nested, composed]).len(),
        5
    );
}

#[test]
fn whole_macro_fragments_cannot_hide_generated_imports() {
    let mut item = fixture(
        "src/item_import.rs",
        "macro_rules! outer { ($item:item) => { $item fn release() { serde_json::json!(); } } } outer!(use external_proc as serde_json;);",
        false,
    );
    item.trusted_external_roots.insert("serde_json".to_owned());
    let mut block = fixture(
        "src/block_import.rs",
        "macro_rules! outer { ($body:block) => { fn release() $body } } outer!({ use external_proc as serde_json; serde_json::json!(); });",
        false,
    );
    block.trusted_external_roots.insert("serde_json".to_owned());
    let mut single_tt = fixture(
        "src/single_tt.rs",
        "macro_rules! outer { ($body:tt) => { $body } } fn release() { outer!({ use external_proc as serde_json; serde_json::json!(); }); }",
        false,
    );
    single_tt
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let repeated_tt = fixture(
        "src/repeated_tt.rs",
        "macro_rules! outer { ($($items:tt)*) => { $($items)* }; } fn release() { outer!(use external_proc as serde_json; serde_json::json!();); }",
        false,
    );
    let bare_tt = fixture(
        "src/bare_tt.rs",
        "macro_rules! outer { ($($items:tt)*) => { $($items)* }; } fn release() { outer!(use external_proc::json; json!();); }",
        false,
    );
    let mut separated = fixture(
        "src/separated.rs",
        "macro_rules! alias { ($keyword:ident) => { $keyword external_proc as serde_json; } } alias!(use); fn release() { serde_json::json!(); }",
        false,
    );
    separated
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let mut public_repetition = fixture(
        "src/public_repetition.rs",
        "macro_rules! alias { ($($tail:tt)*) => { pub $($tail)* } } alias!(use external_proc as serde_json;); fn release() { serde_json::json!(); }",
        false,
    );
    public_repetition
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let dynamic_target = fixture(
        "src/dynamic_target.rs",
        "macro_rules! alias { ($keyword:ident, $target:path) => { $keyword $target; } } alias!(use, external_proc::json); fn release() { json!(); }",
        false,
    );
    let dynamic_visible_target = fixture(
        "src/dynamic_visible_target.rs",
        "macro_rules! alias { ($visibility:vis, $keyword:ident, $target:path) => { $visibility $keyword $target; } } alias!(pub, use, external_proc::serde_json); fn release() { serde_json::json!(); }",
        false,
    );
    let mut expression = fixture(
        "src/expression.rs",
        "macro_rules! outer { ($body:expr) => { $body; } } fn release() { outer!({ use external_proc as serde_json; serde_json::json!(); }); }",
        false,
    );
    expression
        .trusted_external_roots
        .insert("serde_json".to_owned());
    for unit in [
        item,
        block,
        single_tt,
        repeated_tt,
        bare_tt,
        separated,
        public_repetition,
        dynamic_target,
        dynamic_visible_target,
        expression,
    ] {
        let path = unit.path.clone();
        assert!(!find_production_callers(&[unit]).is_empty(), "{path:?}");
    }
}

#[test]
fn structured_macro_matchers_cannot_hide_generated_imports() {
    let marker = fixture(
        "src/marker_dynamic_target.rs",
        "macro_rules! alias { (bind $keyword:ident, $target:path) => { $keyword $target; } } alias!(bind use, external_proc::json); fn release() { json!(); }",
        false,
    );
    let nested = fixture(
        "src/nested_dynamic_target.rs",
        "macro_rules! alias { (bind ($keyword:ident, $target:path)) => { $keyword $target; } } alias!(bind (use, external_proc::json)); fn release() { json!(); }",
        false,
    );
    let skipped_path_arm = fixture(
        "src/skipped_path_arm.rs",
        "macro_rules! alias { ($path:path) => { () }; (bind $keyword:ident $target:path) => { $keyword $target; } } alias!(bind use external_proc::json); fn release() { json!(); }",
        false,
    );
    let skipped_lifetime_arm = fixture(
        "src/skipped_lifetime_arm.rs",
        "macro_rules! alias { ($l:lifetime) => {}; (bind $keyword:ident $target:path) => { $keyword $target; } } alias!(bind use external_proc::json); fn release() { json!(); }",
        false,
    );
    let compound_separator = fixture(
        "src/compound_separator.rs",
        "macro_rules! alias { ($keyword:ident $target:path; $($ignored:ident)=>*) => { $keyword $target; } } alias!(use external_proc::json;); fn release() { json!(); }",
        false,
    );
    let local_stringify = fixture(
        "src/local_stringify.rs",
        "macro_rules! stringify { ($($items:tt)*) => { $($items)* }; } macro_rules! outer { ($($items:tt)*) => { stringify!($($items)*); }; } outer!(use external_proc::json;); fn release() { json!(); }",
        false,
    );
    let imported_stringify = fixture(
        "src/imported_stringify.rs",
        "#[macro_export] macro_rules! real_stringify { ($($items:tt)*) => { $($items)* }; } #[macro_export] macro_rules! real_json { () => {}; } mod external { pub use crate::real_stringify as stringify; } mod external_proc { pub use crate::real_json as json; } use external::stringify; macro_rules! outer { ($($items:tt)*) => { stringify!($($items)*); }; } outer!(use external_proc as serde_json;); fn release() { serde_json::json!(); }",
        false,
    );
    let punctuation_spacing = fixture(
        "src/punctuation_spacing.rs",
        "macro_rules! select { ($left:ident => $right:ident) => {}; ($keyword:ident = > $name:ident) => { $keyword external_proc::$name; } } select!(use = > json); fn release() { json!(); }",
        false,
    );
    for unit in [
        marker,
        nested,
        skipped_path_arm,
        skipped_lifetime_arm,
        compound_separator,
        local_stringify,
        imported_stringify,
        punctuation_spacing,
    ] {
        let path = unit.path.clone();
        assert!(!find_production_callers(&[unit]).is_empty(), "{path:?}");
    }
}

#[test]
fn import_keyword_in_macro_matcher_is_not_an_import() {
    let unit = fixture(
        "src/matcher.rs",
        "macro_rules! parse { (use $path:path) => { () } } fn release() { parse!(use crate::value); }",
        false,
    );
    assert!(find_production_callers(&[unit]).is_empty());
}

#[test]
fn control_flow_keyword_and_cast_are_not_an_import() {
    let mut unit = fixture(
        "src/control_flow.rs",
        "macro_rules! outer { ($keyword:ident) => {{ $keyword { let _ = serde_json::json!({}) as serde_json::Value; break; } }} } fn release() { outer!(loop); }",
        false,
    );
    unit.trusted_external_roots.insert("serde_json".to_owned());
    let mut empty = fixture(
        "src/empty_loop.rs",
        "macro_rules! outer { ($keyword:ident) => {{ $keyword {}; let _ = serde_json::json!({}); }} } fn release() { outer!(loop); }",
        false,
    );
    empty.trusted_external_roots.insert("serde_json".to_owned());
    let mut raw = fixture(
        "src/raw_use.rs",
        "fn r#use() {} macro_rules! outer { () => {{ r#use(); let _ = serde_json::json!({}); }} } fn release() { outer!(); }",
        false,
    );
    raw.trusted_external_roots.insert("serde_json".to_owned());
    let vector = fixture(
        "src/vector_tt.rs",
        "macro_rules! outer { ($($items:tt)*) => {{ let _ = vec![$($items)*]; }} } fn release() { outer!(1, 2); }",
        false,
    );
    let returning = fixture(
        "src/returning.rs",
        "fn value() -> i32 { 1 } macro_rules! outer { ($keyword:ident) => {{ $keyword value(); }} } fn release() -> i32 { outer!(return); 0 }",
        false,
    );
    let trusted_name = fixture(
        "src/returning_trusted_name.rs",
        "fn serde_json() -> i32 { 1 } macro_rules! outer { ($keyword:ident) => {{ $keyword serde_json(); }} } fn release() -> i32 { outer!(return); 0 }",
        false,
    );
    let unrelated_arm = fixture(
        "src/unrelated_dynamic_arm.rs",
        "fn value() -> i32 { 1 } macro_rules! outer { (use $path:path) => { () }; ($keyword:ident) => {{ $keyword value(); }} } fn release() { outer!(use crate::value); }",
        false,
    );
    let first_matching_arm = fixture(
        "src/first_matching_arm.rs",
        "macro_rules! outer { (use $path:path) => { () }; ($keyword:ident $path:path) => { $keyword $path; } } fn release() { outer!(use crate::value); }",
        false,
    );
    let repeated_return = fixture(
        "src/repeated_return.rs",
        "fn serde_json() {} macro_rules! outer { ($($keyword:ident)*) => { $($keyword serde_json();)* } } fn release() { outer!(return); }",
        false,
    );
    let stringified = fixture(
        "src/stringified_keyword.rs",
        "macro_rules! outer { ($keyword:ident) => { stringify!($keyword) }; } fn release() { let _ = outer!(use); }",
        false,
    );
    let repeated_stringified = fixture(
        "src/repeated_stringified_keyword.rs",
        "macro_rules! outer { ($($keyword:ident)*) => { ($(stringify!($keyword)),*) }; } fn release() { let _ = outer!(return use); }",
        false,
    );
    let unrelated_block_alias = fixture(
        "src/unrelated_block_alias.rs",
        "#[macro_export] macro_rules! local_stringify { ($($items:tt)*) => { () }; } mod external { pub use crate::local_stringify as stringify; } fn unrelated() { use external::stringify; } macro_rules! outer { ($keyword:ident) => { stringify!($keyword) }; } fn release() { let _ = outer!(use); }",
        false,
    );
    let findings = find_production_callers(&[
        unit,
        empty,
        raw,
        vector,
        returning,
        trusted_name,
        unrelated_arm,
        first_matching_arm,
        repeated_return,
        stringified,
        repeated_stringified,
        unrelated_block_alias,
    ]);
    assert!(findings.is_empty(), "{findings:?}");
}
