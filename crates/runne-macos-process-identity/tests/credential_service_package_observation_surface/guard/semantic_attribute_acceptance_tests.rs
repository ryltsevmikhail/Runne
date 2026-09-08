use std::path::PathBuf;
use std::process::Command;

use super::analyzer::{GuardVerdict, analyze_source};
use super::semantic_acceptance_support::{assert_compiles, link_real_target};

const HELPER: &str = r#"
extern crate proc_macro;
use proc_macro::TokenStream;
fn generated() -> TokenStream {
    "fn generated_call() { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }".parse().unwrap()
}
#[proc_macro_attribute]
pub fn inject(_: TokenStream, mut input: TokenStream) -> TokenStream {
    input.extend(generated());
    input
}
#[proc_macro_derive(Inject)]
pub fn derive(_: TokenStream) -> TokenStream { generated() }
#[proc_macro_derive(Clone)]
pub fn shadow_clone(_: TokenStream) -> TokenStream { generated() }
#[proc_macro]
pub fn matches(_: TokenStream) -> TokenStream {
    "{ let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }".parse().unwrap()
}
"#;

#[test]
fn opaque_procedural_attribute_cannot_hide_generated_call() {
    assert_opaque(
        "#[guard_attribute_helper::inject] fn entry() {}",
        "attribute",
    );
}

#[test]
fn opaque_derive_cannot_hide_generated_call() {
    assert_opaque(
        "#[derive(guard_attribute_helper::Inject)] struct Entry;",
        "derive",
    );
}

#[test]
fn imported_derive_with_builtin_name_is_not_a_builtin() {
    assert_opaque(
        "use guard_attribute_helper::Clone; #[derive(Clone)] struct Entry;",
        "shadow_clone",
    );
}

#[test]
fn imported_function_macro_with_builtin_name_is_not_a_builtin() {
    assert_opaque(
        "use guard_attribute_helper::matches; fn entry() { matches!(); }",
        "shadow_matches",
    );
}

#[test]
fn imported_std_alias_does_not_prove_standard_macro_identity() {
    assert_opaque(
        "use guard_attribute_helper as std; fn entry() { std::matches!(); }",
        "shadow_std",
    );
}

#[test]
fn associated_item_attribute_cannot_hide_generated_call() {
    assert_opaque(
        "struct Entry; impl Entry { #[guard_attribute_helper::inject] fn entry() {} }",
        "associated_attribute",
    );
}

#[test]
fn production_cfg_attr_cannot_hide_generated_call() {
    assert_opaque(
        "#[cfg_attr(not(test), guard_attribute_helper::inject)] fn entry() {}",
        "cfg_attr",
    );
}

#[test]
fn test_only_procedural_expansion_is_excluded() {
    for item in [
        "#[guard_attribute_helper::inject] fn entry() {}",
        "#[derive(guard_attribute_helper::Inject)] struct Entry;",
    ] {
        let source = format!("#[cfg(test)]\n{item}");
        assert_compiles_with_helper(&source, "test_only");
        assert_eq!(analyze_source(&source), GuardVerdict::Clean);
    }
}

#[test]
fn compiler_builtin_attributes_stay_clean() {
    let source = "#[derive(Clone, Copy, Debug)] struct Entry; #[allow(dead_code)] fn entry() {}";
    assert_compiles(source, "builtin_attributes");
    assert_eq!(analyze_source(source), GuardVerdict::Clean);
}

fn assert_opaque(source: &str, name: &str) {
    assert_compiles_with_helper(source, name);
    let verdict = analyze_source(source);
    assert!(
        matches!(verdict, GuardVerdict::Inconclusive(_)),
        "unavailable procedural expansion must fail closed: {name}: {verdict:?}"
    );
}

fn assert_compiles_with_helper(source: &str, name: &str) {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = CompileDirectory(std::env::temp_dir().join(format!(
        "runne-attribute-acceptance-{}-{unique}-{name}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let helper = directory.0.join("helper.rs");
    let library = directory.0.join(format!(
        "{}guard_attribute_helper{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::write(&helper, HELPER).unwrap();
    let output = Command::new("rustc")
        .args([
            "--crate-type",
            "proc-macro",
            "--crate-name",
            "guard_attribute_helper",
            "--edition",
            "2024",
        ])
        .arg(&helper)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let input = directory.0.join("fixture.rs");
    std::fs::write(&input, source).unwrap();
    let mut compiler = Command::new("rustc");
    compiler.args(["--crate-type", "rlib", "--edition", "2024"]);
    compiler
        .arg(&input)
        .arg("--extern")
        .arg(format!("guard_attribute_helper={}", library.display()));
    link_real_target(&mut compiler);
    let output = compiler
        .arg("-o")
        .arg(directory.0.join("fixture.rlib"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct CompileDirectory(PathBuf);

impl Drop for CompileDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
