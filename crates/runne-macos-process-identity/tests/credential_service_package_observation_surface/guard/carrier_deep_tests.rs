use super::ast_deep_tests::{TARGET, assert_compiles};
use super::count_credential_service_calls;

const REAL_TARGET: &str = r"
    use runne_macos_process_identity::{
        MacOsCredentialServicePackageObservationError as Error,
        MacOsPendingCredentialServicePackageObservationV1 as Pending,
    };
    type Capture = fn() -> Result<Pending, Error>;
";

fn check(source: &str, expected: usize) {
    assert_compiles(source);
    assert_eq!(count_credential_service_calls(source), expected);
}

fn check_real_target(source: &str, expected: usize) {
    let dependencies = std::env::current_exe().unwrap();
    let dependencies = dependencies.parent().unwrap();
    let target = std::fs::read_dir(dependencies)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rlib")
                && path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("librunne_macos_process_identity-")
                })
        })
        .expect("compiled runne_macos_process_identity rlib");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "runne-observation-real-target-{}-{unique}",
        std::process::id()
    ));
    let source_path = base.with_extension("rs");
    let output_path = base.with_extension("rlib");
    std::fs::write(&source_path, source).unwrap();
    let result = std::process::Command::new("rustc")
        .args(["--crate-type", "rlib", "--edition", "2024"])
        .arg(&source_path)
        .arg("--extern")
        .arg(format!("runne_macos_process_identity={}", target.display()))
        .arg("-L")
        .arg(format!("dependency={}", dependencies.display()))
        .arg("-o")
        .arg(&output_path)
        .output()
        .unwrap();
    std::fs::remove_file(source_path).unwrap();
    if output_path.exists() {
        std::fs::remove_file(output_path).unwrap();
    }
    assert!(
        result.status.success(),
        "rustc failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(count_credential_service_calls(source), expected);
}

#[test]
fn carrier_flow_counts_pattern_container_and_returned_pending_values() {
    let if_let = format!(
        "{TARGET} fn production(maybe: Option<Pending>, release: &Release) {{ if let Some(pending) = maybe {{ let _ = pending.verify_exact(release); }} }}"
    );
    let unwrap = format!(
        "{TARGET} fn production(maybe: Option<Pending>, release: &Release) {{ let _ = maybe.unwrap().verify_exact(release); }}"
    );
    let returned = format!(
        "{TARGET} fn identity(pending: Pending) -> Pending {{ pending }} fn production(pending: Pending, release: &Release) {{ let _ = identity(pending).verify_exact(release); }}"
    );
    let destructured = format!(
        "{TARGET} struct Holder {{ pending: Pending }} fn production(holder: Holder, release: &Release) {{ let Holder {{ pending }} = holder; let _ = pending.verify_exact(release); }}"
    );
    for source in [&if_let, &unwrap, &returned, &destructured] {
        check(source, 1);
    }
}

#[test]
fn carrier_flow_counts_invoked_returned_and_indexed_function_items() {
    let returned = format!(
        "{TARGET} fn pick() -> fn() -> Result<Pending, Error> {{ Pending::capture_current }} fn production() {{ let _ = pick()(); }}"
    );
    let indexed = format!(
        "{TARGET} static CAPTURES: [fn() -> Result<Pending, Error>; 1] = [Pending::capture_current]; fn production() {{ let _ = (CAPTURES[0])(); }}"
    );
    check(&returned, 1);
    check(&indexed, 1);
}

#[test]
fn carrier_flow_counts_real_target_returned_and_indexed_function_items() {
    let returned = format!(
        "{REAL_TARGET} fn pick() -> Capture {{ Pending::capture_current }} pub fn production() {{ let _ = pick()(); }}"
    );
    let returned_reference = format!(
        "{REAL_TARGET} fn pick() -> Capture {{ Pending::capture_current }} pub fn production() {{ let _ = pick(); }}"
    );
    let indexed = format!(
        "{REAL_TARGET} const CAPTURES: [Capture; 1] = [Pending::capture_current]; pub fn production() {{ let _ = (CAPTURES[0])(); }}"
    );
    let indexed_reference = format!(
        "{REAL_TARGET} const CAPTURES: [Capture; 1] = [Pending::capture_current]; pub fn production() {{ let _ = CAPTURES[0]; }}"
    );
    check_real_target(&returned, 1);
    check_real_target(&returned_reference, 0);
    check_real_target(&indexed, 1);
    check_real_target(&indexed_reference, 0);
}

#[test]
fn carrier_flow_does_not_conflate_field_names_between_owner_types() {
    let pending = format!(
        "{TARGET} struct Holder {{ pending: Pending }} struct Different; impl Different {{ fn verify_exact(&self, _: &Release) {{}} }} struct Other {{ pending: Different }} fn production(value: Other, release: &Release) {{ value.pending.verify_exact(release); }}"
    );
    let callable = format!(
        "{TARGET} struct TargetFns {{ call: fn() -> Result<Pending, Error> }} struct Other {{ call: fn() }} fn production(value: Other) {{ (value.call)(); }}"
    );
    check(&pending, 0);
    check(&callable, 0);
}

#[test]
fn carrier_flow_does_not_count_uninvoked_function_values() {
    let returned = format!(
        "{TARGET} fn pick() -> fn() -> Result<Pending, Error> {{ Pending::capture_current }} fn production() {{ let _ = pick(); }}"
    );
    let reference = format!("{TARGET} fn production() {{ let _ = Pending::capture_current; }}");
    check(&returned, 0);
    check(&reference, 0);
}
