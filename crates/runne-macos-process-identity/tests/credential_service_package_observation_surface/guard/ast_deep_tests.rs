use super::count_credential_service_calls;
use std::path::{Path, PathBuf};
use std::process::Command;
struct TemporaryRlib(PathBuf);
impl TemporaryRlib {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("runne-observation-ast-{}-{unique}", std::process::id());
        for suffix in 0..u16::MAX {
            let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create {}: {error}", path.display()),
            }
        }
        panic!("cannot allocate temporary rlib directory")
    }

    fn write(&self, relative: &str, source: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, source).unwrap();
        path
    }

    fn compile(
        &self,
        crate_name: &str,
        source: &Path,
        extern_rlib: Option<(&str, &Path)>,
    ) -> PathBuf {
        let output = self.0.join(format!("lib{crate_name}.rlib"));
        let mut command = Command::new("rustc");
        command
            .args([
                "--crate-name",
                crate_name,
                "--crate-type",
                "rlib",
                "--edition",
                "2024",
            ])
            .arg(source)
            .arg("-o")
            .arg(&output);
        super::semantic_acceptance_support::link_real_target(&mut command);
        if let Some((name, rlib)) = extern_rlib {
            command
                .arg("--extern")
                .arg(format!("{name}={}", rlib.display()));
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "rustc failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        output
    }
}
impl Drop for TemporaryRlib {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

pub(super) const TARGET: &str = r"
    pub use runne_macos_process_identity::{
        MacOsCredentialServicePackageObservationError as Error,
        MacOsPendingCredentialServicePackageObservationV1 as Pending,
    };
    pub use runne_api::VerifiedSignedInstalledReleaseV2 as Release;
";

pub(super) fn assert_compiles(source: &str) {
    let fixture = TemporaryRlib::new();
    let source = fixture.write("lib.rs", source);
    fixture.compile("fixture", &source, None);
}

#[test]
fn ast_guard_counts_item_position_macro_invocation_only() {
    let definition = format!(
        "{TARGET} macro_rules! emit {{ () => {{ fn production() {{ let _ = Pending::capture_current(); }} }} }}"
    );
    let invoked = format!("{definition} emit!();");
    assert_compiles(&definition);
    assert_compiles(&invoked);
    assert_eq!(count_credential_service_calls(&definition), 0);
    assert_eq!(count_credential_service_calls(&invoked), 1);
}

#[test]
fn ast_guard_counts_pending_receiver_fields() {
    let source = format!(
        "{TARGET} struct Holder {{ pending: Pending }} fn production(holder: Holder, release: &Release) {{ let _ = holder.pending.verify_exact(release); }}"
    );
    assert_compiles(&source);
    assert_eq!(count_credential_service_calls(&source), 1);
}

#[test]
fn ast_guard_fails_closed_for_unresolved_tuple_function_field() {
    let source = format!(
        "{TARGET} struct Functions(fn() -> Result<Pending, Error>); fn production(functions: Functions) {{ let _ = (functions.0)(); }} fn make() -> Functions {{ Functions(Pending::capture_current) }}"
    );
    assert_compiles(&source);
    assert!(matches!(
        super::analyzer::analyze_source(&source),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn ast_guard_counts_each_existing_indirect_carrier_independently() {
    let function_item = format!(
        "{TARGET} fn production() {{ let capture = Pending::capture_current; let _ = capture(); }}"
    );
    let argument = format!(
        "{TARGET} fn invoke(capture: fn() -> Result<Pending, Error>) -> Result<Pending, Error> {{ capture() }} fn production() {{ let _ = invoke(Pending::capture_current); }}"
    );
    let receiver_alias = format!(
        "{TARGET} fn production(pending: Pending, release: &Release) {{ let alias = pending; let _ = alias.verify_exact(release); }}"
    );
    for source in [&function_item, &argument, &receiver_alias] {
        assert_compiles(source);
        assert_eq!(count_credential_service_calls(source), 1);
    }
}

#[test]
fn ast_guard_counts_dereferenced_pending_receiver() {
    let dereferenced = format!(
        "{TARGET} fn production(pending: Box<Pending>, release: &Release) {{ let _ = (*pending).verify_exact(release); }}"
    );
    assert_compiles(&dereferenced);
    assert_eq!(count_credential_service_calls(&dereferenced), 1);
}

#[test]
fn ast_guard_fails_closed_for_explicit_external_reexport() {
    let fixture = TemporaryRlib::new();
    let helper = fixture.write(
        "helper.rs",
        "pub struct Original; pub use Original as HiddenPending; impl Original { pub fn capture_current() -> Self { Self } }",
    );
    let helper = fixture.compile("helper", &helper, None);
    let consumer = "pub fn production() { let _ = HiddenPending::capture_current(); } use helper::HiddenPending;";
    let consumer_path = fixture.write("consumer.rs", consumer);
    fixture.compile("consumer", &consumer_path, Some(("helper", &helper)));
    assert!(matches!(
        super::analyzer::analyze_source(consumer),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
    let reference = "pub fn production() { let _capture = HiddenPending::capture_current; } use helper::HiddenPending;";
    let reference_path = fixture.write("reference.rs", reference);
    fixture.compile("reference", &reference_path, Some(("helper", &helper)));
    assert_eq!(count_credential_service_calls(reference), 0);
}

#[test]
fn ast_guard_ignores_all_semantically_test_only_call_containers() {
    let local = format!(
        "{TARGET} fn production() {{ #[cfg(test)] let _pending = Pending::capture_current(); }}"
    );
    let block = format!(
        "{TARGET} fn production() {{ #[cfg(test)] {{ let _ = Pending::capture_current(); }} }}"
    );
    let macro_expression = format!(
        "{TARGET} macro_rules! emit {{ () => {{ let _ = Pending::capture_current(); }} }} fn hidden() {{ #[cfg(test)] emit!(); }} fn production() {{ #[cfg(not(test))] emit!(); }}"
    );
    assert_compiles(&local);
    assert_compiles(&block);
    assert_compiles(&macro_expression);
    assert_eq!(count_credential_service_calls(&local), 0);
    assert_eq!(count_credential_service_calls(&block), 0);
    assert_eq!(count_credential_service_calls(&macro_expression), 1);
}

#[test]
fn ast_guard_ignores_external_glob_inside_test_only_item() {
    let fixture = TemporaryRlib::new();
    let helper = fixture.write(
        "helper.rs",
        "pub struct HiddenPending; impl HiddenPending { pub fn capture_current() -> Self { Self } }",
    );
    let helper = fixture.compile("helper", &helper, None);
    let consumer = "#[allow(unused_imports)] use helper::*; #[cfg(test)] fn hidden() { let _ = HiddenPending::capture_current(); }";
    let consumer_path = fixture.write("consumer.rs", consumer);
    fixture.compile("consumer", &consumer_path, Some(("helper", &helper)));
    assert_eq!(count_credential_service_calls(consumer), 0);
}

#[test]
fn ast_guard_does_not_count_unrelated_names_or_methods() {
    let source = r"
        struct Pending;
        impl Pending { fn capture_current() -> Self { Self } }
        fn production() { let _ = Pending::capture_current(); }
    ";
    assert_compiles(source);
    assert_eq!(count_credential_service_calls(source), 0);
    assert_eq!(
        count_credential_service_calls(
            "use helper::HiddenPending; fn production(value: HiddenPending) { value.unrelated(); }"
        ),
        0
    );
}

#[test]
fn ast_guard_does_not_count_invoked_macros_with_unrelated_receiver_types() {
    let function_position = r"
        struct Other;
        impl Other { fn capture_current() -> Self { Self } }
        macro_rules! emit { () => { let _ = Other::capture_current(); } }
        fn production() { emit!(); }
    ";
    let item_position = r"
        struct Other;
        impl Other { fn capture_current() -> Self { Self } }
        macro_rules! emit { () => { fn production() { let _ = Other::capture_current(); } } }
        emit!();
    ";
    assert_compiles(function_position);
    assert_compiles(item_position);
    assert_eq!(count_credential_service_calls(function_position), 0);
    assert_eq!(count_credential_service_calls(item_position), 0);
}

#[test]
fn explicit_import_fallback_tracks_the_receiver_type() {
    let fixture = TemporaryRlib::new();
    let helper = fixture.write(
        "helper.rs",
        "pub struct Dependency; pub struct Release; pub struct HiddenPending; impl HiddenPending { pub fn verify_exact(&self, _: &Release) {} }",
    );
    let helper = fixture.compile("helper", &helper, None);
    let unrelated = "struct Ready; impl Ready { fn verify_exact(&self) {} } pub fn production(ready: Ready) { ready.verify_exact(); } use helper::Dependency;";
    let target = "pub fn production(pending: HiddenPending, release: &helper::Release) { pending.verify_exact(release); } use helper::HiddenPending;";
    for (name, source) in [("unrelated", unrelated), ("target", target)] {
        let path = fixture.write(&format!("{name}.rs"), source);
        fixture.compile(name, &path, Some(("helper", &helper)));
    }
    assert_eq!(count_credential_service_calls(unrelated), 0);
    assert!(matches!(
        super::analyzer::analyze_source(target),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn ast_guard_fails_closed_for_qself_ufcs_on_opaque_external_target_method() {
    let fixture = TemporaryRlib::new();
    let helper = fixture.write(
        "helper.rs",
        "pub struct Hidden; pub trait Gate { fn capture_current() -> Self; } impl Gate for Hidden { fn capture_current() -> Self { Hidden } }",
    );
    let helper = fixture.compile("helper", &helper, None);
    let consumer = "pub fn production() -> helper::Hidden { let _ = <helper::Hidden as Gate>::capture_current(); helper::Hidden } use helper::Gate;";
    let consumer_path = fixture.write("consumer.rs", consumer);
    fixture.compile("consumer", &consumer_path, Some(("helper", &helper)));
    assert!(matches!(
        super::analyzer::analyze_source(consumer),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn ast_guard_fails_closed_for_qself_ufcs_inside_macro_expansion() {
    let fixture = TemporaryRlib::new();
    let helper = fixture.write(
        "helper.rs",
        "pub struct Hidden; pub trait Gate { fn capture_current() -> Self; } impl Gate for Hidden { fn capture_current() -> Self { Hidden } }",
    );
    let helper = fixture.compile("helper", &helper, None);
    let consumer = "pub fn opaque(value: helper::Hidden) {} macro_rules! emit { () => { pub fn production() -> helper::Hidden { let _ = <helper::Hidden as Gate>::capture_current(); helper::Hidden } } } emit!(); use helper::Gate;";
    let consumer_path = fixture.write("consumer.rs", consumer);
    fixture.compile("consumer", &consumer_path, Some(("helper", &helper)));
    assert!(matches!(
        super::analyzer::analyze_source(consumer),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn ast_guard_resolves_local_qself_ufcs_conclusively() {
    let source = r"
        struct Local;
        trait Runnable { fn capture_current() -> Self; }
        impl Runnable for Local { fn capture_current() -> Self { Local } }
        fn production() { let _ = <Local as Runnable>::capture_current(); }
    ";
    assert_compiles(source);
    assert_eq!(count_credential_service_calls(source), 0);
}
