use std::path::PathBuf;

use super::super::analyzer::{GuardVerdict, analyze_source};
use super::super::semantic_acceptance_support::{assert_compiles, link_real_target};

const PRELUDE: &str = r"
use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
use runne_macos_process_identity::MacOsCredentialServicePackageObservationError as Error;
type Capture = fn() -> Result<Pending, Error>;
";

fn assert_calls(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    let verdict = analyze_source(&source);
    assert!(
        matches!(verdict, GuardVerdict::Calls(ref calls) if !calls.is_empty()),
        "{name}: {verdict:?}"
    );
}

fn assert_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert_eq!(analyze_source(&source), GuardVerdict::Clean, "{name}");
}

#[test]
fn method_fallbacks_preserve_target_arguments_or_fail_closed() {
    assert_calls(
        "fn production() { let capture = None::<Capture>.unwrap_or(Pending::capture_current); let _ = capture(); }",
        "final_p1_unwrap_or",
    );
    assert_clean(
        "fn unrelated() -> Result<Pending, Error> { loop {} } fn production() { let _stored = None::<Capture>.unwrap_or(unrelated); }",
        "final_p1_unwrap_or_control",
    );
    let helper = "pub struct Runner; impl Runner { pub fn invoke<T>(&self, callback: fn() -> T) -> T { callback() } }";
    let consumer = format!(
        "{PRELUDE}\nuse flow_helper::Runner; fn production() {{ let runner = Runner; let _ = runner.invoke(Pending::capture_current); }}"
    );
    assert_compiles_with_helper(helper, &consumer, "final_p1_external_method");
    assert!(matches!(
        analyze_source(&consumer),
        GuardVerdict::Inconclusive(_)
    ));
    let control = format!(
        "{PRELUDE}\nuse flow_helper::Runner; fn production() {{ let runner = Runner; let _ = runner.invoke(|| ()); }}"
    );
    assert_compiles_with_helper(helper, &control, "final_p1_external_method_control");
    assert_eq!(analyze_source(&control), GuardVerdict::Clean);
}

#[test]
fn control_flow_and_projection_preserve_callable_facts() {
    assert_calls(
        "fn production() { let capture = loop { break Pending::capture_current; }; let _ = capture(); }",
        "final_p1_loop_break",
    );
    assert_calls(
        "struct Holder { call: Capture } fn unrelated() -> Result<Pending, Error> { loop {} } fn production() { let mut holder = Holder { call: unrelated }; holder.call = Pending::capture_current; let _ = (holder.call)(); }",
        "final_p1_projected_assignment",
    );
    assert_calls(
        "fn production() { if let Some(capture) = Some(Pending::capture_current) && true { let _ = capture(); } }",
        "final_p1_let_chain",
    );
    assert_calls(
        "async fn production() { let capture = async { Pending::capture_current }.await; let _ = capture(); }",
        "final_p1_async_await",
    );
    assert_clean(
        "fn production() { let _capture = loop { break Pending::capture_current; }; }",
        "final_p1_loop_control",
    );
    assert_non_clean(
        "struct Holder { call: Capture } fn unrelated() -> Result<Pending, Error> { loop {} } static mut HOLDER: Holder = Holder { call: unrelated }; fn production() { unsafe { HOLDER.call = Pending::capture_current; let _ = (HOLDER.call)(); } }",
        "final_p1_static_assignment",
    );
}

#[test]
fn pattern_macros_bind_local_expansions_and_fail_closed_when_opaque() {
    assert_calls(
        r"macro_rules! inner { ($pattern:pat) => { Some($pattern) } }
          macro_rules! outer { ($pattern:pat) => { inner!($pattern) } }
          fn production() { if let outer!(capture) = Some(Pending::capture_current) { let _ = capture(); } }",
        "final_p1_local_pattern_macro",
    );
    assert_calls(
        r"macro_rules! bind { ($pattern:pat) => { $pattern } }
          macro_rules! inner { ($pattern:pat) => { inner_bind!($pattern) } }
          macro_rules! inner_bind { ($pattern:pat) => { $pattern } }
          macro_rules! outer { ($pattern:pat) => { Some(inner!($pattern)) } }
          fn production() { if let Some(bind!(capture)) = Some(Pending::capture_current) { let _ = capture(); } if let outer!(capture) = Some(Pending::capture_current) { let _ = capture(); } }",
        "final_p1_nested_pattern_macro",
    );
    assert_calls(
        r"macro_rules! bind { ($pattern:pat) => { $pattern } }
          struct Holder { call: Capture }
          fn production() {
              let (bind!(tuple),) = (Pending::capture_current,); let _ = tuple();
              let Holder { call: bind!(record) } = Holder { call: Pending::capture_current }; let _ = record();
              let [bind!(slice)] = [Pending::capture_current]; let _ = slice();
              let &(bind!(reference)) = &Pending::capture_current; let _ = reference();
              let bind!(typed): Capture = Pending::capture_current; let _ = typed();
          }",
        "final_p1_composite_pattern_macros",
    );
    assert_clean(
        r"macro_rules! some { ($pattern:pat) => { Some($pattern) } }
          fn production() { if let some!(_capture) = Some(Pending::capture_current) {} }",
        "final_p1_pattern_macro_control",
    );
    let helper = "#[macro_export] macro_rules! some { ($pattern:pat) => { Some($pattern) } }";
    let consumer = format!(
        "{PRELUDE}\nfn production() {{ if let flow_helper::some!(capture) = Some(Pending::capture_current) {{ let _ = capture(); }} }}"
    );
    assert_compiles_with_helper(helper, &consumer, "final_p1_external_pattern_macro");
    assert!(matches!(
        analyze_source(&consumer),
        GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn local_constructor_carriers_and_custom_none_do_not_erase_facts() {
    assert_calls(
        "struct Holder(Capture); fn production() { let holder = Holder(Pending::capture_current); let _ = (holder.0)(); }",
        "final_p1_tuple_struct_carrier",
    );
    assert_non_clean(
        "struct None<T>(T); impl<T> None<T> { fn unwrap_or(self, _: Capture) -> T { self.0 } } fn unrelated() -> Result<Pending, Error> { loop {} } fn production() { let capture = None(Pending::capture_current).unwrap_or(unrelated); let _ = capture(); }",
        "final_p1_custom_none",
    );
}

fn assert_non_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert!(
        !matches!(analyze_source(&source), GuardVerdict::Clean),
        "{name}"
    );
}

fn assert_compiles_with_helper(helper: &str, consumer: &str, name: &str) {
    let directory = TempDirectory::new(name);
    let helper_path = directory.0.join("helper.rs");
    let helper_rlib = directory.0.join("libflow_helper.rlib");
    std::fs::write(&helper_path, helper).unwrap();
    let output = std::process::Command::new("rustc")
        .args([
            "--crate-name",
            "flow_helper",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&helper_path)
        .arg("-o")
        .arg(&helper_rlib)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let consumer_path = directory.0.join("consumer.rs");
    std::fs::write(&consumer_path, consumer).unwrap();
    let mut command = std::process::Command::new("rustc");
    command
        .args(["--crate-type", "rlib", "--edition", "2024"])
        .arg(&consumer_path);
    link_real_target(&mut command);
    let output = command
        .arg("--extern")
        .arg(format!("flow_helper={}", helper_rlib.display()))
        .arg("-o")
        .arg(directory.0.join("consumer.rlib"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(name: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "runne-final-p1-{}-{unique}-{name}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
