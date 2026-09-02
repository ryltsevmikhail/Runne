use std::process::Command;
use std::sync::Mutex;

const INNER_CASE: &str = "RUNNE_SLICE_E_INNER_CASE";
const SCENARIO: &str = "RUNNE_SLICE_E_SCENARIO";
const FIXTURE_ROOT: &str = "RUNNE_SLICE_E_FIXTURE_ROOT";
static PROCESS_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn dispatch(
    selector: &'static str,
    inner: fn(&super::support::InnerContext) -> Result<(), &'static str>,
) {
    dispatch_scenarios(selector, &["joined"], |context, _| inner(context));
}

pub(super) fn dispatch_scenarios<F>(selector: &'static str, scenarios: &[&'static str], inner: F)
where
    F: Fn(&super::support::InnerContext, &str) -> Result<(), &'static str>,
{
    if std::env::var_os(INNER_CASE).as_deref() == Some(std::ffi::OsStr::new(selector)) {
        let scenario = std::env::var(SCENARIO).unwrap_or_else(|_| panic!("scenario-env"));
        let context = super::support::InnerContext::from_environment()
            .unwrap_or_else(|stage| panic!("{stage}"));
        inner(&context, &scenario).unwrap_or_else(|stage| panic!("{stage}"));
        return;
    }
    let _lock = PROCESS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for scenario in scenarios {
        run_outer(selector, scenario);
    }
}

fn run_outer(selector: &'static str, scenario: &str) {
    let keychain = super::keychain::DisposableKeychain::create().expect("disposable Keychain");
    let package = super::package::LocalPackage::create(
        keychain.root(),
        selector == "persistent_reference_locates_exact_item_without_expanding_authority"
            || selector == "persistent_reference_rejects_unrelated_same_uid_peer",
    )
    .expect("local package");
    assert!(package.application().starts_with(keychain.root()));
    let secret = super::audit::secret_canary(keychain.root());
    let patterns = super::audit::sensitive_patterns(&secret);
    let output = Command::new(package.desktop())
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("HOME", keychain.home())
        .env("RUNNE_CI_MACOS_KEYCHAIN", keychain.path())
        .env("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST", "1")
        .env(INNER_CASE, selector)
        .env(SCENARIO, scenario)
        .env(FIXTURE_ROOT, keychain.root())
        .env("RUST_BACKTRACE", "0")
        .output()
        .expect("package desktop process");
    let cleanup = keychain.cleanup();
    assert!(cleanup.is_ok(), "explicit Keychain cleanup failed");
    for sink in [&output.stdout, &output.stderr] {
        for pattern in &patterns {
            assert!(!contains(sink, pattern));
        }
    }
    assert!(
        output.status.success(),
        "package desktop failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}
