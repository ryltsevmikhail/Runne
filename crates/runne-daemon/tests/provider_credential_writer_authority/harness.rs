use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

const INNER_CASE: &str = "RUNNE_SLICE_E_INNER_CASE";
const SCENARIO: &str = "RUNNE_SLICE_E_SCENARIO";
const FIXTURE_ROOT: &str = "RUNNE_SLICE_E_FIXTURE_ROOT";
static PROCESS_LOCK: Mutex<()> = Mutex::new(());

#[path = "harness/legacy_dispatch.rs"]
mod legacy_dispatch;

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

pub(super) fn dispatch_legacy_scenarios(
    selector: &'static str,
    inner: fn(
        &super::support::InnerContext,
        &str,
    ) -> Result<super::legacy_evidence::LegacyCleanupEvidence, &'static str>,
) {
    legacy_dispatch::dispatch(selector, inner);
}

fn run_outer(selector: &'static str, scenario: &str) {
    let stale = stale_fixture_processes();
    assert!(
        stale.is_empty(),
        "stale fixture processes from an earlier scenario or run are alive; they \
         answer later handshakes with an unrelated ownership failure: {stale:?}"
    );
    let persistent_reference = selector
        == "persistent_reference_is_bounded_or_fails_closed_on_native_acl_rewrite"
        || selector == "persistent_reference_rejects_unrelated_same_uid_peer";
    let keychain = super::keychain::DisposableKeychain::create().expect("disposable Keychain");
    let package = super::package::LocalPackage::create(
        keychain.root(),
        persistent_reference,
        super::package::PackageMode::CredentialService,
    )
    .expect("local package");
    assert!(package.application().starts_with(keychain.root()));
    let mut service = (!persistent_reference)
        .then(|| {
            super::service_process::TemporaryCredentialService::bootstrap(
                keychain.root(),
                keychain.home(),
                keychain.path(),
                &package.credential_service(),
            )
        })
        .transpose()
        .expect("temporary credential service");
    let secret = super::audit::secret_canary(keychain.root());
    let patterns = super::audit::sensitive_patterns(&secret);
    let output = Command::new(package.desktop())
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("HOME", keychain.home())
        .env(
            "RUNNE_WRITER_HANDOFF_TRACE",
            std::env::var_os("RUNNE_WRITER_HANDOFF_TRACE").unwrap_or_default(),
        )
        .env("RUNNE_CI_MACOS_KEYCHAIN", keychain.path())
        .env("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST", "1")
        .env(INNER_CASE, selector)
        .env(SCENARIO, scenario)
        .env(FIXTURE_ROOT, keychain.root())
        .env("RUST_BACKTRACE", "0")
        .output()
        .expect("package desktop process");
    if let Some(service) = service.as_mut() {
        service.shutdown().expect("credential service cleanup");
    }
    let leaked = reap_fixture_processes(keychain.root());
    let service_stderr =
        std::fs::read(keychain.root().join("credential-service.stderr")).unwrap_or_default();
    let cleanup = keychain.cleanup();
    assert!(cleanup.is_ok(), "explicit Keychain cleanup failed");
    for sink in [&output.stdout, &output.stderr, &service_stderr] {
        for pattern in &patterns {
            assert!(!contains(sink, pattern));
        }
    }
    assert!(
        output.status.success(),
        "package desktop failed: scenario={scenario} leaked={leaked:?} stdout={} stderr={} \
         service_stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&service_stderr),
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}

/// Fixture roots live under unique `runne-slice-e-` temporary directories, so
/// a live process whose command line still references that marker belongs to
/// a scenario that died before reaping its children. Such leftovers answer
/// later handshakes and surface as an unrelated OwnershipMismatch deep in
/// the writer handoff, which is why they are reported and failed on here.
/// Local note: any process whose command line merely mentions the marker
/// (a grep, a pager) also matches; the assert names every match.
fn fixture_process_lines() -> Vec<String> {
    let marker = format!("/{}", crate::keychain::FIXTURE_TEMPFILE_PREFIX);
    let output = Command::new("/bin/ps")
        .args(["-axo", "pid=,command="])
        .output()
        .expect("process table listing");
    assert!(output.status.success(), "process table listing failed");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(marker.as_str()))
        .map(str::to_owned)
        .collect()
}

/// Live processes left over by an earlier scenario or an earlier suite run.
fn stale_fixture_processes() -> Vec<String> {
    fixture_process_lines()
}

/// Terminate every live process referencing this scenario's fixture root and
/// report the ones that had to be killed. A healthy scenario leaves nothing:
/// the supervisor and the service shutdown own their children, so any
/// survivor is a leak caused by the scenario dying mid-handoff.
fn reap_fixture_processes(root: &Path) -> Vec<String> {
    let root_text = root.to_string_lossy();
    let leaked: Vec<String> = fixture_process_lines()
        .into_iter()
        .filter(|line| line.contains(root_text.as_ref()))
        .collect();
    for line in &leaked {
        if let Some(pid) = line.split_whitespace().next() {
            let killed = Command::new("/bin/kill").args(["-9", pid]).output();
            if killed.map_or(true, |result| !result.status.success()) {
                eprintln!("writer-authority harness: failed to kill fixture process {pid}");
            }
        }
    }
    leaked
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::legacy_dispatch::{legacy_child_plan, legacy_preflight};
    use crate::legacy_evidence::LegacyEvidenceBindings;

    #[test]
    fn legacy_child_plan_runs_the_ignored_selector_with_only_allowlisted_bindings() {
        let temporary = tempfile::tempdir().expect("temporary evidence root");
        let bindings = LegacyEvidenceBindings::from_values(
            "a".repeat(64),
            "b".repeat(64),
            "run-1".to_owned(),
            temporary.path().join("final.json"),
        )
        .expect("bindings");
        let plan = legacy_child_plan(
            "legacy_cleanup_scenario_chain_completes_import_cutover_delete_crash_and_tombstone",
            "legacy-import",
            temporary.path().join("child.json"),
            &bindings,
        );
        assert_eq!(
            plan.args,
            vec![
                "--ignored",
                "--exact",
                "legacy_cleanup_scenario_chain_completes_import_cutover_delete_crash_and_tombstone",
                "--nocapture",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            plan.environment
                .iter()
                .map(|(name, _)| *name)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "RUNNE_LEGACY_CLEANUP_CANDIDATE",
                "RUNNE_LEGACY_CLEANUP_EVIDENCE",
                "RUNNE_LEGACY_CLEANUP_RUN_ID",
                "RUNNE_LEGACY_CLEANUP_TUPLE",
            ])
        );
        assert!(
            plan.environment
                .iter()
                .all(|(_, value)| value != bindings.final_path().as_os_str())
        );
    }

    #[test]
    fn legacy_preflight_requires_the_explicit_isolated_host_opt_in() {
        let temporary = tempfile::tempdir().expect("temporary evidence root");
        assert!(matches!(
            legacy_preflight(
                "0",
                "a".repeat(64),
                "b".repeat(64),
                "run-1".to_owned(),
                temporary.path().join("final.json"),
            ),
            Err("legacy cleanup isolated host opt-in is required")
        ));
    }
}
