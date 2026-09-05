use std::ffi::OsString;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::legacy_evidence::{
    LEGACY_CLEANUP_CANDIDATE_ENV, LEGACY_CLEANUP_EVIDENCE_ENV, LEGACY_CLEANUP_RUN_ID_ENV,
    LEGACY_CLEANUP_TUPLE_ENV, LEGACY_SCENARIO_NAMES, LegacyCleanupEvidence, LegacyEvidenceBindings,
};

#[path = "legacy_sinks.rs"]
mod legacy_sinks;

use legacy_sinks::{MAX_SERVICE_LOG_BYTES, bounded_wait, read_bounded_sink, spawn_bounded_drain};

const ISOLATED_ENV: &str = "RUNNE_LEGACY_CLEANUP_ISOLATED";
const SERVICE_STDOUT: &str = "credential-service.stdout";
const SERVICE_STDERR: &str = "credential-service.stderr";

pub(super) struct LegacyChildPlan {
    pub(super) args: Vec<&'static str>,
    pub(super) environment: Vec<(&'static str, OsString)>,
}

pub(super) fn dispatch(
    selector: &'static str,
    inner: fn(
        &super::super::support::InnerContext,
        &str,
    ) -> Result<LegacyCleanupEvidence, &'static str>,
) {
    if std::env::var_os(super::INNER_CASE).as_deref() == Some(selector.as_ref()) {
        run_inner(selector, inner);
        return;
    }
    let bindings = LegacyEvidenceBindings::from_environment()
        .and_then(legacy_preflight_from_environment)
        .unwrap_or_else(|stage| panic!("{stage}"));
    let _lock = super::PROCESS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut aggregate = LegacyCleanupEvidence::default();
    for scenario in LEGACY_SCENARIO_NAMES {
        aggregate
            .merge(
                run_outer(selector, scenario, &bindings).unwrap_or_else(|stage| panic!("{stage}")),
            )
            .unwrap_or_else(|stage| panic!("{stage}"));
    }
    aggregate
        .write_envelope(
            bindings.final_path(),
            bindings.candidate_sha256(),
            bindings.tuple_sha256(),
            bindings.workflow_run_id(),
        )
        .unwrap_or_else(|stage| panic!("{stage}"));
}

fn run_inner(
    selector: &'static str,
    inner: fn(
        &super::super::support::InnerContext,
        &str,
    ) -> Result<LegacyCleanupEvidence, &'static str>,
) {
    let scenario = std::env::var(super::SCENARIO).unwrap_or_else(|_| panic!("scenario-env"));
    let bindings =
        LegacyEvidenceBindings::from_environment().unwrap_or_else(|stage| panic!("{stage}"));
    let context = super::super::support::InnerContext::from_environment()
        .unwrap_or_else(|stage| panic!("{stage}"));
    let evidence = inner(&context, &scenario).unwrap_or_else(|stage| panic!("{stage}"));
    evidence
        .write_fragment(bindings.final_path(), &scenario, &bindings)
        .unwrap_or_else(|stage| panic!("{stage}"));
    let _ = selector;
}

fn run_outer(
    selector: &'static str,
    scenario: &'static str,
    bindings: &LegacyEvidenceBindings,
) -> Result<LegacyCleanupEvidence, &'static str> {
    let keychain = super::super::keychain::DisposableKeychain::create()
        .map_err(|_| "legacy disposable keychain")?;
    let package = super::super::package::LocalPackage::create(
        keychain.root(),
        false,
        super::super::package::PackageMode::CredentialService,
    )
    .inspect_err(|stage| eprintln!("LEGACY PACKAGE STAGE: {stage}"))?;
    let mut service = super::super::service_process::TemporaryCredentialService::bootstrap(
        keychain.root(),
        keychain.home(),
        keychain.path(),
        &package.credential_service(),
    )
    .map_err(|_| "legacy credential service")?;
    let secret = super::super::audit::secret_canary(keychain.root());
    let patterns = super::super::audit::sensitive_patterns(&secret);
    let fragment = keychain.root().join("legacy-evidence-fragment.json");
    let plan = legacy_child_plan(selector, scenario, fragment.clone(), bindings);
    let mut child = Command::new(package.desktop())
        .args(&plan.args)
        .env_clear()
        .env("HOME", keychain.home())
        .env("RUNNE_CI_MACOS_KEYCHAIN", keychain.path())
        .env("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST", "1")
        .env(super::INNER_CASE, selector)
        .env(super::SCENARIO, scenario)
        .env(super::FIXTURE_ROOT, keychain.root())
        .envs(plan.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "legacy child process launch")?;
    let result = collect_child_and_service_sinks(
        &mut child,
        keychain.root(),
        &mut service,
        &patterns,
        &fragment,
        scenario,
        bindings,
    );
    let evidence = match result {
        Ok(evidence) => evidence,
        Err(stage) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = service.shutdown();
            let _ = keychain.cleanup();
            return Err(stage);
        }
    };
    keychain
        .cleanup()
        .map_err(|_| "legacy explicit keychain cleanup failed")?;
    Ok(evidence)
}

/// Waits for the exact child, then bounds and audits every collected sink:
/// the child's own stdout/stderr and both credential-service logs. Any
/// overflow, canary match or child failure fails closed before the fragment
/// is accepted.
fn collect_child_and_service_sinks(
    child: &mut Child,
    root: &std::path::Path,
    service: &mut super::super::service_process::TemporaryCredentialService,
    patterns: &[Vec<u8>],
    fragment: &std::path::Path,
    scenario: &str,
    bindings: &LegacyEvidenceBindings,
) -> Result<LegacyCleanupEvidence, &'static str> {
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let stdout = child
        .stdout
        .take()
        .ok_or("legacy child stdout unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("legacy child stderr unavailable")?;
    let stdout_handle = spawn_bounded_drain(stdout, stdout_overflow.clone());
    let stderr_handle = spawn_bounded_drain(stderr, stderr_overflow.clone());
    let status = bounded_wait(child).map_err(|_| "legacy child wait failed")?;
    let child_stdout = stdout_handle
        .join()
        .map_err(|_| "legacy child stdout drain failed")?;
    let child_stderr = stderr_handle
        .join()
        .map_err(|_| "legacy child stderr drain failed")?;
    service
        .shutdown()
        .map_err(|_| "legacy credential service cleanup")?;
    let service_stdout = read_bounded_sink(&root.join(SERVICE_STDOUT), MAX_SERVICE_LOG_BYTES)?;
    let service_stderr = read_bounded_sink(&root.join(SERVICE_STDERR), MAX_SERVICE_LOG_BYTES)?;
    if stdout_overflow.load(Ordering::SeqCst) || stderr_overflow.load(Ordering::SeqCst) {
        return Err("legacy child output exceeded the collection bound");
    }
    if !status.success() {
        // The child's own failure report is the only diagnosable artifact of a
        // failed scenario; print its bounded tail before failing closed.
        eprintln!("LEGACY CHILD STDERR TAIL:");
        eprintln!("{}", String::from_utf8_lossy(&child_stderr));
        return Err("legacy child process failed");
    }
    if [
        &child_stdout,
        &child_stderr,
        &service_stdout,
        &service_stderr,
    ]
    .into_iter()
    .any(|sink| {
        patterns
            .iter()
            .any(|pattern| super::contains(sink, pattern))
    }) {
        return Err("legacy child output contains sensitive material");
    }
    LegacyCleanupEvidence::read_fragment(fragment, scenario, bindings)
}

pub(super) fn legacy_preflight(
    isolated: &str,
    candidate: String,
    tuple: String,
    run_id: String,
    final_path: std::path::PathBuf,
) -> Result<LegacyEvidenceBindings, &'static str> {
    if isolated != "1" {
        return Err("legacy cleanup isolated host opt-in is required");
    }
    LegacyEvidenceBindings::from_values(candidate, tuple, run_id, final_path)
}

fn legacy_preflight_from_environment(
    bindings: LegacyEvidenceBindings,
) -> Result<LegacyEvidenceBindings, &'static str> {
    if std::env::var(ISOLATED_ENV).as_deref() != Ok("1") {
        return Err("legacy cleanup isolated host opt-in is required");
    }
    Ok(bindings)
}

pub(super) fn legacy_child_plan(
    selector: &'static str,
    _scenario: &'static str,
    child_path: std::path::PathBuf,
    bindings: &LegacyEvidenceBindings,
) -> LegacyChildPlan {
    LegacyChildPlan {
        args: vec![
            "--ignored",
            "--exact",
            selector,
            "--nocapture",
            "--test-threads=1",
        ],
        environment: vec![
            (
                LEGACY_CLEANUP_CANDIDATE_ENV,
                OsString::from(bindings.candidate_sha256()),
            ),
            (LEGACY_CLEANUP_EVIDENCE_ENV, child_path.into_os_string()),
            (
                LEGACY_CLEANUP_RUN_ID_ENV,
                OsString::from(bindings.workflow_run_id()),
            ),
            (
                LEGACY_CLEANUP_TUPLE_ENV,
                OsString::from(bindings.tuple_sha256()),
            ),
        ],
    }
}
