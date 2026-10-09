use super::*;
#[path = "protected_runtime_tests/approval_crash.rs"]
pub mod approval_crash;
#[path = "protected_runtime_tests/fixture.rs"]
mod fixture;
#[path = "protected_runtime_tests/lifecycle.rs"]
mod lifecycle;
#[path = "protected_runtime_tests/process.rs"]
mod process;
use fixture::*;
use process::*;
use runne_platform_desktop::permission_reauth_linux::{
    NativePermissionWarningMainThreadScheduler, NativePermissionWarningUiTask, PamCancellation,
    PamConversationHandler, PamInteractionError, PamMessageKind,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn parsed(arguments: &[&str]) -> Result<PathBuf, CliError> {
    let state = parse_global_options(arguments.iter().map(OsString::from).collect())?;
    protected_runtime_owner::parse_invocation(state).map(|(path, _)| path)
}

#[test]
fn protected_runtime_root_is_an_explicit_permissions_alternative() {
    let root = parsed(&[
        "permissions",
        "--protected-runtime-root",
        "/tmp/runne-root",
        "status",
        "--workspace-id",
        "018f2e3a-7000-7000-8000-000000000001",
    ])
    .expect("explicit protected-root permission read parses");
    assert_eq!(root, PathBuf::from("/tmp/runne-root"));
}

#[test]
fn protected_runtime_root_rejects_profile_relative_root_and_non_permissions_commands() {
    assert!(matches!(
        parsed(&[
            "--profile",
            "/tmp/profile",
            "permissions",
            "--protected-runtime-root",
            "/tmp/root",
            "approvals",
            "list",
        ]),
        Err(CliError::Usage)
    ));
    assert!(matches!(
        parsed(&[
            "permissions",
            "--protected-runtime-root",
            "relative",
            "approvals",
            "list"
        ]),
        Err(CliError::Usage)
    ));
    assert!(matches!(
        parsed(&["conversation", "--protected-runtime-root", "/tmp/root"]),
        Err(CliError::Usage)
    ));
}

#[test]
fn protected_runtime_root_keeps_approval_response_on_existing_confirmation_path() {
    assert_eq!(
        parsed(&[
            "permissions",
            "--protected-runtime-root",
            "/tmp/root",
            "approvals",
            "respond",
            "--approval-id",
            "018f2e3a-7000-7000-8000-000000000001",
            "--decision",
            "approve",
            "--command-id",
            "018f2e3a-7000-7000-8000-000000000002",
            "--idempotency-key",
            "same-command-key",
        ])
        .expect("approval response parses for protected owner"),
        PathBuf::from("/tmp/root")
    );
}

struct RefuseNativeUi;

impl NativePermissionWarningMainThreadScheduler for RefuseNativeUi {
    fn schedule(&self, _: NativePermissionWarningUiTask) -> Result<(), ()> {
        Err(())
    }
}

impl PamConversationHandler for RefuseNativeUi {
    fn present(
        &self,
        _: PamMessageKind,
        _: &str,
        _: &PamCancellation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
        Err(PamInteractionError::Cancelled)
    }
}

/// Child entry uses the real protected CLI owner and daemon; native evidence is
/// supplied only by the existing cfg(test) mock-authority API.
#[test]
fn protected_runtime_subprocess_entry() {
    let Ok(arguments) = std::env::var("RUNNE_CLI_OWNER_ARGS") else {
        return;
    };
    let arguments: Vec<String> = serde_json::from_str(&arguments).expect("child arguments");
    let arguments = arguments.into_iter().map(OsString::from).collect();
    let outcome = if std::env::var_os("RUNNE_CLI_OWNER_UI_ENTRY").is_some() {
        crate::run_entrypoint(arguments)
    } else {
        protected_runtime_owner::run(
            arguments,
            Arc::new(RefuseNativeUi),
            Arc::new(RefuseNativeUi),
        )
    };
    let result = serde_json::json!({
        "stdout": outcome.stdout,
        "stderr": outcome.stderr,
        "exitCode": outcome.exit_code,
    });
    std::fs::write(
        std::env::var_os("RUNNE_CLI_OWNER_RESULT").expect("child result path"),
        serde_json::to_vec(&result).expect("encode child result"),
    )
    .expect("write child result");
}

/// Test-only lifecycle barriers are inert unless the child test names one.
pub fn barrier(name: &str) {
    if std::env::var("RUNNE_CLI_OWNER_BARRIER").as_deref() != Ok(name) {
        return;
    }
    let directory =
        PathBuf::from(std::env::var_os("RUNNE_CLI_OWNER_BARRIER_DIR").expect("barrier directory"));
    std::fs::write(directory.join(format!("ready-{name}")), b"ready")
        .expect("publish lifecycle barrier");
    let deadline = Instant::now() + Duration::from_mins(3);
    while !directory.join(format!("release-{name}")).exists() {
        assert!(
            Instant::now() < deadline,
            "lifecycle barrier timed out: {name}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn record_mock_native_consent() {
    if let Some(path) = std::env::var_os("RUNNE_CLI_MOCK_NATIVE_LOG") {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("mock-native-consent log")
            .write_all(b"mock-native-consent\n")
            .expect("record mock-native-consent");
    }
}

pub fn mock_native_consent(
    runtime: &protected_runtime_owner::ProtectedPermissionsRuntime<'_>,
    expires_at_unix_ms: u64,
) -> Result<bool, ModeApiError> {
    super::permission_ceremony_deadline(expires_at_unix_ms).ok_or_else(unavailable_mode_error)?;
    let _ = (&runtime.scheduler, &runtime.pam);
    let mut supervisor = runtime
        .supervisor
        .lock()
        .map_err(|_| unavailable_mode_error())?;
    supervisor
        .test_complete_permission_mode_with_mock_native_authority()
        .map_err(|_| unavailable_mode_error())?;
    drop(supervisor);
    record_mock_native_consent();
    Ok(true)
}
