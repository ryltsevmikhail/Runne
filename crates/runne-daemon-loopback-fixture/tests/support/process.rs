#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use runne_api::ProviderActivationBindingV1;
use runne_platform_desktop::{
    BundledRuntimeProcessStatus, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeProcess,
};
use runne_runtime_client::AuthenticatedRuntimeClient;

const PROTECTED_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Monotonic suffix so repeated launches into one fixture root never collide
/// with a stale fixture socket file.
#[cfg(target_os = "linux")]
static SESSION_BUS_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Binds one real session-bus fixture socket inside the owner-private fixture
/// root and returns its strictly valid socket path.
///
/// The listener is dropped immediately: the socket file survives (absolute
/// path, socket type, own-euid ownership), while connections to it are
/// refused instantly — the exact fast-fail a host without a session bus
/// produces, so Linux provider-bound launches do not depend on a real bus.
/// `with_validated_session_bus_address` re-validates the path through the
/// strict production checks before injecting it into the launch spec.
#[cfg(target_os = "linux")]
fn fixture_session_bus(root: &Path) -> PathBuf {
    let sequence = SESSION_BUS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let socket_path = root.join(format!("session-bus-{sequence}.sock"));
    let listener = UnixListener::bind(&socket_path).expect("fixture session bus socket");
    drop(listener);
    socket_path
}

pub fn executable(name: &str, fixture_root: &Path) -> PathBuf {
    let source = match name {
        "activation_process" => PathBuf::from(env!("CARGO_BIN_EXE_activation_process")),
        "recovery_process" => PathBuf::from(env!("CARGO_BIN_EXE_recovery_process")),
        _ => panic!("unknown fixture executable"),
    };
    let destination = fixture_root.join(name);

    #[cfg(unix)]
    std::fs::set_permissions(fixture_root, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture executable root owner-private");
    std::fs::copy(&source, &destination).expect("copy fixture executable into owner-private root");
    #[cfg(unix)]
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
        .expect("make copied fixture executable owner-private");
    let writer = fixture_root.join("runne");
    std::fs::copy(&source, &writer).expect("stage fixture-owned writer identity");
    #[cfg(unix)]
    std::fs::set_permissions(&writer, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture writer owner-private");

    destination
}

fn openai_spec(executable: &Path, runtime_root: &Path) -> ProtectedBundledRuntimeLaunchSpec {
    // The fixture root (runtime_root's parent) is the owner-private tempdir.
    #[cfg(target_os = "linux")]
    let session_bus_socket =
        fixture_session_bus(runtime_root.parent().expect("owner-private fixture root"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable, runtime_root)
        .expect("owner-private protected fixture spec")
        .with_provider_activation(ProviderActivationBindingV1::openai_responses_text_v1());
    #[cfg(target_os = "linux")]
    let spec = spec
        .with_validated_session_bus_address(&session_bus_socket)
        .expect("fixture session bus address");
    spec
}

pub async fn protected_client(
    process: &mut ProtectedBundledRuntimeProcess,
) -> AuthenticatedRuntimeClient {
    let profile = process
        .take_runtime_profile()
        .expect("one-time protected profile");
    let client = profile
        .connect(PROTECTED_CLIENT_TIMEOUT)
        .await
        .expect("authenticated protected runtime client");
    assert!(process.matches_client(&client));
    client
}

pub fn stop(mut process: ProtectedBundledRuntimeProcess) {
    stop_owned(&mut process);
}

/// Stops the disposable fixture and returns bounded diagnostics for an
/// unexpected runtime response. The child output is reduced to fixed
/// categories so payloads, credentials, and correlation values are omitted.
#[allow(dead_code)]
pub fn stop_with_diagnostic(
    mut process: ProtectedBundledRuntimeProcess,
    runtime_root: &Path,
) -> String {
    let shutdown = if process.request_graceful_stop().is_ok() {
        process
            .wait_for_exit(Duration::from_secs(10))
            .map(|status| match status {
                BundledRuntimeProcessStatus::Exited => "graceful_reap",
                BundledRuntimeProcessStatus::Running => "reap_still_running",
            })
            .unwrap_or("reap_failed")
    } else {
        "graceful_stop_failed"
    };
    let stderr = process
        .take_captured_output_for_test()
        .map(|(_, stderr)| stderr)
        .unwrap_or_default();
    format!(
        "shutdown={shutdown} {} {}",
        super::execution::diagnostic_stage(runtime_root),
        summarize_child_stderr(&stderr)
    )
}

fn stop_owned(process: &mut ProtectedBundledRuntimeProcess) {
    process
        .request_graceful_stop()
        .expect("authenticated fixture shutdown");
    assert_eq!(
        process
            .wait_for_exit(Duration::from_secs(10))
            .expect("reap owned fixture child"),
        BundledRuntimeProcessStatus::Exited
    );
}

fn summarize_child_stderr(stderr: &[u8]) -> String {
    const MAX_BYTES: usize = 4096;
    let bounded = &stderr[..stderr.len().min(MAX_BYTES)];
    let mut categories = Vec::new();
    for line in String::from_utf8_lossy(bounded).lines() {
        let category = if line.contains("fatal: protected activation failed") {
            "protected_activation_failed"
        } else if line.contains("fatal: protected activation channel failed") {
            "protected_channel_failed"
        } else if line.contains("fatal: bootstrap error") {
            "bootstrap_failed"
        } else if line.contains("panicked at") {
            "panic"
        } else if line.contains("ERROR") || line.contains("error") {
            "error"
        } else if !line.trim().is_empty() {
            "other"
        } else {
            continue;
        };
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    format!(
        "child_stderr_bytes={} bounded_bytes={} categories={categories:?}",
        stderr.len(),
        bounded.len()
    )
}

#[allow(dead_code)]
pub fn launch(executable: &Path, root: &Path) -> ProtectedBundledRuntimeProcess {
    DevelopmentBundledRuntimeLauncher::new()
        .launch(&openai_spec(executable, root))
        .expect("protected OpenAI V2 fixture launch")
}

#[allow(dead_code)]
pub fn launch_with_output(executable: &Path, root: &Path) -> ProtectedBundledRuntimeProcess {
    DevelopmentBundledRuntimeLauncher::new()
        .launch_for_test(&openai_spec(executable, root), [0x5a; 32], true, None)
        .expect("protected OpenAI V2 fixture launch")
}

#[cfg(test)]
mod tests {
    use super::summarize_child_stderr;

    #[test]
    fn child_stderr_summary_is_bounded_and_redacted() {
        let stderr = format!(
            "panicked at secret-payload\ncredential=secret\n{}",
            "x".repeat(8_192)
        );
        let summary = summarize_child_stderr(stderr.as_bytes());
        assert!(summary.contains("categories=[\"panic\", \"other\"]"));
        assert!(!summary.contains("secret-payload"));
        assert!(!summary.contains("credential"));
        assert!(summary.contains("bounded_bytes=4096"));
    }
}
