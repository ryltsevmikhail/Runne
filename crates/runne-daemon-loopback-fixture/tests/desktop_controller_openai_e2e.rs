#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use runne_app_core::{AppCore, RuntimeAvailability, RuntimeMode};
use runne_desktop::{
    BundledRuntimeController, BundledShutdownOutcome, NativeOpenAiActivationTestGate,
    OwnedRuntimeLifecycle,
};

fn copied_executable(source: &Path, destination: PathBuf) -> PathBuf {
    std::fs::copy(source, &destination).expect("copy controlled fixture executable");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o755))
        .expect("mark controlled fixture executable");
    destination
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_desktop_controller_uses_exact_openai_v2_without_v1_downgrade() {
    let temporary = tempfile::tempdir().expect("temporary desktop profile");
    let fixture = Path::new(env!("CARGO_BIN_EXE_activation_process"));
    let desktop = copied_executable(fixture, temporary.path().join("runne-desktop"));
    copied_executable(fixture, temporary.path().join("runned"));

    let core = Arc::new(
        AppCore::open_with_runtime_mode(
            &temporary.path().join("profile.sqlite3"),
            RuntimeMode::Bundled,
        )
        .expect("open bundled desktop core"),
    );
    let controller = BundledRuntimeController::discover_with_loopback_openai_activation(
        Arc::clone(&core),
        &desktop,
        &temporary.path().join("bundled-runtime"),
        NativeOpenAiActivationTestGate::loopback_fixture(),
    )
    .expect("discover bundled production daemon fixture");

    assert_eq!(
        controller
            .connect_runtime()
            .await
            .expect("protected V2 connection"),
        RuntimeAvailability::Live
    );
    assert_eq!(
        core.bootstrap().expect("sanitized bootstrap").runtime,
        RuntimeAvailability::Live
    );

    let shutdown_controller = Arc::clone(&controller);
    tokio::task::spawn_blocking(move || shutdown_controller.stop_on_explicit_quit())
        .await
        .expect("join explicit desktop shutdown");
    assert!(matches!(
        controller.shutdown_outcome(),
        Some(BundledShutdownOutcome::Graceful | BundledShutdownOutcome::Forced)
    ));
}
