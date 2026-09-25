#![cfg(all(target_os = "linux", feature = "desktop-protected"))]

//! Production-path regression for the Linux baseline runtime lifecycle: a
//! real bundled daemon starts at authorization epoch 0 and remains usable
//! without installed signed enrollment evidence.

#[path = "support/owner_private.rs"]
mod owner_private;

use std::sync::Arc;
use std::time::Duration;

use runne_app_core::{AppCore, RuntimeAvailability};
use runne_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeStopDisposition, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_baseline_v2_connects_and_installs_without_signed_enrollment() {
    let temporary = owner_private::tempdir();
    let profile_directory = temporary.path().join("com.runne.desktop");
    std::fs::create_dir(&profile_directory).expect("profile directory");
    owner_private::secure_directory(&profile_directory);
    let runtime_root = profile_directory.join("bundled-runtime");
    // The controlled executable is suitable for a protected V2 launch, but
    // carries no signed installed enrollment tuple or writer capability.
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable.path(), &runtime_root)
        .expect("protected launch spec")
        // Provider activation preserves the baseline protected V2 runtime path.
        .with_openai_provider_activation();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    supervisor.start().expect("V2 protected launch");
    assert_eq!(
        supervisor.state(),
        BundledRuntimeLifecycleState::Handshaking
    );

    let baseline_profile = supervisor
        .take_runtime_profile()
        .expect("baseline V2 profile");
    let baseline_client = baseline_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("baseline V2 client connect");
    let baseline = baseline_client.session_info().clone();
    assert_eq!(
        baseline.authorization_epoch, 0,
        "without installed signed evidence startup remains on the baseline epoch"
    );
    supervisor
        .record_client_ready(&baseline_client)
        .expect("baseline readiness");

    // The exact baseline client must remain installable into AppCore.
    let desktop_database = temporary.path().join("desktop-profile.sqlite3");
    let project_directory = temporary.path().join("project");
    std::fs::create_dir(&project_directory).expect("project directory");
    let profile_key = [0x5A; 32];
    let core = AppCore::open_bundled_anchored(
        &desktop_database,
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile_key)),
        profile_key,
    )
    .expect("bundled AppCore");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin AppCore activation");
    assert_eq!(
        core.install_bundled_runtime_client(lease, baseline_client)
            .await
            .expect("install baseline client"),
        RuntimeAvailability::Live
    );
    let marker = project_directory.join("marker.txt");
    std::fs::write(&marker, b"local enrollment marker").expect("write marker");
    core.open_local_project(&project_directory)
        .expect("open local project");
    drop(core);

    assert_eq!(
        supervisor.stop().expect("graceful enrolled stop"),
        BundledRuntimeStopDisposition::Graceful
    );
    assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    assert!(marker.exists(), "the enrolled project marker survives");
}
