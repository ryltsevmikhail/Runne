#![cfg(all(target_os = "linux", feature = "desktop-protected"))]

//! Production-path regression for the Linux local enrollment lifecycle: a
//! real bundled daemon starts at authorization epoch 0, the supervisor-run
//! V2→V3 enrollment transition raises it to exactly 1 before the first
//! client connection, the enrolled V3 client renews over the wall-clock
//! ticket domain, and the owned child stops gracefully.

#[path = "support/owner_private.rs"]
mod owner_private;

use std::sync::Arc;
use std::time::Duration;

use runne_app_core::{AppCore, RuntimeAvailability};
use runne_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeStopDisposition, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor,
};
use runne_runtime_client::RuntimeTransportKind;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_local_enrollment_connects_renews_and_installs_on_the_production_path() {
    let temporary = owner_private::tempdir();
    let profile_directory = temporary.path().join("com.runne.desktop");
    std::fs::create_dir(&profile_directory).expect("profile directory");
    owner_private::secure_directory(&profile_directory);
    let runtime_root = profile_directory.join("bundled-runtime");
    // The provider-bound composition stages the colocated credential writer
    // next to the daemon, so the controlled directory carries both binaries.
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable.path(), &runtime_root)
        .expect("protected launch spec")
        // The production Linux composition launches with provider activation so
        // the daemon admits a V2 enrollment-capable launch (never a bare V1).
        .with_openai_provider_activation();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    supervisor.start().expect("V2 protected launch");
    assert_eq!(
        supervisor.state(),
        BundledRuntimeLifecycleState::Handshaking
    );

    // The V2→V3 enrollment transition replaces the pending epoch-0 V2
    // profile with the enrolled epoch-1 V3 profile in place.
    supervisor
        .begin_local_linux_enrollment_transition()
        .expect("linux local enrollment transition");
    let enrolled_profile = supervisor
        .take_runtime_profile()
        .expect("enrolled V3 profile");
    let enrolled_client = enrolled_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("enrolled V3 client connect");
    assert_eq!(
        enrolled_client.transport_kind(),
        RuntimeTransportKind::ProtectedBundled
    );
    let enrolled = enrolled_client.session_info().clone();
    assert_eq!(
        enrolled.authorization_epoch, 1,
        "the enrollment transition must raise the epoch to exactly 1"
    );
    supervisor
        .record_client_ready(&enrolled_client)
        .expect("enrolled readiness");

    // The V3 renewal must work on Linux over the shared unix wall-clock
    // ticket domain instead of failing closed as on the pre-fix tree.
    supervisor
        .queue_renewal_profile()
        .expect("V3 renewal on Linux");
    let renewed_profile = supervisor
        .take_runtime_profile()
        .expect("renewed V3 profile");
    let renewed_client = renewed_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed V3 client connect");
    let renewed = renewed_client.session_info().clone();
    assert_eq!(renewed.authorization_epoch, 1);
    assert_eq!(renewed.authority_id, enrolled.authority_id);
    assert_eq!(renewed.daemon_instance_id, enrolled.daemon_instance_id);
    assert_eq!(
        renewed.launch_generation, enrolled.launch_generation,
        "the V3 renewal rotates the session without a restart generation bump"
    );
    assert_ne!(renewed.session_id, enrolled.session_id);
    supervisor
        .record_client_ready(&renewed_client)
        .expect("renewed readiness");

    // The exact post-transition client must be installable into AppCore:
    // before the epoch-contract fix this open ended in RuntimeUnavailable
    // because the connected session still carried the pre-transition epoch.
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
        core.install_bundled_runtime_client(lease, renewed_client)
            .await
            .expect("install enrolled client"),
        RuntimeAvailability::Live
    );
    let marker = project_directory.join("marker.txt");
    std::fs::write(&marker, b"local enrollment marker").expect("write marker");
    core.open_local_project(&project_directory)
        .expect("open enrolled local project");
    drop(core);

    assert_eq!(
        supervisor.stop().expect("graceful enrolled stop"),
        BundledRuntimeStopDisposition::Graceful
    );
    assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    assert!(marker.exists(), "the enrolled project marker survives");
}
