use super::*;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_linux_baseline_v2_remains_usable_without_installed_enrollment() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        &temporary.path().join("bundled-runtime"),
    )
    .unwrap()
    .with_openai_provider_activation();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor.start().unwrap();
    let profile = supervisor.take_runtime_profile().unwrap();
    assert!(profile.enrollment_owned_launch().is_none());
    let client = profile.connect(Duration::from_secs(10)).await.unwrap();
    assert_eq!(client.session_info().authorization_epoch, 0);
    supervisor.record_client_ready(&client).unwrap();
    let (_, facts) = supervisor.linux_activation_context().unwrap();
    assert_eq!(
        hex::encode(facts.runtime_authority_id),
        client.session_info().authority_id
    );
    supervisor.stop().unwrap();
}

/// Measures a real protected V2 daemon. The writer fixture is never executed;
/// this test proves installation binding, not native credential enrollment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_gate_facts_follow_live_v2_authority_and_deny_after_stop() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        &temporary.path().join("runtime"),
    )
    .unwrap()
    .with_openai_provider_activation();
    let root = spec.runtime_root().to_path_buf();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    assert!(supervisor.linux_activation_context().is_err());
    supervisor.start().expect("protected V2 launch");
    assert!(
        supervisor.linux_activation_context().is_err(),
        "unacknowledged profile is not ready"
    );
    let client = supervisor
        .take_runtime_profile()
        .unwrap()
        .connect(Duration::from_secs(10))
        .await
        .unwrap();
    supervisor.record_client_ready(&client).unwrap();
    let (measured_root, facts) = supervisor.linux_activation_context().expect("live context");
    assert_eq!(measured_root, root);
    assert_eq!(
        hex::encode(facts.runtime_authority_id),
        client.session_info().authority_id
    );
    let expected: [u8; 32] = Sha256::digest(std::fs::read(executable.path()).unwrap()).into();
    assert_eq!(facts.daemon_image_digest, expected);
    assert_eq!(
        facts.writer_image_digest, expected,
        "explicit inert writer fixture"
    );
    // Actual staged layout is unrelated to the daemon's bootstrap profile dir.
    assert_ne!(
        executable.path().parent().unwrap(),
        root.join("runne-daemon")
    );
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        supervisor.linux_activation_context().is_err(),
        "changed root permissions must deny"
    );
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(supervisor.linux_activation_context().is_ok());
    std::fs::remove_file(root.join(".desktop-protected-activation/executables-v1/runne")).unwrap();
    assert!(
        supervisor.linux_activation_context().is_err(),
        "missing staged writer must deny"
    );
    supervisor.stop().unwrap();
    assert!(supervisor.linux_activation_context().is_err());
}
