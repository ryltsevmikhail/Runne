#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use gocode_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeStopDisposition, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor,
};
use gocode_runtime_client::RuntimeTransportKind;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_bundled_process_rotates_session_restarts_and_stops_owned_child() {
    let temporary = tempfile::tempdir().expect("temporary runtime root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec");
    let runtime_root = spec.runtime_root().to_path_buf();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    supervisor.start().expect("first protected launch");
    assert_eq!(
        supervisor.state(),
        BundledRuntimeLifecycleState::Handshaking
    );
    let initial_profile = supervisor
        .take_runtime_profile()
        .expect("initial one-time profile");
    let initial_client = initial_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected client");
    assert_eq!(
        initial_client.transport_kind(),
        RuntimeTransportKind::ProtectedBundled
    );
    supervisor
        .record_client_ready(&initial_client)
        .expect("exact initial readiness");
    let initial = initial_client.session_info().clone();

    let renewed_profile = supervisor.renew_profile().expect("session renewal");
    let renewed_client = renewed_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed protected client");
    supervisor
        .record_client_ready(&renewed_client)
        .expect("exact renewed readiness");
    let renewed = renewed_client.session_info().clone();
    assert_eq!(renewed.authority_id, initial.authority_id);
    assert_eq!(renewed.event_log_lineage_id, initial.event_log_lineage_id);
    assert_eq!(renewed.daemon_instance_id, initial.daemon_instance_id);
    assert_eq!(renewed.launch_generation, initial.launch_generation);
    assert_ne!(renewed.session_id, initial.session_id);

    assert_eq!(
        supervisor.stop().expect("graceful owned stop"),
        BundledRuntimeStopDisposition::Graceful
    );
    assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    assert!(!supervisor.owns_runtime());

    let stable_record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            runtime_root
                .join(".desktop-protected-activation")
                .join("stable-binding-v1.json"),
        )
        .expect("stable activation record"),
    )
    .expect("stable record JSON");
    let authority = stable_record["authority_id"]
        .as_array()
        .expect("stable authority")
        .iter()
        .map(|value| u8::try_from(value.as_u64().expect("authority byte")).expect("u8 byte"))
        .collect::<Vec<_>>();
    assert_eq!(hex::encode(&authority), initial.authority_id);
    let sidecar = std::fs::read(
        runtime_root
            .join("gocode-daemon")
            .join("local-session-authority-id"),
    )
    .expect("authority sidecar");
    assert_eq!(sidecar, authority);

    supervisor.start().expect("fresh protected restart");
    let restarted_profile = supervisor
        .take_runtime_profile()
        .expect("restart one-time profile");
    let restarted_client = restarted_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("restarted protected client");
    supervisor
        .record_client_ready(&restarted_client)
        .expect("exact restarted readiness");
    let restarted = restarted_client.session_info();
    assert_eq!(restarted.authority_id, initial.authority_id);
    assert_eq!(restarted.event_log_lineage_id, initial.event_log_lineage_id);
    assert_ne!(restarted.daemon_instance_id, initial.daemon_instance_id);
    assert_ne!(restarted.session_id, initial.session_id);
    assert_eq!(restarted.launch_generation, initial.launch_generation + 1);

    let activation_directory = runtime_root.join(".desktop-protected-activation");
    for record in std::fs::read_dir(activation_directory).expect("activation records") {
        let path = record.expect("activation record").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(path).expect("record bytes");
        let text = String::from_utf8(bytes).expect("record JSON");
        assert!(!text.contains("secret"));
        assert!(!text.contains("bootstrap"));
        assert!(!text.contains("credential"));
        assert!(!text.contains("endpoint"));
    }

    assert_eq!(
        supervisor.stop().expect("second graceful owned stop"),
        BundledRuntimeStopDisposition::Graceful
    );
}
