#![cfg(unix)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use gocode_api::ProviderActivationBindingV1;
use gocode_app_core::{AppCore, RuntimeAvailability, RuntimeMode};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_application::verification::export_port::VerificationExporter;
use gocode_domain::verification::backup::StreamInventory;
use gocode_domain::verification::digest::VerificationDigest;
use gocode_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeProcessStatus, BundledRuntimeStopDisposition,
    DevelopmentBundledRuntimeLauncher, FirstActivationFaultPoint, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor,
};
use gocode_runtime_client::RuntimeTransportKind;
use gocode_security::SecretBroker;
use gocode_store::verification::backup_store::InMemoryBackupStore;
use rand::{RngCore as _, rngs::OsRng};

fn random_secret() -> [u8; 32] {
    let mut value = [0_u8; 32];
    while value == [0; 32] {
        OsRng.fill_bytes(&mut value);
    }
    value
}

fn material_representations(materials: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut representations = Vec::new();
    for material in materials {
        let standard = base64::engine::general_purpose::STANDARD.encode(material);
        representations.extend([
            material.clone(),
            standard.as_bytes().to_vec(),
            standard.trim_end_matches('=').as_bytes().to_vec(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(material)
                .into_bytes(),
            hex::encode(material).into_bytes(),
            hex::encode_upper(material).into_bytes(),
        ]);
    }
    representations
}

fn assert_absent(kind: &str, bytes: &[u8], representations: &[Vec<u8>]) {
    for representation in representations {
        assert!(
            !bytes
                .windows(representation.len())
                .any(|window| window == representation),
            "{kind} contained protected material"
        );
    }
}

fn assert_tree_absent(root: &std::path::Path, representations: &[Vec<u8>]) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("read audited directory")
                    .map(|entry| entry.expect("audited entry").path()),
            );
        } else if path.is_file() {
            assert_absent(
                path.to_string_lossy().as_ref(),
                &std::fs::read(&path).expect("read audited artifact"),
                representations,
            );
        }
    }
}

fn assert_tracked_fixtures_absent(representations: &[Vec<u8>]) {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository)
        .output()
        .expect("list tracked fixtures");
    assert!(tracked.status.success());
    for relative in tracked.stdout.split(|byte| *byte == 0) {
        if relative.is_empty() {
            continue;
        }
        let path = repository.join(String::from_utf8_lossy(relative).as_ref());
        if path.is_file() {
            assert_absent(
                path.to_string_lossy().as_ref(),
                &std::fs::read(&path).expect("read tracked file"),
                representations,
            );
        }
    }
}

#[test]
fn early_child_exit_closes_the_inherited_channel_without_readiness_timeout() {
    let executable = PathBuf::from("/usr/bin/false");
    assert!(
        executable.is_file(),
        "direct-exec false fixture is required"
    );
    let temporary = tempfile::tempdir().expect("temporary early-exit root");
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("early-exit launch spec");
    let started = Instant::now();
    assert_eq!(
        DevelopmentBundledRuntimeLauncher::new()
            .launch(&spec)
            .expect_err("early child exit must close the protected channel"),
        ProtectedBundledRuntimeError::ProtectedChannelUnavailable
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an exited child must not be reported as a readiness timeout"
    );
}

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

    supervisor
        .queue_renewal_profile()
        .expect("queue session renewal");
    let renewed_profile = supervisor
        .take_runtime_profile()
        .expect("renewed one-time profile");
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

    let desktop_database = temporary.path().join("desktop-profile.sqlite3");
    let project_directory = temporary.path().join("project");
    std::fs::create_dir(&project_directory).expect("project directory");
    let core = AppCore::open_with_runtime_mode(&desktop_database, RuntimeMode::Bundled)
        .expect("bundled AppCore");
    let initial_lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin protected AppCore activation");
    assert_eq!(
        core.install_bundled_runtime_client(initial_lease, renewed_client)
            .await
            .expect("install protected client"),
        RuntimeAvailability::Live
    );
    let project = core
        .open_local_project(&project_directory)
        .expect("open local project");
    core.open_project_conversation(project.id)
        .await
        .expect("open runtime conversation");
    let before_restart = core
        .send_project_message(project.id, "first protected message")
        .await
        .expect("send before restart");
    assert_eq!(before_restart.messages.len(), 2);
    let before_ids = before_restart
        .messages
        .iter()
        .map(|message| message.message_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        before_ids.iter().collect::<HashSet<_>>().len(),
        before_ids.len()
    );

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
    let daemon_profile_directory = runtime_root.join("gocode-daemon");
    assert!(
        !daemon_profile_directory
            .join("client-profile.json")
            .exists()
    );
    assert!(
        std::fs::read_dir(&daemon_profile_directory)
            .expect("daemon profile directory")
            .all(|entry| {
                let name = entry
                    .expect("daemon profile entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned();
                !name.starts_with("bootstrap-") && !name.ends_with(".secret")
            })
    );

    let restart_lease = core
        .begin_bundled_runtime_restart()
        .await
        .expect("fence old AppCore session");
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
    let restarted = restarted_client.session_info().clone();
    assert_eq!(restarted.authority_id, initial.authority_id);
    assert_eq!(restarted.event_log_lineage_id, initial.event_log_lineage_id);
    assert_ne!(restarted.daemon_instance_id, initial.daemon_instance_id);
    assert_ne!(restarted.session_id, initial.session_id);
    assert_eq!(restarted.launch_generation, initial.launch_generation + 1);
    core.install_bundled_runtime_client(restart_lease, restarted_client)
        .await
        .expect("install restarted protected client");

    let resumed = core
        .open_project_conversation(project.id)
        .await
        .expect("resume conversation after restart");
    assert_eq!(
        resumed
            .messages
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<Vec<_>>(),
        before_ids.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let after_restart = core
        .send_project_message(project.id, "second protected message")
        .await
        .expect("send after restart");
    assert_eq!(after_restart.messages.len(), 4);
    assert_eq!(
        after_restart
            .messages
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<HashSet<_>>()
            .len(),
        after_restart.messages.len()
    );

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_bound_v2_bundled_process_renews_and_stops_without_v1_downgrade() {
    let temporary = tempfile::tempdir().expect("temporary V2 runtime root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec")
            .with_provider_activation(ProviderActivationBindingV1::deterministic_v1());
    let mut process = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("provider-bound V2 launch");
    assert_eq!(
        process.provider_activation(),
        Some(&ProviderActivationBindingV1::deterministic_v1())
    );

    let initial = process
        .take_runtime_profile()
        .expect("initial V2 profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("initial V2 session");
    assert!(process.matches_client(&initial));
    let initial_session = initial.session_info().clone();

    let renewed = process
        .renew_profile()
        .expect("V2 renewal")
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed V2 session");
    assert!(process.matches_client(&renewed));
    assert_eq!(
        renewed.session_info().authority_id,
        initial_session.authority_id
    );
    assert_eq!(
        renewed.session_info().event_log_lineage_id,
        initial_session.event_log_lineage_id
    );
    assert_ne!(
        renewed.session_info().session_id,
        initial_session.session_id
    );

    process
        .request_graceful_stop()
        .expect("V2 authenticated shutdown");
    assert_eq!(
        process
            .wait_for_exit(Duration::from_secs(5))
            .expect("V2 daemon exit"),
        BundledRuntimeProcessStatus::Exited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proven_owned_crash_recovers_the_exact_stable_hot_wal_binding() {
    let temporary = tempfile::tempdir().expect("temporary crash root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec");

    let mut crashed = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("initial protected runtime");
    let initial_client = crashed
        .take_runtime_profile()
        .expect("initial protected profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected session");
    assert!(crashed.matches_client(&initial_client));
    let initial = initial_client.session_info().clone();
    drop(initial_client);

    crashed.terminate().expect("terminate exact owned child");
    assert_eq!(
        crashed
            .wait_for_exit(Duration::from_secs(5))
            .expect("reap exact owned child"),
        BundledRuntimeProcessStatus::Exited
    );
    let database = spec.runtime_root().join("gocode-daemon/event-log.db");
    assert!(
        database.with_extension("db-wal").exists() || database.with_extension("db-shm").exists(),
        "owned crash must exercise the hot-WAL recovery path"
    );
    drop(crashed);

    let mut recovered = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("recover exact stable protected runtime");
    let recovered_client = recovered
        .take_runtime_profile()
        .expect("recovered protected profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("recovered protected session");
    assert!(recovered.matches_client(&recovered_client));
    let current = recovered_client.session_info();
    assert_eq!(current.authority_id, initial.authority_id);
    assert_eq!(current.event_log_lineage_id, initial.event_log_lineage_id);
    assert_eq!(current.launch_generation, initial.launch_generation + 1);
    assert_ne!(current.daemon_instance_id, initial.daemon_instance_id);
    assert_ne!(current.session_id, initial.session_id);

    recovered
        .request_graceful_stop()
        .expect("authenticated recovered shutdown");
    assert_eq!(
        recovered
            .wait_for_exit(Duration::from_secs(5))
            .expect("recovered exit"),
        BundledRuntimeProcessStatus::Exited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_activation_recovers_across_crash_and_durable_write_fault_matrix() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    for fault in [
        FirstActivationFaultPoint::BeforePreparePersistence,
        FirstActivationFaultPoint::AfterPrepareFileSync,
        FirstActivationFaultPoint::AfterPreparePersistence,
        FirstActivationFaultPoint::BeforeCommit,
        FirstActivationFaultPoint::AfterCommit,
        FirstActivationFaultPoint::AfterEventLogCreation,
        FirstActivationFaultPoint::BeforeFinalPin,
        FirstActivationFaultPoint::AfterFinalPinFileSync,
        FirstActivationFaultPoint::AfterFinalPin,
    ] {
        let temporary = tempfile::tempdir().expect("temporary fault root");
        let spec =
            ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
                .expect("protected launch spec");
        let activation = spec.runtime_root().join(".desktop-protected-activation");
        let pending_path = activation.join("pending-first-activation-v1.json");
        let stable_path = activation.join("stable-binding-v1.json");

        let error = DevelopmentBundledRuntimeLauncher::new()
            .launch_for_test(&spec, random_secret(), false, Some(fault))
            .expect_err("injected activation fault must abort and reap the child");
        assert_eq!(
            error,
            ProtectedBundledRuntimeError::ActivationStateUnavailable
        );

        let prepared_stable = if pending_path.exists() {
            let pending: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&pending_path).expect("read durable pending activation"),
            )
            .expect("pending activation JSON");
            Some(pending["stable"].clone())
        } else {
            None
        };

        let mut recovered = DevelopmentBundledRuntimeLauncher::new()
            .launch(&spec)
            .unwrap_or_else(|error| panic!("exact recovery after {fault:?}: {error}"));
        let profile = recovered
            .take_runtime_profile()
            .expect("recovered one-time profile");
        let client = profile
            .connect(Duration::from_secs(10))
            .await
            .unwrap_or_else(|error| panic!("recovered session after {fault:?}: {error}"));
        assert!(recovered.matches_client(&client));
        let stable: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&stable_path).expect("final stable pin"))
                .expect("stable JSON");
        if let Some(prepared_stable) = prepared_stable {
            assert_eq!(
                stable, prepared_stable,
                "recovery after {fault:?} must preserve the exact preparation"
            );
        }
        assert!(
            !pending_path.exists(),
            "recovery after {fault:?} must finish the exact final pin"
        );
        assert!(
            spec.runtime_root()
                .join("gocode-daemon/event-log.db")
                .exists(),
            "recovery after {fault:?} must leave one usable Event Log"
        );
        recovered
            .request_graceful_stop()
            .expect("authenticated recovered shutdown");
        assert_eq!(
            recovered
                .wait_for_exit(Duration::from_secs(10))
                .expect("wait for recovered child"),
            gocode_platform_desktop::BundledRuntimeProcessStatus::Exited
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_protected_material_is_absent_from_every_forbidden_local_sink() {
    let temporary = tempfile::tempdir().expect("temporary audit root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec");
    let runtime_root = spec.runtime_root().to_path_buf();
    let launch_secret = random_secret();
    let mut process = DevelopmentBundledRuntimeLauncher::new()
        .launch_for_test(&spec, launch_secret, true, None)
        .expect("audited protected launch");

    let initial_profile = process
        .take_runtime_profile()
        .expect("initial audited profile");
    let initial_bootstrap = initial_profile.test_bootstrap_material();
    let activation_keys = process.test_activation_key_material().into_values();
    let initial_client = initial_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("initial audited client");
    let initial_session_authority = initial_client.test_session_authority();
    assert!(process.matches_client(&initial_client));

    let renewed_profile = process.renew_profile().expect("audited renewal ticket");
    let renewal_bootstrap_ticket = renewed_profile.test_bootstrap_material();
    let renewed_client = renewed_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed audited client");
    let renewed_session_authority = renewed_client.test_session_authority();
    assert!(process.matches_client(&renewed_client));

    let mut materials = vec![
        launch_secret.to_vec(),
        initial_bootstrap.as_ref().to_vec(),
        renewal_bootstrap_ticket.as_ref().to_vec(),
        initial_session_authority.as_ref().to_vec(),
        renewed_session_authority.as_ref().to_vec(),
    ];
    materials.extend(
        activation_keys
            .into_iter()
            .filter(|key| key.as_ref() != [0; 32])
            .map(|key| key.as_ref().to_vec()),
    );
    assert!(
        materials.iter().all(|material| material != &[0; 32]),
        "every audited category must be non-zero"
    );
    assert_eq!(
        materials.iter().collect::<HashSet<_>>().len(),
        materials.len(),
        "raw secret, derived keys, renewal ticket and session authorities must be distinct"
    );
    let representations = material_representations(&materials);

    let desktop_database = temporary.path().join("desktop-audit.sqlite3");
    let project_directory = temporary.path().join("audit-project");
    std::fs::create_dir(&project_directory).expect("audit project directory");
    let core = AppCore::open_with_runtime_mode(&desktop_database, RuntimeMode::Bundled)
        .expect("audit AppCore");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin audited AppCore activation");
    core.install_bundled_runtime_client(lease, renewed_client)
        .await
        .expect("install audited protected client");
    let project = core
        .open_local_project(&project_directory)
        .expect("open audit project");
    core.open_project_conversation(project.id)
        .await
        .expect("open audited conversation");
    let timeline = core
        .send_project_message(project.id, "safe protected audit message")
        .await
        .expect("send audited message");
    let renderer_frames = [
        serde_json::to_vec(&core.bootstrap().expect("renderer bootstrap")).unwrap(),
        serde_json::to_vec(&timeline).unwrap(),
        serde_json::to_vec(
            &core
                .diagnostics("test-version", "test-platform")
                .expect("renderer diagnostics"),
        )
        .unwrap(),
    ]
    .concat();
    assert_absent("renderer frames", &renderer_frames, &representations);

    let safe_error_frames = format!(
        "{process:?};{};{}",
        ProtectedBundledRuntimeError::ActivationStateUnavailable,
        ProtectedBundledRuntimeError::LaunchAuthority(
            gocode_api::LaunchAuthorityError::ReadinessProofMismatch
        )
    );
    assert_absent(
        "renderer-safe errors",
        safe_error_frames.as_bytes(),
        &representations,
    );

    assert_tree_absent(temporary.path(), &representations);

    let mut broker = SecretBroker::new();
    for (index, material) in materials.iter().enumerate() {
        broker
            .register(&format!("protected-audit-{index}"), material.clone())
            .expect("register audited protected material");
    }
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(broker.prohibited_content_guard());
    for material in &materials {
        for boundary in [
            CanonicalContentBoundary::CanonicalMutation,
            CanonicalContentBoundary::OutboundDelivery,
        ] {
            assert!(matches!(
                guard.inspect(boundary, material),
                Ok(ContentDisposition::Prohibited { .. })
            ));
        }
    }

    let exporter = VerificationExporter::new(Arc::clone(&guard));
    let safe_export = exporter
        .export_run_json(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            "completed",
            Some("passed"),
            0,
        )
        .expect("safe export");
    assert_absent("export", &safe_export, &representations);
    for material in &materials {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material);
        assert!(
            exporter
                .export_run_json(
                    uuid::Uuid::now_v7(),
                    uuid::Uuid::now_v7(),
                    &encoded,
                    None,
                    0,
                )
                .is_err(),
            "protected material must be denied before export"
        );
    }

    let backup = InMemoryBackupStore::new(Arc::clone(&guard));
    let manifest = backup
        .create_backup(
            vec![StreamInventory {
                stream_name: "safe-stream".into(),
                event_count: 1,
                first_sequence: 1,
                last_sequence: 1,
            }],
            VerificationDigest::from_bytes([1; 32]),
        )
        .expect("safe synthetic backup");
    assert_absent(
        "backup",
        &backup
            .archive_bytes(&manifest.backup_id)
            .expect("backup bytes"),
        &representations,
    );
    let safe_archive_count = backup.archive_count();
    for material in &materials {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material);
        assert!(
            backup
                .create_backup(
                    vec![StreamInventory {
                        stream_name: encoded,
                        event_count: 1,
                        first_sequence: 1,
                        last_sequence: 1,
                    }],
                    VerificationDigest::from_bytes([1; 32]),
                )
                .is_err(),
            "protected material must be denied before backup"
        );
        assert_eq!(backup.archive_count(), safe_archive_count);
    }

    process
        .request_graceful_stop()
        .expect("authenticated audited shutdown");
    assert_eq!(
        process
            .wait_for_exit(Duration::from_secs(10))
            .expect("wait for audited child"),
        gocode_platform_desktop::BundledRuntimeProcessStatus::Exited
    );
    let (stdout, stderr) = process
        .take_captured_output_for_test()
        .expect("captured audited output");
    assert_absent("captured stdout", &stdout, &representations);
    assert_absent("captured stderr/logs", &stderr, &representations);
    drop(core);

    assert_tree_absent(&runtime_root, &representations);
    assert_tree_absent(temporary.path(), &representations);
    assert_tracked_fixtures_absent(&representations);
}
