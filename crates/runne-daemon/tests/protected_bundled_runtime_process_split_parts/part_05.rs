// Forward profile rebind: an aged stable binding (same profile_id, stale
// profile_hash/capability_digest) migrates to the current contract generation
// while authority/lineage identity and the Event Log are preserved.

fn stable_binding_path(runtime_root: &std::path::Path) -> std::path::PathBuf {
    runtime_root
        .join(".desktop-protected-activation")
        .join("stable-binding-v1.json")
}

fn aged_stable_record(original: &[u8]) -> Vec<u8> {
    let mut aged: serde_json::Value = serde_json::from_slice(original).expect("stable record JSON");
    aged["profile_hash"] = serde_json::Value::Array(vec![serde_json::json!(0x0b_u8); 32]);
    aged["capability_digest"] = serde_json::Value::Array(vec![serde_json::json!(0x0c_u8); 32]);
    serde_json::to_vec(&aged).expect("encode aged record")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_profile_binding_rebinds_forward_preserving_identity() {
    let _process_guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable = owner_private::ControlledExecutable::copy_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        &temporary.path().join("runtime"),
    )
    .expect("protected launch spec");
    let runtime_root = spec.runtime_root().to_path_buf();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    supervisor.start().expect("first protected launch");
    let initial_profile = supervisor
        .take_runtime_profile()
        .expect("initial one-time profile");
    let initial_client = initial_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected client");
    supervisor
        .record_client_ready(&initial_client)
        .expect("exact initial readiness");
    let initial = initial_client.session_info().clone();
    assert_eq!(
        supervisor.stop().expect("graceful owned stop"),
        BundledRuntimeStopDisposition::Graceful
    );

    let record_path = stable_binding_path(&runtime_root);
    let original_bytes = std::fs::read(&record_path).expect("original stable record");
    let aged_bytes = aged_stable_record(&original_bytes);
    std::fs::write(&record_path, &aged_bytes).expect("write aged stable record");

    supervisor
        .start()
        .expect("rebind restart after contract generation change");
    let rebound_profile = supervisor
        .take_runtime_profile()
        .expect("rebound one-time profile");
    let rebound_client = rebound_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("rebound protected client");
    supervisor
        .record_client_ready(&rebound_client)
        .expect("exact rebound readiness");
    let rebound = rebound_client.session_info().clone();
    assert_eq!(rebound.authority_id, initial.authority_id);
    assert_eq!(
        rebound.event_log_lineage_id, initial.event_log_lineage_id,
        "Event Log lineage must survive the profile rebind"
    );

    let migrated_bytes = std::fs::read(&record_path).expect("migrated stable record");
    assert_eq!(
        migrated_bytes, original_bytes,
        "rebind must restore the exact current-generation record"
    );

    assert_eq!(
        supervisor.stop().expect("graceful stop after rebind"),
        BundledRuntimeStopDisposition::Graceful
    );

    supervisor
        .start()
        .expect("second restart uses the exact-match path");
    let exact_profile = supervisor
        .take_runtime_profile()
        .expect("exact-match one-time profile");
    let exact_client = exact_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("exact-match protected client");
    supervisor
        .record_client_ready(&exact_client)
        .expect("exact-match readiness");
    let exact = exact_client.session_info().clone();
    assert_eq!(exact.authority_id, initial.authority_id);
    assert_eq!(exact.event_log_lineage_id, initial.event_log_lineage_id);
    assert_eq!(
        std::fs::read(&record_path).expect("record after exact restart"),
        original_bytes
    );
    assert_eq!(
        supervisor.stop().expect("final graceful stop"),
        BundledRuntimeStopDisposition::Graceful
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_authority_binding_is_rejected_without_rewrite() {
    let _process_guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable = owner_private::ControlledExecutable::copy_from(env!("CARGO_BIN_EXE_runned"));
    let spec = ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        &temporary.path().join("runtime"),
    )
    .expect("protected launch spec");
    let runtime_root = spec.runtime_root().to_path_buf();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    supervisor.start().expect("first protected launch");
    let initial_profile = supervisor
        .take_runtime_profile()
        .expect("initial one-time profile");
    let initial_client = initial_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected client");
    supervisor
        .record_client_ready(&initial_client)
        .expect("exact initial readiness");
    assert_eq!(
        supervisor.stop().expect("graceful owned stop"),
        BundledRuntimeStopDisposition::Graceful
    );

    let record_path = stable_binding_path(&runtime_root);
    let original_bytes = std::fs::read(&record_path).expect("original stable record");
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&original_bytes).expect("stable record JSON");
    let authority = tampered["authority_id"]
        .as_array_mut()
        .expect("authority array");
    let last = authority.len() - 1;
    let current = authority[last].as_u64().expect("authority byte");
    authority[last] = serde_json::json!((current + 1) % 256);
    let aged = aged_stable_record(&serde_json::to_vec(&tampered).expect("encode tampered"));
    std::fs::write(&record_path, &aged).expect("write tampered aged record");

    let outcome = supervisor.start();
    assert!(
        outcome.is_err(),
        "a foreign authority identity must never be adopted by the rebind"
    );
    assert_eq!(
        std::fs::read(&record_path).expect("record after rejected launch"),
        aged,
        "a rejected rebind must not rewrite the stored binding"
    );
}
