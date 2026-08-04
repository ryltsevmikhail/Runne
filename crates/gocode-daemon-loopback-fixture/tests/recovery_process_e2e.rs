#![cfg(unix)]

mod support;

use gocode_daemon_loopback_fixture::prepare_runtime_root;
use gocode_runtime_client::ReplayDeliveryDisposition;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_process_replays_the_pending_terminal_outbox_without_a_second_effect() {
    let temporary = tempfile::tempdir().expect("temporary fixture root");
    let runtime_root = temporary.path().join("runtime");
    std::fs::create_dir(&runtime_root).expect("create private runtime root");
    #[cfg(unix)]
    std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture root owner-private");
    let placeholder_key =
        prepare_runtime_root(&runtime_root).expect("create fixture key placeholder");
    let executable = support::executable("recovery_process", temporary.path());

    let mut first = support::launch(&executable, &runtime_root);
    let first_client = support::protected_client(&mut first).await;
    let first_session = first_client.session_info().clone();
    let first_replay_binding = first_client.replay_persistence_binding();
    let conversation = support::send_canonical_conversation(&first_client).await;
    let execution = support::execution_stage(&runtime_root);
    support::assert_first_activation_stages(&execution, &conversation);
    drop(first_client);
    support::stop(first);
    assert_eq!(
        support::execution_stage(&runtime_root).terminal_outbox_pending,
        1
    );
    let first_active_key =
        prepare_runtime_root(&runtime_root).expect("reload first active fixture key");
    assert_ne!(placeholder_key.key_ref(), first_active_key.key_ref());
    assert_ne!(placeholder_key.bytes(), first_active_key.bytes());
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(first_active_key.path())
            .expect("read first active fixture key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let mut second = support::launch(&executable, &runtime_root);
    let second_client = support::protected_client(&mut second).await;
    let second_session = second_client.session_info().clone();
    assert_eq!(second_session.authority_id, first_session.authority_id);
    assert_eq!(second_session.principal_id, first_session.principal_id);
    assert_eq!(
        second_session.event_log_lineage_id, first_session.event_log_lineage_id,
        "stable replay lineage must survive the reaped process boundary"
    );
    assert_ne!(
        second_session.daemon_instance_id,
        first_session.daemon_instance_id
    );
    assert_ne!(second_session.session_id, first_session.session_id);
    assert_eq!(
        second_session.launch_generation,
        first_session.launch_generation + 1
    );
    assert_eq!(
        second_client.replay_persistence_binding().digest(),
        first_replay_binding.digest()
    );
    assert_eq!(second_session.profile_id, first_session.profile_id);
    assert_eq!(second_session.schema_hash, first_session.schema_hash);
    assert_eq!(second_session.capabilities, first_session.capabilities);
    assert_eq!(
        second_session.capability_digest,
        first_session.capability_digest
    );
    let restored = second_client
        .list_messages(conversation.conversation_id)
        .await
        .expect("process two reads the exact canonical timeline");
    assert_eq!(restored, conversation.timeline);
    let full_replay = support::replay_from(
        &second_client,
        conversation.conversation_id,
        None,
        gocode_runtime_client::ReplayIdentityTracker::new(),
    )
    .await;
    assert_eq!(full_replay, conversation.replay_events);
    assert!(
        full_replay
            .iter()
            .all(|event| event.disposition == ReplayDeliveryDisposition::New)
    );
    let inclusive_resume = support::replay_from(
        &second_client,
        conversation.conversation_id,
        Some(&conversation.last_cursor),
        conversation.replay_tracker.clone(),
    )
    .await;
    let last = conversation
        .replay_events
        .last()
        .expect("process one replay event");
    let [duplicate] = inclusive_resume.as_slice() else {
        panic!("inclusive resume returns only the preserved last event");
    };
    assert_eq!(duplicate.event, last.event);
    assert_eq!(duplicate.cursor, last.cursor);
    assert_eq!(duplicate.digest, last.digest);
    assert_eq!(duplicate.disposition, ReplayDeliveryDisposition::Duplicate);
    assert_eq!(support::accepted_requests(&runtime_root), 1);
    let recovered_execution = support::execution_stage(&runtime_root);
    assert_eq!(recovered_execution.terminal_outbox_total, 1);
    assert_eq!(recovered_execution.terminal_outbox_pending, 0);
    let second_active_key =
        prepare_runtime_root(&runtime_root).expect("reload second active fixture key");
    assert_eq!(first_active_key.key_ref(), second_active_key.key_ref());
    assert_eq!(first_active_key.bytes(), second_active_key.bytes());
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(second_active_key.path())
            .expect("read second active fixture key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(second_client);
    support::stop(second);
}
