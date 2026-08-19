#![cfg(unix)]

mod support;

use runne_daemon_loopback_fixture::prepare_runtime_root;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_process_uses_the_protected_v2_channel_and_canonical_conversation() {
    let temporary = tempfile::tempdir().expect("temporary fixture root");
    let runtime_root = temporary.path().join("runtime");
    std::fs::create_dir(&runtime_root).expect("create private runtime root");
    #[cfg(unix)]
    std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture root owner-private");
    let key_before = prepare_runtime_root(&runtime_root).expect("create retained fixture key");
    let executable = support::executable("activation_process", temporary.path());
    let mut process = support::launch(&executable, &runtime_root);
    let client = support::protected_client(&mut process).await;
    let conversation = support::send_canonical_conversation(&client).await;
    let execution = support::execution_stage(&runtime_root);
    support::assert_first_activation_stages(&execution, &conversation);
    drop(client);
    support::stop(process);
    assert_eq!(
        support::execution_stage(&runtime_root).terminal_outbox_pending,
        1
    );
    let key_after = prepare_runtime_root(&runtime_root).expect("reload retained fixture key");
    assert_ne!(key_before.key_ref(), key_after.key_ref());
    assert_ne!(key_before.bytes(), key_after.bytes());
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(key_after.path())
            .expect("read active fixture key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
