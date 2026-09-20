//! D1.3 append identity readback contract tests.
//!
//! Invariant (plan sections 5/6, B8): after a conversation text append
//! commits, the exact durable identity is readable back by original command
//! identity, re-issue never duplicates the append, and an unacknowledged
//! commit stays blocked instead of being blindly retried.

use runne_application::conversation_text_service::ConversationTextServiceError;
use runne_application::ports::TextGenerationPhase;
use runne_store::store::StoreTransaction;

#[path = "support/d13_append_fixture.rs"]
mod d13_append_fixture;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

use d13_append_fixture::*;

#[test]
fn ack_loss_crash_sim_readback_returns_exact_identity_without_duplicate_append() {
    let (_directory, database_path) = database_directory("d13-readback-crash-sim");
    let (store, identity) = initialized(&database_path);
    seed_conversation(&store);
    let started = text_service(&store)
        .begin(&generate_context(), original_input("hello"))
        .unwrap();
    let completed = finish_completed(&store, &started).unwrap();
    assert_eq!(completed.phase, TextGenerationPhase::Completed);
    drop(store);

    let reopened = reopened_store(&database_path, identity);
    let readback = readback(&reopened);
    assert_eq!(readback, completed);
    assert_eq!(finish_completed(&reopened, &started).unwrap(), completed);
    assert_eq!(append_counts(&reopened), (3, 1, 1));
}

#[test]
fn fingerprint_conflict_rejects_reissue_and_keeps_stream_unchanged() {
    let (_directory, database_path) = database_directory("d13-readback-fingerprint");
    let store = StoreTransaction::open(&database_path, authority(), available_guard()).unwrap();
    seed_conversation(&store);
    let started = text_service(&store)
        .begin(&generate_context(), original_input("hello"))
        .unwrap();
    finish_completed(&store, &started).unwrap();
    assert_eq!(append_counts(&store), (3, 1, 1));

    // The service maps the repository-level `CommitError::IdempotencyConflict`
    // onto its typed `Conflict` variant; the stream must stay unchanged.
    let conflict = text_service(&store)
        .finish(
            &generate_context(),
            finish_input("different text", &started),
        )
        .unwrap_err();
    assert_eq!(conflict, ConversationTextServiceError::Conflict);
    assert_eq!(append_counts(&store), (3, 1, 1));
    assert_eq!(readback(&store).phase, TextGenerationPhase::Completed);
}

#[test]
#[cfg(unix)]
fn real_sigkill_between_commit_and_ack_preserves_exactly_once_append() {
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};
    const CHILD_PATH: &str = "RUNNE_D13_TEXT_APPEND_KILL_DB";
    const READY: &str = "D13_APPEND_READY";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let store =
            StoreTransaction::open(path.to_str().unwrap(), authority(), available_guard()).unwrap();
        seed_conversation(&store);
        let started = text_service(&store)
            .begin(&generate_context(), original_input("hello"))
            .unwrap();
        assert_eq!(
            finish_completed(&store, &started).unwrap().phase,
            TextGenerationPhase::Completed
        );
        println!("{READY}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must kill child while its committed append is still alive");
    }

    let (_directory, database_path) = database_directory("d13-readback-sigkill");
    let (initializer, identity) = initialized(&database_path);
    drop(initializer);
    // The last-closed reader leaves the checkpointed WAL in place; checkpoint
    // it and remove the sidecars (a legal recovery state) so the child can use
    // the ordinary safe-file admission.
    let cleanup = rusqlite::Connection::open(&database_path).unwrap();
    cleanup
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    drop(cleanup);
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{database_path}{suffix}"));
        let _ = std::fs::remove_file(sidecar);
    }
    let name = format!("{}::{KILL_TEST_NAME}", module_path!());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name.split_once("::").unwrap().1, "--nocapture"])
        .env(CHILD_PATH, &database_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = KillChild(child);
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines().take(100) {
            if line.is_ok_and(|line| line.contains(READY)) {
                let _ = send.send(());
                return;
            }
        }
    });
    let ready = receive.recv_timeout(std::time::Duration::from_secs(20));
    child.0.kill().expect("kill the exact child process");
    let status = child.0.wait().unwrap();
    reader.join().unwrap();
    ready.expect("child must confirm the committed append before SIGKILL");
    assert_eq!(status.signal(), Some(9));

    let reopened = reopened_store(&database_path, identity);
    let readback = readback(&reopened);
    assert_eq!(readback.phase, TextGenerationPhase::Completed);
    let (_, assistants, users) = conversation_evidence(&reopened);
    assert_eq!(assistants, vec![readback.assistant_message_id]);
    assert_eq!(users, vec![readback.user_message_id]);
}

#[test]
fn uncertain_ack_reopen_alone_creates_no_new_receipt_rows() {
    let (_directory, database_path) = database_directory("d13-readback-no-blind-retry");
    let (store, identity) = initialized(&database_path);
    seed_conversation(&store);
    let started = text_service(&store)
        .begin(&generate_context(), original_input("hello"))
        .unwrap();
    finish_completed(&store, &started).unwrap();
    assert_eq!(append_counts(&store), (3, 1, 1));
    let receipts_before = receipt_count(&database_path);
    drop(store);

    let reopened = reopened_store(&database_path, identity);
    assert_eq!(append_counts(&reopened), (3, 1, 1));
    assert_eq!(readback(&reopened).phase, TextGenerationPhase::Completed);
    assert_eq!(receipt_count(&database_path), receipts_before);
}

#[cfg(unix)]
struct KillChild(std::process::Child);

#[cfg(unix)]
impl Drop for KillChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
