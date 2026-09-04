#[test]
fn cleanup_recovery_process_kill_does_not_reissue_committed_witness() {
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};
    const CHILD_PATH: &str = "RUNNE_RECOVERY_COMMIT_KILL_DB";
    const READY: &str = "RECOVERY_COMMIT_READY";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let store = super::online_claim_test_support::reopen_test_store(
            std::path::Path::new(&path), 100,
        );
        let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
        assert_eq!(accepted.attempt(), 1);
        println!("{READY}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must kill child while its committed witness is still alive");
    }

    let store = recovery_ledger_store();
    let _old_claim = old_cleanup_claim(&store);
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    drop(store);
    let name = format!("{}::cleanup_recovery_process_kill_does_not_reissue_committed_witness", module_path!());
    // libtest names omit the crate-name prefix present in module_path!().
    let name = name.split_once("::").unwrap().1;
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD_PATH, &path)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().unwrap();
    let mut child = RecoveryKillChild(child);
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
    ready.expect("child must confirm committed admission before SIGKILL");
    assert_eq!(status.signal(), Some(9));

    let mut reopened = super::online_claim_test_support::reopen_test_store(&path, 101);
    assert_eq!(
        reopened.accept_cleanup_recovery(recovery_request(&reopened, 98)).err(),
        Some(runne_provider::CredentialLifecycleError::Conflict),
    );
    let connection = reopened.connection.lock().unwrap();
    let states: (i64, String, Vec<u8>) = connection.query_row(
        "SELECT COUNT(*), state, continuation_digest FROM credential_cleanup_recovery_attempts",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(states, (1, "ACCEPTED".to_owned(), vec![99; 32]));
    let old_states: (String, String) = connection.query_row(
        "SELECT t.state, a.state FROM provider_credential_ticket_attempts t
         JOIN provider_credential_process_attachments a USING(operation_id)
         WHERE t.ticket_digest=?1 AND a.continuation_binding_digest=?2",
        rusqlite::params![[18_u8; 32], [19_u8; 32]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(old_states, ("TOMBSTONED".to_owned(), "TOMBSTONED".to_owned()));
    drop(connection);
    reopened.now = std::sync::Arc::new(|| 129);
    assert!(reopened.supersede_cleanup_recovery(recovery_request(&reopened, 98), 1).is_err());
    reopened.now = std::sync::Arc::new(|| 130);
    let next = reopened.supersede_cleanup_recovery(recovery_request(&reopened, 98), 1).unwrap();
    assert_eq!((next.attempt(), next.issued_at(), next.expires_at()), (2, 130, 160));
    reopened.attach_cleanup_recovery(next).unwrap();
    assert!(reopened.accept_cleanup_recovery(recovery_request(&reopened, 97)).is_err());
    let connection = reopened.connection.lock().unwrap();
    let old: (String, Vec<u8>) = connection.query_row(
        "SELECT state, terminal_digest FROM credential_cleanup_recovery_attempts WHERE attempt=1",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(old, ("SUPERSEDED".to_owned(), vec![99; 32]));
}

struct RecoveryKillChild(std::process::Child);

impl Drop for RecoveryKillChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
