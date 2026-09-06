use std::thread;

use super::*;

#[test]
fn fallback_waits_for_main_thread_cleanup_before_returning() {
    let (terminal, receiver) = terminal();
    let id = state::allocate_id().expect("prompt id");
    let observer = CleanupObserver::new();
    assert!(routes::register_or_finish(
        id,
        PromptUiState::observed(observer.clone(), true),
        &terminal,
    ));
    let (task_sender, task_receiver) = mpsc::sync_channel(1);
    let (result_sender, result_receiver) = mpsc::sync_channel(1);

    let worker = thread::spawn(move || {
        let result =
            routes::wait_for_result(&receiver, Duration::from_millis(1), id, &terminal, |task| {
                task_sender.send(task).expect("cleanup task receiver");
            });
        result_sender.send(result).expect("result receiver");
    });

    let cleanup = task_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("fallback cleanup task");
    assert!(matches!(
        result_receiver.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(observer.events(), []);

    cleanup();

    assert!(matches!(
        result_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("terminal result"),
        Err(SecureCredentialPromptError::Unavailable)
    ));
    worker.join().expect("worker");
    assert_cleaned(id, &observer);
}

#[test]
fn pending_setup_times_out_without_waiting_and_late_registration_cleans() {
    let id = state::allocate_id().expect("prompt id");
    let observer = CleanupObserver::new();
    let (terminal, receiver) = terminal();

    let result =
        routes::wait_for_result(&receiver, Duration::from_millis(1), id, &terminal, |_| {
            panic!("pending prompt has no registered AppKit state to clean")
        });
    assert!(matches!(
        result,
        Err(SecureCredentialPromptError::Unavailable)
    ));

    let prompt = PromptUiState::observed(observer.clone(), true);
    assert!(!routes::register_or_finish(id, prompt, &terminal));
    assert_cleaned(id, &observer);
}
