use std::thread;

use super::*;

#[test]
fn fallback_waits_for_main_thread_cleanup_before_returning() {
    let (id, observer) = registered_prompt();
    let (terminal, receiver) = terminal();
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
