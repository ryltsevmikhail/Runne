use super::*;

#[test]
fn t1_protected_provider_http_and_runtime_client_replay() {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "t1_positive::t1_protected_provider_http_and_runtime_client_replay_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("run isolated T1 child test");
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll isolated T1 child") {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            #[cfg(not(unix))]
            child.kill().expect("kill timed-out T1 child");
            let _ = child.wait();
            panic!("isolated T1 child exceeded 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect T1 child output");
    let scanner = super::t1_support::frozen_scanner();
    super::assert_absent("T1 child stdout", &output.stdout, &scanner);
    super::assert_absent("T1 child stderr", &output.stderr, &scanner);
    assert!(
        status.success(),
        "isolated T1 child failed after frozen scans: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
