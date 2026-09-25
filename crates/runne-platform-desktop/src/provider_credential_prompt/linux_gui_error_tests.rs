use std::process::Command;

use runne_platform_ports::provider_credential_prompt::SecureCredentialPromptError;

use super::kill_and_reap;

#[test]
fn cleanup_returns_unavailable_for_child_already_exited_nonzero() {
    let mut child = Command::new("sh")
        .args(["-c", "exit 1"])
        .spawn()
        .expect("spawn exited child");
    let status = child.wait().expect("wait for child");
    assert!(!status.success());

    assert!(matches!(
        kill_and_reap(&mut child),
        SecureCredentialPromptError::Unavailable
    ));
}
