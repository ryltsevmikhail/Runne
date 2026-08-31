#[cfg(target_os = "macos")]
#[test]
fn macos_start_identity_is_stable_for_a_live_child_and_rejects_after_reap() {
    use std::process::Command;

    use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

    let mut child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 10"])
        .spawn()
        .unwrap();
    let pid = child.id();
    let first = super::observed_start_identity(pid);
    let second = super::observed_start_identity(pid);
    child.kill().unwrap();
    child.wait().unwrap();
    let after_reap = super::observed_start_identity(pid);

    assert!(matches!(first, Ok(identity) if identity != [0; 32]));
    assert_eq!(first, second);
    assert_eq!(after_reap, Err(BrokerHandoffError::Rejected));
}
