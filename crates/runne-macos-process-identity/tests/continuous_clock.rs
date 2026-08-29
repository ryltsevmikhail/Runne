#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::process::Command;

use runne_macos_process_identity::MacOsContinuousClock;

const CHILD_SENTINEL: &str = "RUNNE_MACOS_CONTINUOUS_CLOCK_CHILD";
const CHILD_PREFIX: &str = "continuous-clock-millis=";

#[test]
fn continuous_clock_uses_one_boot_domain_across_an_exec_child_process() {
    let before = MacOsContinuousClock::now_millis().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "continuous_clock_child_probe",
            "--nocapture",
        ])
        .env(CHILD_SENTINEL, "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "child probe failed: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let child_millis = stdout
        .lines()
        .find_map(|line| line.strip_prefix(CHILD_PREFIX))
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let after = MacOsContinuousClock::now_millis().unwrap();
    assert!(before <= child_millis && child_millis <= after);
}

#[test]
#[ignore = "runs only as the exec child probe"]
fn continuous_clock_child_probe() {
    assert_eq!(std::env::var(CHILD_SENTINEL).as_deref(), Ok("1"));
    println!(
        "{CHILD_PREFIX}{}",
        MacOsContinuousClock::now_millis().unwrap()
    );
}
