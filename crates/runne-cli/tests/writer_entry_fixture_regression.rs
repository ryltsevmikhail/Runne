//! First-party sweep regression through the TEST-ONLY fixture binary (the
//! production binary contains no reporting code). The fixture enters the
//! REAL shared early-entry sweep routine (same source file compiled into the
//! production CLI) before any other work, so a deliberately inherited
//! descriptor — for which no parent snapshot exists anywhere — must be gone,
//! and the child environment is exactly what the parent injected.

use std::os::fd::IntoRawFd as _;
use std::process::{Command, Stdio};

#[test]
fn fixture_entry_sweeps_inherited_descriptor_and_reports_exact_env() {
    let fixture =
        std::env::temp_dir().join(format!("runne-writer-fixture-probe-{}", std::process::id()));
    std::fs::write(&fixture, b"inheritance probe").expect("fixture file");
    let file = std::fs::File::open(&fixture).expect("open probe");
    let inherited_fd = file.into_raw_fd();
    assert!(inherited_fd > 2);

    let mut child = Command::new(env!("CARGO_BIN_EXE_writer-entry-fixture"))
        .env_clear()
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/0/bus")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fixture child");
    let output = child.wait_with_output().expect("child completes");
    let report = String::from_utf8_lossy(&output.stdout);

    let env_block = report
        .split("ENV-START\n")
        .nth(1)
        .and_then(|rest| rest.split("ENV-END\n").next())
        .expect("env report");
    let mut names: Vec<&str> = env_block
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.split('=').next().unwrap_or("").trim_matches('"'))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["DBUS_SESSION_BUS_ADDRESS"],
        "the fixture environment is exactly the injected variable"
    );

    let fd_block = report
        .split("FD-START\n")
        .nth(1)
        .and_then(|rest| rest.split("FD-END\n").next())
        .expect("fd report");
    let survivors: Vec<(i32, String)> = fd_block
        .lines()
        .filter_map(|line| {
            let (fd, target) = line.split_once('\t')?;
            Some((fd.trim().parse::<i32>().ok()?, target.to_owned()))
        })
        .filter(|(fd, _)| *fd > 2)
        .collect();
    let probe_target = std::fs::canonicalize(&fixture)
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_default();
    assert!(
        survivors.iter().all(|(_, target)| *target != probe_target),
        "the inherited probe descriptor must be closed by the shared sweep; survivors: {survivors:?}"
    );
    assert!(
        survivors.len() <= 1
            && survivors
                .iter()
                .all(|(_, target)| target.ends_with("/fd") && target.contains("/proc/")),
        "only the report enumerator may appear above stdio: {survivors:?}"
    );
    assert!(matches!(
        nix::unistd::close(inherited_fd),
        Ok(()) | Err(nix::errno::Errno::EBADF)
    ));
}
