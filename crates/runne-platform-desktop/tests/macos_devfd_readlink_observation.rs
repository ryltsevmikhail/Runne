//! OPT-IN diagnostic (run with `cargo test ... -- --ignored`): ONE recorded
//! observation of the `/dev/fd` readlink behavior on ONE host running ONE
//! macOS build — not a generalization over all processes, hardware, or macOS
//! versions, and NOT part of the mandatory battery (no supported macOS
//! release is required to fail with errno 22).
//!
//! The production editor launch on macOS is refused BY DECISION —
//! `launch_system_default_editor` returns the existing typed `Unavailable`
//! deterministically after the shared validation (deliberate temporary
//! macOS-backend limitation; see
//! crates/runne-platform-desktop/src/root_handle_broker/unix_editor.rs and
//! the gateway reachability test). This diagnostic records, for the record,
//! the underlying OS observation: `readlink` on a `/dev/fd/N` descriptor for
//! a plain directory `File` opened by THIS test process.
//!
//! Recorded per run: the OS version and build
//! (`/usr/bin/sw_vers -productVersion` and `-buildVersion`) and the actual
//! readlink result — `Ok(path)` or `Err(raw_os_error)` — printed to stderr.
//! Any `Err` value is a valid recorded observation and does NOT fail the
//! test; the test fails ONLY if the readlink SUCCEEDS, i.e. the observation
//! itself has changed and every decision citing it must be revisited.
#![cfg(target_os = "macos")]

use std::os::fd::AsRawFd;
use std::process::Command;

#[test]
#[ignore = "opt-in diagnostic: single-host /dev/fd readlink observation; \
            the mandatory battery does not require errno 22 from any \
            supported macOS"]
fn devfd_readlink_observation_on_this_host() {
    fn sw_vers(flag: &str) -> String {
        let output = Command::new("/usr/bin/sw_vers")
            .arg(flag)
            .output()
            .unwrap_or_else(|error| panic!("run /usr/bin/sw_vers {flag}: {error}"));
        assert!(output.status.success(), "sw_vers {flag} failed: {output:?}");
        String::from_utf8(output.stdout)
            .expect("sw_vers output is UTF-8")
            .trim()
            .to_owned()
    }

    let directory = tempfile::tempdir().expect("fixture directory");
    let handle = std::fs::File::open(directory.path()).expect("open fixture directory as File");
    let fd = handle.as_raw_fd();

    let observed = std::fs::read_link(format!("/dev/fd/{fd}"));

    let os_version = sw_vers("-productVersion");
    let os_build = sw_vers("-buildVersion");

    match &observed {
        Ok(path) => panic!(
            "observation changed, revisit /dev/fd dependency: readlink(\"/dev/fd/{fd}\") \
             succeeded with {path:?} on macOS {os_version} (build {os_build})"
        ),
        Err(error) => eprintln!(
            "observation: readlink(\"/dev/fd/{fd}\") on macOS {os_version} \
             (build {os_build}) -> raw_os_error {:?} ({error}); \
             any errno is a valid recorded observation",
            error.raw_os_error()
        ),
    }
}
