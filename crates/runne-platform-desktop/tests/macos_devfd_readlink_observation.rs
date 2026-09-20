//! ONE recorded observation of the `/dev/fd` readlink behavior on ONE host
//! running ONE macOS version — not a generalization over all processes,
//! hardware, or macOS versions.
//!
//! The production editor launch on macOS fails closed because it would need
//! to re-resolve an open directory descriptor through `/dev/fd/N`
//! (see crates/runne-platform-desktop/src/root_handle_broker/unix_editor.rs,
//! the deliberate temporary macOS-backend limitation). This test records the
//! underlying OS observation this limitation rests on: `readlink` on a
//! `/dev/fd/N` descriptor for a plain directory `File` opened by THIS test
//! process. The observed errno and the OS version (from
//! `/usr/bin/sw_vers -productVersion`) are printed to stderr; the assertion
//! pins EINVAL (22) FOR THE PRINTED VERSION ON THIS HOST only. If a future
//! OS makes the readlink succeed — or fail differently — this test must be
//! revisited together with every decision that cites it.
#![cfg(target_os = "macos")]

use std::os::fd::AsRawFd;
use std::process::Command;

#[test]
fn devfd_readlink_observation_is_einval_on_this_host() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let handle = std::fs::File::open(directory.path()).expect("open fixture directory as File");
    let fd = handle.as_raw_fd();

    let observed = std::fs::read_link(format!("/dev/fd/{fd}"));

    let version = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .expect("run /usr/bin/sw_vers -productVersion");
    assert!(
        version.status.success(),
        "sw_vers -productVersion failed: {version:?}"
    );
    let os_version = String::from_utf8(version.stdout)
        .expect("sw_vers output is UTF-8")
        .trim()
        .to_owned();

    match &observed {
        Ok(path) => panic!(
            "observation changed, revisit /dev/fd dependency: readlink(\"/dev/fd/{fd}\") \
             succeeded with {path:?} on macOS {os_version}"
        ),
        Err(error) => {
            eprintln!(
                "observation: readlink(\"/dev/fd/{fd}\") on macOS {os_version} -> \
                 raw_os_error {:?} ({error})",
                error.raw_os_error()
            );
            assert_eq!(
                error.raw_os_error(),
                Some(22), // EINVAL
                "on macOS {os_version} readlink(\"/dev/fd/N\") must fail with \
                 EINVAL (22) on this host"
            );
        }
    }
}
