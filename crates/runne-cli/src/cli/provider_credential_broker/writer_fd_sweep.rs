//! Single-threaded writer startup descriptor sweep. Only stdio and the
//! caller-validated read-only secret pipe may survive. The pipe is not read
//! until authenticated claim; every other descriptor is closed before broker
//! processing. The no-secret fixture uses the same sweep with no exception.

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepError {
    Denied,
}

#[cfg(any(test, feature = "writer-entry-fixture"))]
pub(super) fn close_inherited_descriptors(
    enumerate: impl FnOnce() -> io::Result<Vec<i32>>,
) -> Result<(), SweepError> {
    close_inherited_descriptors_except(enumerate, None)
}

pub(super) fn close_inherited_descriptors_except(
    enumerate: impl FnOnce() -> io::Result<Vec<i32>>,
    retained_secret: Option<i32>,
) -> Result<(), SweepError> {
    let snapshot = enumerate().map_err(|_| SweepError::Denied)?;
    // The enumerator's own descriptor is closed by dropping its result
    // before any explicit close, keeping the snapshot list final.
    for fd in snapshot {
        if fd <= libc::STDERR_FILENO || retained_secret == Some(fd) {
            continue;
        }
        match nix::unistd::close(fd) {
            Ok(()) => {}
            Err(nix::errno::Errno::EBADF) => {}
            Err(_) => return Err(SweepError::Denied),
        }
    }
    Ok(())
}

pub(super) fn enumerate_proc_fds() -> io::Result<Vec<i32>> {
    let inventory = std::fs::read_dir("/proc/self/fd")?;
    let mut descriptors = Vec::new();
    for entry in inventory.flatten() {
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
            descriptors.push(fd);
        }
    }
    Ok(descriptors)
}

#[cfg(feature = "writer-entry-fixture")]
pub(super) fn close_inherited_descriptors_production() -> Result<(), SweepError> {
    close_inherited_descriptors(enumerate_proc_fds)
}

/// Reports the post-sweep surviving descriptors and inherited environment
/// names for the TEST-ONLY fixture binary (never linked into production).
#[cfg(feature = "writer-entry-fixture")]
pub fn report_sweep_facts() {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "ENV-START");
    for (name, value) in std::env::vars_os() {
        let _ = writeln!(out, "{name:?}={value:?}");
    }
    let _ = writeln!(out, "ENV-END");
    let _ = writeln!(out, "FD-START");
    if let Ok(inventory) = std::fs::read_dir("/proc/self/fd") {
        for entry in inventory.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let target = std::fs::read_link(format!("/proc/self/fd/{name}"))
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default();
            let _ = writeln!(out, "{name}\t{target}");
        }
    }
    let _ = writeln!(out, "FD-END");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_closes_real_inherited_descriptor_and_tolerates_only_ebadf() {
        use std::os::fd::IntoRawFd as _;
        let file = std::fs::File::create(
            std::env::temp_dir().join(format!("runne-writer-sweep-{}", std::process::id())),
        )
        .expect("fixture file");
        // Ownership is released before the raw sweep close, so exactly one
        // close happens and no runtime IO-safety invariant is involved.
        let fd = file.into_raw_fd();
        assert!(fd > 2);
        // The snapshot lists the real descriptor plus an already-closed one
        // (EBADF tolerance) while the enumerator itself is a pure fixture.
        let snapshot = vec![fd, 999_999];
        close_inherited_descriptors(|| Ok(snapshot)).expect("sweep succeeds");
        assert!(
            std::fs::read_link(format!("/proc/self/fd/{fd}")).is_err(),
            "descriptor must be closed by the sweep"
        );
    }

    #[test]
    fn sweep_keeps_stdio() {
        // A snapshot containing stdio must not attempt to close 0/1/2.
        // Closing std 1 in-process would break the test harness; using an
        // injected snapshot with only stdio proves the filter without any
        // real close.
        let probe = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = probe.clone();
        close_inherited_descriptors(|| {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0, 1, 2])
        })
        .expect("stdio-only snapshot is a no-op");
        assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
    }
}
