//! Single-threaded writer startup descriptor sweep. Only stdio and the
//! caller-validated read-only secret pipe may survive. The pipe is not read
//! until authenticated claim; every other descriptor is closed before broker
//! processing. The no-secret fixture uses the same sweep with no exception.

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepError {
    Denied,
}

// `pub` (not `pub(super)`) is required by the fixture bin, which includes this
// private module at its crate root; in the library tree the enclosing modules
// are private, so `pub` does not widen the shipped API.
#[cfg(test)]
pub fn close_inherited_descriptors(
    enumerate: impl FnOnce() -> io::Result<Vec<i32>>,
) -> Result<(), SweepError> {
    close_inherited_descriptors_except(enumerate, None)
}

pub fn close_inherited_descriptors_except(
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
            Ok(()) | Err(nix::errno::Errno::EBADF) => {}
            Err(_) => return Err(SweepError::Denied),
        }
    }
    Ok(())
}

pub fn enumerate_proc_fds() -> io::Result<Vec<i32>> {
    let inventory = std::fs::read_dir("/proc/self/fd")?;
    let mut descriptors = Vec::new();
    for entry in inventory.flatten() {
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
            descriptors.push(fd);
        }
    }
    Ok(descriptors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_closes_real_inherited_descriptor_and_tolerates_only_ebadf() -> std::io::Result<()> {
        use std::os::fd::IntoRawFd as _;
        let path = std::env::temp_dir().join(format!("runne-writer-sweep-{}", std::process::id()));
        let file = std::fs::File::create(&path)?;
        // Ownership is released before the raw sweep close, so exactly one
        // close happens and no runtime IO-safety invariant is involved.
        let fd = file.into_raw_fd();
        if fd <= libc::STDERR_FILENO {
            return Err(std::io::Error::other(
                "fixture descriptor must exceed the stdio range",
            ));
        }
        // The snapshot lists the real descriptor plus an already-closed one
        // (EBADF tolerance) while the enumerator itself is a pure fixture.
        let snapshot = vec![fd, 999_999];
        close_inherited_descriptors(|| Ok(snapshot)).map_err(|_| {
            std::io::Error::other("sweep must tolerate exactly one already-closed entry")
        })?;
        if std::fs::read_link(format!("/proc/self/fd/{fd}")).is_ok_and(|target| target == path) {
            return Err(std::io::Error::other(
                "descriptor must be closed by the sweep",
            ));
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn sweep_keeps_stdio() -> Result<(), &'static str> {
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
        .map_err(|_| "stdio-only snapshot must be a no-op")?;
        if !probe.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("sweep must consult the injected snapshot");
        }
        Ok(())
    }
}
