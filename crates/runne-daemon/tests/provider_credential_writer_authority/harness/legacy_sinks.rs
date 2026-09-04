//! Bounded sink collection for the legacy scenario child and the disposable
//! credential-service logs. Every sink is capped; overflow, unreadable or
//! non-regular sinks fail closed so a fragment is never accepted from a
//! partially observed run.

use std::io::Read;
use std::process::Child;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) const MAX_CHILD_OUTPUT_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_SERVICE_LOG_BYTES: u64 = 64 * 1024;
const CHILD_WAIT_TIMEOUT: Duration = Duration::from_secs(1800);

/// Drains one child pipe forever (so the child never blocks on a full pipe)
/// while collecting at most [`MAX_CHILD_OUTPUT_BYTES`] and flagging overflow.
pub(super) fn spawn_bounded_drain(
    reader: impl Read + Send + 'static,
    overflow: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut collected = Vec::new();
        let mut total = 0u64;
        let mut chunk = [0u8; 8192];
        let mut reader = reader;
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    total += read as u64;
                    if total <= MAX_CHILD_OUTPUT_BYTES {
                        collected.extend_from_slice(&chunk[..read]);
                    } else {
                        overflow.store(true, Ordering::SeqCst);
                    }
                }
                // A mid-stream read error means the collected bytes are not
                // the complete sink output; fail the collection closed.
                Err(_) => {
                    overflow.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        collected
    })
}

/// Waits for the exact child under a hard deadline; a timed-out child is
/// killed and reaped before the failure is reported.
pub(super) fn bounded_wait(child: &mut Child) -> Result<std::process::ExitStatus, ()> {
    let deadline = Instant::now() + CHILD_WAIT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return Err(()),
        }
    }
}

/// Reads one regular log sink under an exact byte bound. A missing sink is an
/// empty observation; anything oversized, unreadable or non-regular fails.
/// The opened file descriptor is re-verified by device/inode so a swap between
/// the pre-check and the open cannot substitute another file's bytes.
pub(super) fn read_bounded_sink(
    path: &std::path::Path,
    limit: u64,
) -> Result<Vec<u8>, &'static str> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Ok(metadata) if metadata.file_type().is_file() => {
            let mut bytes = Vec::new();
            let file =
                std::fs::File::open(path).map_err(|_| "legacy service sink is unreadable")?;
            let opened = file
                .metadata()
                .map_err(|_| "legacy service sink is unreadable")?;
            let same_file = opened.ino() == metadata.ino() && opened.dev() == metadata.dev();
            if !opened.is_file() || !same_file {
                return Err("legacy service sink is not a regular file");
            }
            file.take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "legacy service sink is unreadable")?;
            if bytes.len() as u64 > limit {
                return Err("legacy service sink exceeded the collection bound");
            }
            Ok(bytes)
        }
        Ok(_) => Err("legacy service sink is not a regular file"),
        Err(_) => Err("legacy service sink is unreadable"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{MAX_SERVICE_LOG_BYTES, read_bounded_sink, spawn_bounded_drain};

    #[test]
    fn missing_service_sink_is_an_empty_observation() {
        let temporary = tempfile::tempdir().expect("temporary sink root");
        let missing = temporary.path().join("credential-service.stdout");
        assert_eq!(
            read_bounded_sink(&missing, MAX_SERVICE_LOG_BYTES),
            Ok(Vec::new())
        );
    }

    #[test]
    fn oversized_service_sink_fails_closed_without_exposing_bytes() {
        let temporary = tempfile::tempdir().expect("temporary sink root");
        let path = temporary.path().join("credential-service.stderr");
        std::fs::write(&path, vec![0x41; (MAX_SERVICE_LOG_BYTES + 1) as usize]).expect("sink");
        assert_eq!(
            read_bounded_sink(&path, MAX_SERVICE_LOG_BYTES),
            Err("legacy service sink exceeded the collection bound")
        );
    }

    #[test]
    fn non_regular_service_sink_fails_closed() {
        let temporary = tempfile::tempdir().expect("temporary sink root");
        let target = temporary.path().join("target.txt");
        std::fs::write(&target, b"legitimate").expect("target");
        let link = temporary.path().join("credential-service.stdout");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(
            read_bounded_sink(&link, MAX_SERVICE_LOG_BYTES),
            Err("legacy service sink is not a regular file")
        );
    }

    #[test]
    fn service_stdout_canary_is_collected_for_the_leak_audit() {
        let temporary = tempfile::tempdir().expect("temporary sink root");
        let path = temporary.path().join("credential-service.stdout");
        std::fs::write(&path, b"canary-secret-material").expect("sink");
        let sink = read_bounded_sink(&path, MAX_SERVICE_LOG_BYTES).expect("bounded sink");
        assert!(crate::harness::contains(&sink, b"canary-secret-material"));
    }

    #[test]
    fn child_pipe_drain_flags_overflow_and_stops_collecting_at_the_bound() {
        let overflow = Arc::new(AtomicBool::new(false));
        let payload = vec![0x42u8; (super::MAX_CHILD_OUTPUT_BYTES + 1) as usize];
        let handle = spawn_bounded_drain(Cursor::new(payload), overflow.clone());
        let collected = handle.join().expect("drain thread");
        assert!(overflow.load(Ordering::SeqCst));
        assert_eq!(collected.len(), super::MAX_CHILD_OUTPUT_BYTES as usize);
    }

    #[test]
    fn child_pipe_drain_collects_undersized_output_without_overflow() {
        let overflow = Arc::new(AtomicBool::new(false));
        let handle = spawn_bounded_drain(Cursor::new(b"small output".to_vec()), overflow.clone());
        let collected = handle.join().expect("drain thread");
        assert!(!overflow.load(Ordering::SeqCst));
        assert_eq!(collected, b"small output".to_vec());
    }
}
