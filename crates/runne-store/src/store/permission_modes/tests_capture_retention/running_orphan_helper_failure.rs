//! Fatal failures retain the actual helper handle until process teardown.
use super::record_pump::Failure;
use std::io::Write;

pub(super) fn require<T>(value: Result<T, Failure>) -> T {
    match value {
        Ok(value) => value,
        Err(failure) => fatal(failure),
    }
}

fn diagnostic(failure: &Failure, mut writer: impl Write) {
    // A diagnostic is optional. Neither an IO error nor an unwinding writer
    // failure may escape and drop the real helper handle owned by fatal.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = writeln!(
            writer,
            "R05_RECORD_FATAL primary={} secondary={} stderr_bytes={} collected={:?} uncollected={}",
            failure.primary,
            failure.secondary.len(),
            failure.stderr.len(),
            failure.status,
            failure.uncollected.is_some()
        );
    }));
}

fn fatal(failure: Failure) -> ! {
    diagnostic(&failure, std::io::stderr().lock());
    // No error/Child drop, success return, extra wait or cleanup-success claim.
    // Aborting panic hooks/OOM are process termination, never an unwind return.
    std::hint::black_box(&failure);
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fails;
    impl Write for Fails {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct Panics;
    impl Write for Panics {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("injected diagnostic failure")
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn diagnostic_failure_cannot_unwind_past_the_borrowed_failure() {
        let failure = Failure::before_spawn("synthetic diagnostic-only regression");
        diagnostic(&failure, Fails);
        diagnostic(&failure, Panics);
        assert_eq!(failure.primary, "synthetic diagnostic-only regression");
        assert!(failure.uncollected.is_none()); // NOT an actual Child ownership witness.
    }
}
