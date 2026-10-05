use crate::local_command_linux::io::{
    LinuxCommandOutputChunkV1, LinuxCommandOutputLimitsV1, OUTPUT_DRAIN_QUANTUM, OUTPUT_READ_CHUNK,
};
use crate::local_command_linux::spec::LinuxCommandError;
use std::fs::File;
use std::io;

pub(in crate::local_command_linux) struct OutputCapture {
    stdout: StreamCapture,
    stderr: StreamCapture,
}

struct StreamCapture {
    reader: File,
    limit: usize,
    retained: Vec<u8>,
    captured_total: usize,
    observed_total: u64,
    observed_overflowed: bool,
    truncated: bool,
    eof: bool,
}

impl OutputCapture {
    pub(super) fn new(stdout: File, stderr: File, limits: LinuxCommandOutputLimitsV1) -> Self {
        Self {
            stdout: StreamCapture::new(stdout, limits.stdout_bytes()),
            stderr: StreamCapture::new(stderr, limits.stderr_bytes()),
        }
    }

    /// Drains at most one fixed quantum so a chatty command cannot starve control.
    pub(in crate::local_command_linux) fn poll(&mut self) -> Result<(), LinuxCommandError> {
        let mut remaining = OUTPUT_DRAIN_QUANTUM;
        let mut buffer = [0; OUTPUT_READ_CHUNK];
        for _ in 0..2 {
            for stream in [&mut self.stdout, &mut self.stderr] {
                if remaining == 0 || stream.eof {
                    continue;
                }
                let requested = buffer.len().min(remaining);
                match unsafe {
                    libc::read(
                        std::os::fd::AsRawFd::as_raw_fd(&stream.reader),
                        buffer.as_mut_ptr().cast(),
                        requested,
                    )
                } {
                    count if count > 0 => {
                        let count = count as usize;
                        stream.retain(&buffer[..count]);
                        remaining -= count;
                    }
                    0 => stream.eof = true,
                    _ => match io::Error::last_os_error().kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {}
                        _ => return Err(LinuxCommandError::Unavailable),
                    },
                }
            }
        }
        Ok(())
    }

    pub(in crate::local_command_linux) fn take(
        &mut self,
        leader_exit_code: Option<i32>,
    ) -> LinuxCommandOutputChunkV1 {
        LinuxCommandOutputChunkV1 {
            stdout: std::mem::take(&mut self.stdout.retained),
            stderr: std::mem::take(&mut self.stderr.retained),
            stdout_truncated: self.stdout.truncated,
            stderr_truncated: self.stderr.truncated,
            stdout_observed_bytes: self.stdout.observed_total,
            stderr_observed_bytes: self.stderr.observed_total,
            observed_bytes_overflowed: self.stdout.observed_overflowed
                || self.stderr.observed_overflowed,
            stdout_eof: self.stdout.eof,
            stderr_eof: self.stderr.eof,
            leader_exit_code,
        }
    }
}

impl StreamCapture {
    fn new(reader: File, limit: usize) -> Self {
        Self {
            reader,
            limit,
            retained: Vec::with_capacity(limit.min(OUTPUT_READ_CHUNK)),
            captured_total: 0,
            observed_total: 0,
            observed_overflowed: false,
            truncated: false,
            eof: false,
        }
    }

    fn retain(&mut self, bytes: &[u8]) {
        match self.observed_total.checked_add(bytes.len() as u64) {
            Some(total) => self.observed_total = total,
            None => {
                self.observed_total = u64::MAX;
                self.observed_overflowed = true;
            }
        }
        let remaining = self.limit.saturating_sub(self.captured_total);
        let retained = remaining.min(bytes.len());
        self.retained.extend_from_slice(&bytes[..retained]);
        self.captured_total += retained;
        self.truncated |= retained < bytes.len();
    }
}
