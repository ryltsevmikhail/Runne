use std::{
    io::{self, Read},
    os::fd::BorrowedFd,
    time::Instant,
};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use runne_platform_ports::provider_credential_prompt::SecureCredentialPromptError;
use zeroize::Zeroizing;

const READ_CHUNK_BYTES: usize = 4096;

/// Owns the complete response buffer in a zeroizing allocation.
pub(super) struct PromptResponse(Zeroizing<Vec<u8>>);

impl PromptResponse {
    pub(super) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Reads up to `maximum` bytes without growing the secret buffer.
pub(super) fn read_bounded_response(
    mut reader: impl Read,
    maximum: usize,
    deadline: Instant,
    mut wait_readable: impl FnMut(Instant) -> Result<(), SecureCredentialPromptError>,
) -> (Result<(), SecureCredentialPromptError>, PromptResponse) {
    let mut response = Zeroizing::new(Vec::with_capacity(maximum));
    let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES]);
    loop {
        if let Err(error) = wait_readable(deadline) {
            return (Err(error), PromptResponse(response));
        }
        match reader.read(&mut *chunk) {
            Ok(0) => return (Ok(()), PromptResponse(response)),
            Ok(read) => {
                if read > maximum.saturating_sub(response.len()) {
                    return (
                        Err(SecureCredentialPromptError::Rejected),
                        PromptResponse(response),
                    );
                }
                response.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                return (
                    Err(SecureCredentialPromptError::Unavailable),
                    PromptResponse(response),
                );
            }
        }
    }
}

pub(super) fn wait_readable(
    descriptor: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), SecureCredentialPromptError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SecureCredentialPromptError::Unavailable);
        }
        let mut descriptors = [PollFd::new(descriptor, PollFlags::POLLIN)];
        let ready = match poll(
            &mut descriptors,
            PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX),
        ) {
            Ok(ready) => ready,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return Err(SecureCredentialPromptError::Unavailable),
        };
        let events = descriptors[0].revents().unwrap_or(PollFlags::POLLNVAL);
        if ready == 0 || events.contains(PollFlags::POLLNVAL) {
            return Err(SecureCredentialPromptError::Unavailable);
        }
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{self, Read},
        os::fd::AsFd as _,
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    use nix::unistd::pipe;
    use runne_platform_ports::provider_credential_prompt::SecureCredentialPromptError;

    use super::{PromptResponse, read_bounded_response, wait_readable};

    struct Chunks {
        parts: Vec<&'static [u8]>,
        next_part: usize,
        fail_after: bool,
    }

    impl Read for Chunks {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if let Some(chunk) = self.parts.get(self.next_part) {
                self.next_part += 1;
                let count = chunk.len().min(output.len());
                output[..count].copy_from_slice(&chunk[..count]);
                return Ok(count);
            }
            if self.fail_after {
                return Err(io::ErrorKind::Other.into());
            }
            Ok(0)
        }
    }

    fn chunks(parts: Vec<&'static [u8]>) -> Chunks {
        Chunks {
            parts,
            next_part: 0,
            fail_after: false,
        }
    }

    #[test]
    fn multiple_chunks_at_exact_bound_are_kept_in_zeroizing_owner() {
        let mut reader = chunks(vec![b"secret-", b"material"]);
        let (result, response) = read_bounded_response(
            &mut reader,
            15,
            Instant::now() + Duration::from_secs(1),
            |_| Ok(()),
        );
        assert!(result.is_ok());
        assert_eq!(response.as_slice(), b"secret-material");

        let (sender, receiver) = std::sync::mpsc::channel();
        sender.send(response).expect("transfer zeroizing owner");
        let response: PromptResponse = receiver.recv().expect("receive zeroizing owner");
        assert_eq!(response.as_slice(), b"secret-material");
    }

    #[test]
    fn crossing_bound_is_rejected_before_append() {
        let mut reader = chunks(vec![b"1234", b"56"]);
        let (result, response) = read_bounded_response(
            &mut reader,
            5,
            Instant::now() + Duration::from_secs(1),
            |_| Ok(()),
        );
        assert!(matches!(result, Err(SecureCredentialPromptError::Rejected)));
        assert_eq!(response.as_slice(), b"1234");
    }

    #[test]
    fn read_error_preserves_closed_error_and_secret_owner() {
        let mut reader = Chunks {
            parts: vec![b"secret"],
            next_part: 0,
            fail_after: true,
        };
        let (result, response) = read_bounded_response(
            &mut reader,
            16,
            Instant::now() + Duration::from_secs(1),
            |_| Ok(()),
        );
        assert!(matches!(
            result,
            Err(SecureCredentialPromptError::Unavailable)
        ));
        assert_eq!(response.as_slice(), b"secret");
    }

    #[test]
    fn reader_deadline_joins_while_pipe_stays_open_after_child_exit() {
        let mut child = Command::new("true").spawn().expect("spawn child");
        assert!(child.wait().expect("wait for child").success());

        let (read_end, write_end) = pipe().expect("pipe");
        let reader = File::from(read_end);
        let poll_fd = reader.as_fd().try_clone_to_owned().expect("clone poll fd");
        let deadline = Instant::now() + Duration::from_millis(100);
        let started = Instant::now();
        let task = thread::spawn(move || {
            read_bounded_response(reader, 64, deadline, |deadline| {
                wait_readable(poll_fd.as_fd(), deadline)
            })
        });
        let (result, response) = task.join().expect("reader terminates by deadline");
        drop(write_end);

        assert!(matches!(
            result,
            Err(SecureCredentialPromptError::Unavailable)
        ));
        assert!(response.as_slice().is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
