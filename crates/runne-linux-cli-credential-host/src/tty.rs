//! Bounded, non-echoing credential input from an explicitly owned terminal.
use std::fs::File;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Debug, Eq, PartialEq)]
pub enum InputError {
    Unavailable,
    Cancelled,
    Invalid,
}

pub fn read_secret(terminal: &mut File) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let signals = SignalGuard::new()?;
    let _guard = TerminalGuard::new(terminal)?;
    terminal
        .write_all(b"API key: ")
        .map_err(|_| InputError::Unavailable)?;
    terminal.flush().map_err(|_| InputError::Unavailable)?;
    let result = read_line(terminal, &signals);
    let _ = terminal.write_all(b"\r\n");
    result
}

fn read_line(terminal: &mut File, signals: &SignalGuard) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut secret = Zeroizing::new(Vec::with_capacity(4096));
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut descriptors = [
            libc::pollfd {
                fd: terminal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                2,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready <= 0 {
            return Err(InputError::Cancelled);
        }
        if descriptors[1].revents != 0 {
            // Consume the signal so restoring the mask does not terminate
            // the process before the terminal guard restores echo.
            let mut info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
            unsafe {
                libc::read(
                    signals.fd.as_raw_fd(),
                    info.as_mut_ptr().cast(),
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                );
            }
            return Err(InputError::Cancelled);
        }
        if descriptors[0].revents & libc::POLLIN == 0 {
            return Err(InputError::Unavailable);
        }
        let mut byte = Zeroizing::new([0u8]);
        terminal
            .read_exact(&mut *byte)
            .map_err(|_| InputError::Unavailable)?;
        match byte[0] {
            b'\n' | b'\r' => {
                return if secret.is_empty() {
                    Err(InputError::Invalid)
                } else {
                    Ok(secret)
                };
            }
            3 | 4 => return Err(InputError::Cancelled),
            8 | 127 => {
                if let Some(last) = secret.last_mut() {
                    *last = 0;
                }
                secret.pop();
            }
            33..=126 if secret.len() < 4096 => secret.push(byte[0]),
            _ => return Err(InputError::Invalid),
        }
    }
}

struct TerminalGuard {
    fd: OwnedFd,
    previous: libc::termios,
}
impl TerminalGuard {
    fn new(terminal: &File) -> Result<Self, InputError> {
        let fd = terminal
            .try_clone()
            .map_err(|_| InputError::Unavailable)?
            .into();
        let mut previous = MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(terminal.as_raw_fd(), previous.as_mut_ptr()) } != 0 {
            return Err(InputError::Unavailable);
        }
        let previous = unsafe { previous.assume_init() };
        let guard = Self { fd, previous };
        let mut hidden = guard.previous;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        hidden.c_iflag &= !(libc::IXON | libc::ICRNL | libc::INLCR | libc::IGNCR);
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(terminal.as_raw_fd(), libc::TCSAFLUSH, &hidden) } != 0 {
            return Err(InputError::Unavailable);
        }
        Ok(guard)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.previous);
        }
    }
}

struct SignalGuard {
    fd: OwnedFd,
    previous: libc::sigset_t,
}
impl SignalGuard {
    fn new() -> Result<Self, InputError> {
        let mut set = MaybeUninit::uninit();
        unsafe {
            libc::sigemptyset(set.as_mut_ptr());
        }
        let mut set = unsafe { set.assume_init() };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            unsafe {
                libc::sigaddset(&mut set, signal);
            }
        }
        let mut previous = MaybeUninit::uninit();
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, previous.as_mut_ptr()) } != 0 {
            return Err(InputError::Unavailable);
        }
        let previous = unsafe { previous.assume_init() };
        let raw = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if raw < 0 {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
            return Err(InputError::Unavailable);
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            previous,
        })
    }
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
#[path = "tty_tests.rs"]
mod tests;
