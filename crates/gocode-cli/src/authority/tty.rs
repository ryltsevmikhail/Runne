//! Minimal TTY confirmation boundary used by future lifecycle ceremonies.

#[cfg(test)]
use super::super::CliError;

#[cfg(test)]
pub(super) trait Tty {
    fn stdin_is_terminal(&self) -> bool;
    fn stdout_is_terminal(&self) -> bool;
    fn read_confirmation(&mut self) -> Result<String, CliError>;

    fn confirm(&mut self, challenge: &str) -> Result<(), CliError> {
        require_terminal(self.stdin_is_terminal(), self.stdout_is_terminal())?;
        if self.read_confirmation()? == challenge {
            Ok(())
        } else {
            Err(CliError::AuthorityConfirmationFailed)
        }
    }
}

#[cfg(test)]
pub(super) const fn require_terminal(
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> Result<(), CliError> {
    if stdin_is_terminal && stdout_is_terminal {
        Ok(())
    } else {
        Err(CliError::AuthorityNonInteractive)
    }
}

#[cfg(test)]
pub(super) fn last_twelve_lower_hex(digest: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex[52..].into()
}

#[cfg(test)]
pub(super) fn confirm_digest(tty: &mut dyn Tty, digest: &[u8; 32]) -> Result<(), CliError> {
    tty.confirm(&last_twelve_lower_hex(digest))
}

#[cfg(test)]
fn read_confirmation_line(reader: &mut impl std::io::Read) -> Result<String, CliError> {
    let mut bytes = Vec::with_capacity(13);
    while bytes.len() < 14 {
        let mut byte = [0];
        if reader
            .read(&mut byte)
            .map_err(|_| CliError::AuthorityConfirmationFailed)?
            != 1
        {
            return Err(CliError::AuthorityConfirmationFailed);
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if bytes.len() != 13 || bytes[12] != b'\n' || !bytes[..12].iter().all(u8::is_ascii_hexdigit) {
        return Err(CliError::AuthorityConfirmationFailed);
    }
    String::from_utf8(bytes[..12].to_vec()).map_err(|_| CliError::AuthorityConfirmationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_redirected_streams_and_uses_exact_lower_hex_challenge() {
        assert!(matches!(
            require_terminal(false, true),
            Err(CliError::AuthorityNonInteractive)
        ));
        assert_eq!(last_twelve_lower_hex(&[0xab; 32]), "abababababab");
    }

    struct FakeTty {
        input: String,
        terminal: bool,
    }
    impl Tty for FakeTty {
        fn stdin_is_terminal(&self) -> bool {
            self.terminal
        }
        fn stdout_is_terminal(&self) -> bool {
            self.terminal
        }
        fn read_confirmation(&mut self) -> Result<String, CliError> {
            Ok(std::mem::take(&mut self.input))
        }
    }

    #[test]
    fn confirmation_requires_the_exact_lowercase_last_twelve_hex() {
        for input in ["ABABABABABAB", "abababababab\n", "abababababa"] {
            assert!(matches!(
                confirm_digest(
                    &mut FakeTty {
                        input: input.into(),
                        terminal: true
                    },
                    &[0xab; 32]
                ),
                Err(CliError::AuthorityConfirmationFailed)
            ));
        }
        assert!(
            confirm_digest(
                &mut FakeTty {
                    input: "abababababab".into(),
                    terminal: true
                },
                &[0xab; 32]
            )
            .is_ok()
        );
    }

    #[test]
    fn bounded_reader_accepts_only_a_twelve_hex_lf_line() {
        assert_eq!(
            read_confirmation_line(&mut &b"abababababab\n"[..]).expect("line"),
            "abababababab"
        );
        for mut input in [b"abababababab".as_slice(), b"ababababababx\n", b"short\n"] {
            assert!(matches!(
                read_confirmation_line(&mut input),
                Err(CliError::AuthorityConfirmationFailed)
            ));
        }
    }
}
