//! Parse terminal editing and bracketed paste without retaining control bytes.
use super::InputError;
use zeroize::Zeroizing;

pub(super) struct Input {
    secret: Zeroizing<Vec<u8>>,
    escape: usize,
    pasting: bool,
}

impl Input {
    pub(super) fn new() -> Self {
        Self {
            secret: Zeroizing::new(Vec::with_capacity(4096)),
            escape: 0,
            pasting: false,
        }
    }

    /// True only for an explicit Enter outside a complete paste envelope.
    pub(super) fn push(&mut self, byte: u8) -> Result<bool, InputError> {
        if matches!(byte, 3 | 4) {
            return Err(InputError::Cancelled);
        }
        if self.escape > 0 {
            let marker = if self.pasting {
                b"\x1b[201~"
            } else {
                b"\x1b[200~"
            };
            if byte != marker[self.escape] {
                return Err(InputError::Invalid);
            }
            self.escape += 1;
            if self.escape == marker.len() {
                self.escape = 0;
                self.pasting = !self.pasting;
            }
            return Ok(false);
        }
        match byte {
            27 => self.escape = 1,
            b'\n' | b'\r' if !self.pasting && !self.secret.is_empty() => return Ok(true),
            8 | 127 if !self.pasting => {
                if let Some(last) = self.secret.last_mut() {
                    *last = 0;
                }
                self.secret.pop();
            }
            33..=126 if self.secret.len() < 4096 => self.secret.push(byte),
            _ => return Err(InputError::Invalid),
        }
        Ok(false)
    }

    pub(super) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.secret
    }
}
