use std::fmt;

/// Closed rejection for one exact ordered admission relay transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionRelayError;

impl fmt::Display for QualificationAdmissionRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification admission relay rejected")
    }
}

impl std::error::Error for QualificationAdmissionRelayError {}

/// Opaque move-only context-then-fault relay transcript.
pub struct QualificationAdmissionRelayTranscript {
    bytes: Vec<u8>,
}

impl QualificationAdmissionRelayTranscript {
    pub(crate) const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Consumes the transcript into its single exact transport byte sequence.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
