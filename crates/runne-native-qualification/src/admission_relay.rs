use std::fmt;

/// Closed rejection while turning one admitted pair into ordered relay frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionRelayError;

impl fmt::Display for QualificationAdmissionRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification admission relay rejected")
    }
}

impl std::error::Error for QualificationAdmissionRelayError {}

/// Opaque move-only runner-context-then-fault relay output.
pub struct QualificationAdmissionRelayPair {
    frames: [Vec<u8>; 2],
}

impl QualificationAdmissionRelayPair {
    pub(crate) const fn new(context: Vec<u8>, fault: Vec<u8>) -> Self {
        Self {
            frames: [context, fault],
        }
    }

    /// Consumes the pair into its only exact context-first ordered output.
    #[must_use]
    pub fn into_ordered_frames(self) -> [Vec<u8>; 2] {
        self.frames
    }
}
