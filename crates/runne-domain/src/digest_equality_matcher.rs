/// Opaque, non-authoritative equality oracle for one 256-bit digest.
pub struct DigestEqualityMatcherV1 {
    expected: [u8; 32],
}

impl DigestEqualityMatcherV1 {
    /// Retains the expected digest without exposing it again.
    #[doc(hidden)]
    #[must_use]
    pub fn from_expected(expected: [u8; 32]) -> Self {
        Self { expected }
    }

    /// Compares all 32 candidate bytes before returning one boolean.
    #[doc(hidden)]
    #[must_use]
    pub fn matches(&self, candidate: &[u8; 32]) -> bool {
        let mut difference = 0_u8;
        for (expected, candidate) in core::iter::zip(&self.expected, candidate) {
            difference |= expected ^ candidate;
        }
        difference == 0
    }
}
