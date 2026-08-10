/// Maximum serialized size accepted for a verified root admission claim.
pub const MAX_ROOT_HANDLE_ADMISSION_BYTES: usize = 4096;

/// Opaque, single-use admission for binding a transferred native directory handle.
///
/// Its only constructor is crate-private so transport callers cannot forge a
/// filesystem admission or substitute a renderer-visible path.
pub struct RootHandleAdmission {
    bytes: Box<[u8]>,
}

impl RootHandleAdmission {
    /// Creates an opaque verified admission for internal claim producers.
    #[allow(dead_code)]
    pub(crate) fn from_verified_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ROOT_HANDLE_ADMISSION_BYTES { return None; }
        Some(Self { bytes: bytes.into_boxed_slice() })
    }

    /// Consumes this single-use admission after runtime verification.
    pub fn consume(self) {
        let _ = self.bytes.len();
    }
}

impl std::fmt::Debug for RootHandleAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RootHandleAdmission([REDACTED])")
    }
}
