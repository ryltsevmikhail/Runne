use sha2::{Digest, Sha256};

use super::{NativeSecretRef, ScannerError, TailBinding};

const CHECKPOINT_V1: &[u8] = b"RUNNE_SCANNER_CHECKPOINT_V1\0";

/// Canonical checkpoint containing metadata and an opaque tail reference only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerCheckpoint {
    tail_reference: NativeSecretRef,
    binding: TailBinding,
    sequence: u64,
    safe_prefix_high_water: u64,
    checkpoint_id: [u8; 16],
    digest: [u8; 32],
}

impl ScannerCheckpoint {
    /// Constructs and digests one canonical checkpoint.
    pub fn new(
        tail_reference: NativeSecretRef,
        binding: TailBinding,
        sequence: u64,
        safe_prefix_high_water: u64,
    ) -> Result<Self, ScannerError> {
        if sequence == 0
            || safe_prefix_high_water > binding.cursor()
            || tail_reference.binding_digest() != &binding.digest()
        {
            return Err(ScannerError::InvalidCheckpoint);
        }
        let digest = checkpoint_digest(tail_reference, binding, sequence, safe_prefix_high_water);
        let mut checkpoint_id = [0; 16];
        checkpoint_id.copy_from_slice(&digest[..16]);
        Ok(Self {
            tail_reference,
            binding,
            sequence,
            safe_prefix_high_water,
            checkpoint_id,
            digest,
        })
    }

    /// Reconstructs and validates an exact durable checkpoint.
    pub fn from_durable(
        tail_reference: NativeSecretRef,
        binding: TailBinding,
        sequence: u64,
        safe_prefix_high_water: u64,
        checkpoint_id: [u8; 16],
        digest: [u8; 32],
    ) -> Result<Self, ScannerError> {
        let value = Self::new(tail_reference, binding, sequence, safe_prefix_high_water)?;
        if value.checkpoint_id != checkpoint_id || value.digest != digest {
            return Err(ScannerError::InvalidCheckpoint);
        }
        Ok(value)
    }

    /// Returns the opaque native tail reference.
    pub const fn tail_reference(self) -> NativeSecretRef {
        self.tail_reference
    }
    /// Returns the checkpoint binding.
    pub const fn binding(self) -> TailBinding {
        self.binding
    }
    /// Returns the monotonic checkpoint sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Returns the scanned safe-prefix high-water.
    pub const fn safe_prefix_high_water(self) -> u64 {
        self.safe_prefix_high_water
    }
    /// Returns the stable checkpoint identity.
    pub const fn checkpoint_id(self) -> [u8; 16] {
        self.checkpoint_id
    }
    /// Returns the canonical checkpoint digest.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

fn checkpoint_digest(
    reference: NativeSecretRef,
    binding: TailBinding,
    sequence: u64,
    high_water: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_V1);
    hasher.update(reference.id());
    hasher.update(reference.version().to_be_bytes());
    hasher.update(reference.binding_digest());
    hasher.update(binding.digest());
    hasher.update(sequence.to_be_bytes());
    hasher.update(high_water.to_be_bytes());
    hasher.finalize().into()
}
