//! Provider-neutral secret-withholding and recovery contracts.

mod checkpoint;
mod scanner;
mod types;

pub use checkpoint::ScannerCheckpoint;
pub use scanner::{CredentialMatcher, ScanStep, scan_provider_chunk};
pub use types::{
    NativeSecretRef, ScannerError, ScannerTerminalDisposition, ScannerUncertainReason,
    SecureStoreError, TailBinding, WithheldTailStore,
};
