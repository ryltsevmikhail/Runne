//! Audited Windows-only ownership boundary for native directory handles.
//!
//! No caller receives a raw handle, a path-derived identity, or an inheritable
//! descriptor. The only `unsafe` code in the desktop root-broker path lives in
//! this crate and is intentionally target-gated.

#![cfg(windows)]

pub(crate) mod duplicate;
pub(crate) mod identity;
pub(crate) mod relative;

pub use duplicate::{ExactTargetProcess, RemoteHandleLease};
pub use identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError};
