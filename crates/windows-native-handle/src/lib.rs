//! Audited Windows-only ownership boundary for native directory handles.
//!
//! No caller receives a raw handle, a path-derived identity, or an inheritable
//! descriptor. The only `unsafe` code in the desktop root-broker path lives in
//! this crate and is intentionally target-gated.

mod clock;
#[cfg_attr(not(windows), allow(dead_code))]
mod model;
#[cfg_attr(not(windows), allow(dead_code))]
mod model_expiry;
mod protocol;
#[cfg_attr(not(windows), allow(dead_code))]
mod wire;

pub use clock::{ClockSample, ProtocolClock};
pub use protocol::ProtocolError;
pub use wire::{HandleAckReady, HandleFinalize, HandleNack, ProtectedHandleOffer};

#[cfg(test)]
mod model_tests;
#[cfg(test)]
mod wire_tests;

#[cfg(windows)]
mod duplicate;
#[cfg(windows)]
mod identity;
#[cfg(windows)]
mod path;
#[cfg(windows)]
mod receiver;
#[cfg(windows)]
mod relative;

#[cfg(windows)]
pub use duplicate::{
    ExactTargetProcess, LauncherProcessBinding, OfferedRemoteHandleLease, RemoteHandleLease,
};
#[cfg(windows)]
pub use identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError};
#[cfg(windows)]
pub use receiver::{CommittedDirectory, ReceiverDisposition, StagedHandleReceiver};
