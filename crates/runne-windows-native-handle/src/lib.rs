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
mod directory_files;
#[cfg(windows)]
mod duplicate;
#[cfg(windows)]
mod editor_files;
#[cfg(windows)]
mod identity;
#[cfg(windows)]
mod path;
#[cfg(windows)]
mod process_files;
#[cfg(all(test, windows))]
mod process_files_tests;
#[cfg(windows)]
mod protected_runtime;
#[cfg(windows)]
mod receiver;
#[cfg(windows)]
mod regular_file;
#[cfg(windows)]
mod relative;
#[cfg(windows)]
mod transfer;

#[cfg(windows)]
pub use directory_files::{NativeDirectoryEntry, NativeDirectoryEntryKind};
#[cfg(windows)]
pub use duplicate::{
    ExactTargetProcess, LauncherProcessBinding, OfferedRemoteHandleLease, RemoteHandleLease,
};
#[cfg(windows)]
pub use identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError};
#[cfg(windows)]
pub use process_files::ProcessFiles;
#[cfg(windows)]
pub use protected_runtime::{
    ProtectedNamedPipeChannel, assign_kill_on_close_job, named_pipe_peer_process_id,
    restrict_to_owner,
};
#[cfg(windows)]
pub use receiver::{CommittedDirectory, ReceiverDisposition, StagedHandleReceiver};
#[cfg(windows)]
pub use regular_file::{
    NativeFileError, RegularFileId, RegularFileSnapshot, identity_of_open_file,
    inspect_regular_file, move_regular_file_no_replace_write_through, sync_regular_file,
};
#[cfg(windows)]
pub use transfer::{ProtectedHandleReceiver, ProtectedHandleSender};
