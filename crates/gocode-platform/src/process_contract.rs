//! Fail-closed native process platform stubs.

mod linux;
mod macos;
mod selector;
mod status;
mod windows;

#[cfg(test)]
mod tests;

pub use linux::LinuxProcessPlatformPort;
pub use macos::MacOsProcessPlatformPort;
pub use selector::{
    ProcessPlatformStubV1, ProcessPlatformTargetV1, UnsupportedProcessPlatformPort,
};
pub use status::{NATIVE_SANDBOX_STATUS, PROCESS_CONTRACT_STATUS};
pub use windows::WindowsProcessPlatformPort;
