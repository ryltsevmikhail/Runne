//! Windows inherited named-pipe admission transport.

use std::os::windows::io::{AsHandle, AsRawHandle, OwnedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, ERROR_PIPE_CONNECTED, GetLastError};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, GetNamedPipeInfo};

use super::{LaunchAuthorityError, ProtectedActivationChannel};

/// Takes ownership of the inherited stdin handle only when it is the protected
/// named-pipe server endpoint. Ordinary console/file stdin remains external
/// daemon mode and is left untouched.
pub(super) fn from_inherited_stdin()
-> Result<Option<ProtectedActivationChannel>, LaunchAuthorityError> {
    let stdin = std::io::stdin();
    let owned: OwnedHandle = stdin
        .as_handle()
        .try_clone_to_owned()
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    let raw = owned.as_raw_handle();
    let mut flags = 0_u32;
    let mut out_size = 0_u32;
    let mut in_size = 0_u32;
    let is_pipe = unsafe {
        GetNamedPipeInfo(
            raw as _,
            &mut flags,
            &mut out_size,
            &mut in_size,
            null_mut(),
        )
    } != 0;
    if !is_pipe {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_HANDLE {
            return Ok(None);
        }
        return Err(LaunchAuthorityError::ProtectedChannelUnavailable);
    }

    let connected = unsafe { ConnectNamedPipe(raw as _, null_mut()) } != 0;
    if !connected {
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            return Err(LaunchAuthorityError::ProtectedChannelUnavailable);
        }
    }
    ProtectedActivationChannel::new(owned.into()).map(Some)
}
