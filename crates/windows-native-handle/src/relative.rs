use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{HANDLE, OBJ_CASE_INSENSITIVE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::identity::{NativeHandleError, OwnedHandle};

pub fn open_relative_component(
    root: &OwnedHandle,
    component: &OsStr,
) -> Result<OwnedHandle, NativeHandleError> {
    let mut wide = component.encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.len() > usize::from(u16::MAX / 2) || wide.contains(&0) {
        return Err(NativeHandleError::Rejected);
    }
    let byte_len = u16::try_from(
        wide.len()
            .checked_mul(2)
            .ok_or(NativeHandleError::Rejected)?,
    )
    .map_err(|_| NativeHandleError::Rejected)?;
    let name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).unwrap(),
        RootDirectory: root.raw(),
        ObjectName: &raw const name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: this uses one validated UTF-16 component relative to the owned root.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_GENERIC_READ,
            &raw const attributes,
            &raw mut status,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    (result >= 0)
        .then_some(())
        .ok_or(NativeHandleError::Rejected)?;
    OwnedHandle::new(handle)
}
