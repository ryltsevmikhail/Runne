use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, FileIdInfo,
    GetFileInformationByHandleEx, OPEN_EXISTING,
};

use crate::path::ValidatedWindowsPath;
use crate::relative::open_relative_component;

/// Fail-closed native-handle failures. OS details are intentionally not exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHandleError {
    /// The supplied path, object type, or stable identity was unsafe.
    Rejected,
    /// A required Windows primitive was unavailable or failed.
    Unavailable,
    /// The target process is not the exact expected process.
    TargetMismatch,
}

impl fmt::Display for NativeHandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("native directory handle rejected")
    }
}

impl std::error::Error for NativeHandleError {}

/// ReFS-safe stable native identity, never derived from a path.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DirectoryIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

impl fmt::Debug for DirectoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectoryIdentity(<redacted>)")
    }
}

impl DirectoryIdentity {
    /// Returns a fixed native-identity digest suitable for an admission binding.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"runne.windows-directory-identity.v1");
        hasher.update(self.volume_serial.to_be_bytes());
        hasher.update(self.file_id);
        hasher.finalize().into()
    }

    pub(crate) const fn wire_parts(self) -> (u64, [u8; 16]) {
        (self.volume_serial, self.file_id)
    }

    pub(crate) fn from_wire(
        volume_serial: u64,
        file_id: [u8; 16],
    ) -> Result<Self, NativeHandleError> {
        if volume_serial == 0 || file_id == [0; 16] {
            return Err(NativeHandleError::Rejected);
        }
        Ok(Self {
            volume_serial,
            file_id,
        })
    }
}

/// Move-only directory handle with verified identity and no path retention.
pub struct DirectoryHandle {
    handle: OwnedHandle,
    identity: DirectoryIdentity,
}

impl DirectoryHandle {
    /// Opens an absolute Windows directory one component at a time.
    ///
    /// # Errors
    ///
    /// Returns a closed error for relative, reparse-point, non-directory, or
    /// identity-query failures.
    pub fn open(path: &Path) -> Result<Self, NativeHandleError> {
        let path = ValidatedWindowsPath::absolute(path)?;
        let mut current = open_anchor(path.anchor())?;
        verify_directory(&current)?;
        for component in path.components() {
            current = open_relative_component(&current, component)?;
            verify_directory(&current)?;
        }
        Self::from_owned(current)
    }

    /// Opens a directory beneath this handle without resolving reparse points.
    ///
    /// # Errors
    ///
    /// Returns a closed error for traversal, reparse-point, non-directory, or
    /// identity-query failures.
    pub fn open_relative_directory(&self, path: &Path) -> Result<Self, NativeHandleError> {
        let components = ValidatedWindowsPath::relative(path)?;
        let mut current = self.handle.try_clone()?;
        for component in components {
            current = open_relative_component(&current, &component)?;
            verify_directory(&current)?;
        }
        Self::from_owned(current)
    }

    /// Returns an independently owned local clone after rechecking its identity.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the clone cannot be created or its identity
    /// does not match the original directory.
    pub fn try_clone(&self) -> Result<Self, NativeHandleError> {
        let cloned = self.handle.try_clone()?;
        let clone = Self::from_owned(cloned)?;
        (clone.identity == self.identity)
            .then_some(clone)
            .ok_or(NativeHandleError::Rejected)
    }

    /// Returns the stable identity for native admission binding.
    #[must_use]
    pub const fn identity(&self) -> DirectoryIdentity {
        self.identity
    }

    pub(crate) const fn raw(&self) -> HANDLE {
        self.handle.raw()
    }

    pub(crate) const fn owned_handle(&self) -> &OwnedHandle {
        &self.handle
    }

    pub(crate) fn from_owned(handle: OwnedHandle) -> Result<Self, NativeHandleError> {
        let identity = identity_for(handle.raw())?;
        Ok(Self { handle, identity })
    }
}

impl fmt::Debug for DirectoryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectoryHandle(<redacted>)")
    }
}

pub struct OwnedHandle(HANDLE);

// Windows kernel handles retain their ownership semantics across threads. The
// raw value stays private, and every close remains exclusively owned by `Drop`.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub fn new(handle: HANDLE) -> Result<Self, NativeHandleError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(NativeHandleError::Unavailable);
        }
        // SAFETY: `handle` is newly owned and valid; this only clears inheritance.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            // SAFETY: `handle` is newly owned and must be released on this failure path.
            let _ = unsafe { CloseHandle(handle) };
            return Err(NativeHandleError::Unavailable);
        }
        Ok(Self(handle))
    }

    pub fn try_clone(&self) -> Result<Self, NativeHandleError> {
        crate::duplicate::duplicate_local(self.raw())
    }

    pub const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this type owns its valid handle exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn open_anchor(path: &Path) -> Result<OwnedHandle, NativeHandleError> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: `wide` is NUL-terminated for the duration of this synchronous call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    OwnedHandle::new(handle)
}

pub fn verify_directory(handle: &OwnedHandle) -> Result<DirectoryIdentity, NativeHandleError> {
    identity_for(handle.raw())
}

fn identity_for(handle: HANDLE) -> Result<DirectoryIdentity, NativeHandleError> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut file_id = FILE_ID_INFO::default();
    // SAFETY: both stack buffers have the exact structure sizes requested.
    let attributes_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap(),
        )
    };
    // SAFETY: `file_id` has the exact layout required by FileIdInfo.
    let identity_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut file_id).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap(),
        )
    };
    if attributes_ok == 0
        || identity_ok == 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || unsupported_file_id(&file_id)
    {
        return Err(NativeHandleError::Rejected);
    }
    Ok(DirectoryIdentity {
        volume_serial: file_id.VolumeSerialNumber,
        file_id: file_id.FileId.Identifier,
    })
}

fn unsupported_file_id(file_id: &FILE_ID_INFO) -> bool {
    file_id.VolumeSerialNumber == 0 || file_id.FileId.Identifier == [0; 16]
}
