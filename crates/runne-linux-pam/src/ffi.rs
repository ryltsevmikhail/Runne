#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::ptr;

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_CONV_ERR: c_int = 6;
pub const PAM_USER: c_int = 2;
pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;
const MAX_NSS_BUFFER: usize = 128 * 1024;
const MAX_USER_BYTES: usize = 256;

#[repr(C)]
pub struct PamMessage {
    pub(super) msg_style: c_int,
    pub(super) msg: *const c_char,
}

#[repr(C)]
pub struct PamResponse {
    pub(super) resp: *mut c_char,
    pub(super) resp_retcode: c_int,
}

pub type ConversationCallback = unsafe extern "C" fn(
    c_int,
    *const *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
pub struct PamConversation {
    pub(super) conv: Option<ConversationCallback>,
    pub(super) appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conversation: *const PamConversation,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_get_item(handle: *mut c_void, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
}

pub struct PamSession {
    handle: *mut c_void,
    last_status: c_int,
}

impl PamSession {
    pub(super) fn start(user: &CStr, conversation: &PamConversation) -> Result<Self, c_int> {
        let mut handle = ptr::null_mut();
        // SAFETY: both C strings and the conversation remain live for the PAM transaction.
        let status = unsafe {
            pam_start(
                c"system-auth".as_ptr(),
                user.as_ptr(),
                conversation,
                &raw mut handle,
            )
        };
        if status != PAM_SUCCESS || handle.is_null() {
            if !handle.is_null() {
                // SAFETY: pam_start returned an owned handle even though it reported failure.
                unsafe { pam_end(handle, status) };
            }
            return Err(status);
        }
        Ok(Self {
            handle,
            last_status: status,
        })
    }

    pub(super) fn authenticate(&mut self) -> c_int {
        // SAFETY: the handle is live and flags prohibit null authentication tokens.
        let status = unsafe { pam_authenticate(self.handle, PAM_DISALLOW_NULL_AUTHTOK) };
        self.last_status = status;
        status
    }

    pub(super) fn account_management(&mut self) -> c_int {
        // SAFETY: the handle is live; no account-management options are requested.
        let status = unsafe { pam_acct_mgmt(self.handle, 0) };
        self.last_status = status;
        status
    }

    pub(super) fn pam_user(&mut self) -> Result<CString, ()> {
        let mut value = ptr::null();
        // SAFETY: the handle is live and `value` is writable output storage.
        let status = unsafe { pam_get_item(self.handle, PAM_USER, &raw mut value) };
        self.last_status = status;
        if status != PAM_SUCCESS || value.is_null() {
            return Err(());
        }
        // SAFETY: PAM returns a NUL-terminated PAM_USER item for a live handle.
        bounded_c_string(value.cast(), MAX_USER_BYTES).ok_or(())
    }

    pub(super) fn finish(mut self) -> c_int {
        // SAFETY: this wrapper uniquely owns the live PAM handle until this call.
        let status = unsafe { pam_end(self.handle, self.last_status) };
        self.handle = ptr::null_mut();
        status
    }
}

impl Drop for PamSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: this wrapper uniquely owns the live handle and ends it exactly once.
            unsafe { pam_end(self.handle, self.last_status) };
            self.handle = ptr::null_mut();
        }
    }
}

pub fn real_uid() -> u32 {
    // SAFETY: getuid has no pointer or ownership preconditions.
    unsafe { libc::getuid() }
}

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no pointer or ownership preconditions.
    unsafe { libc::geteuid() }
}

pub fn username_for_uid(uid: u32) -> Result<CString, ()> {
    let uid = libc::uid_t::try_from(uid).map_err(|_| ())?;
    lookup_passwd(|record, buffer, result| {
        // SAFETY: `record`, `buffer`, and `result` are valid writable NSS outputs.
        unsafe { libc::getpwuid_r(uid, record, buffer, MAX_NSS_BUFFER, result) }
    })
    .map(|identity| identity.name)
}

pub fn uid_for_username(name: &CStr) -> Result<u32, ()> {
    lookup_passwd(|record, buffer, result| {
        // SAFETY: `name` is NUL-terminated and all NSS output pointers are valid.
        unsafe { libc::getpwnam_r(name.as_ptr(), record, buffer, MAX_NSS_BUFFER, result) }
    })
    .map(|identity| identity.uid)
}

struct PasswdIdentity {
    name: CString,
    uid: u32,
}

fn lookup_passwd(
    mut lookup: impl FnMut(*mut libc::passwd, *mut c_char, *mut *mut libc::passwd) -> c_int,
) -> Result<PasswdIdentity, ()> {
    let mut buffer = vec![0_u8; MAX_NSS_BUFFER];
    let mut record = MaybeUninit::<libc::passwd>::zeroed();
    let mut result = ptr::null_mut();
    let status = lookup(
        record.as_mut_ptr(),
        buffer.as_mut_ptr().cast(),
        &raw mut result,
    );
    if status != 0 || result.is_null() {
        return Err(());
    }
    // SAFETY: a zero return with a non-null result initializes the passwd record.
    let record = unsafe { record.assume_init() };
    if record.pw_name.is_null() {
        return Err(());
    }
    // SAFETY: NSS returned a NUL-terminated name stored in the provided buffer.
    let name = bounded_c_string(record.pw_name, MAX_USER_BYTES).ok_or(())?;
    Ok(PasswdIdentity {
        name,
        uid: record.pw_uid,
    })
}

fn bounded_c_string(pointer: *const c_char, maximum: usize) -> Option<CString> {
    if pointer.is_null() {
        return None;
    }
    let length = (0..maximum).find(|offset| {
        // SAFETY: callers provide a valid C string with at least one NUL in the bound.
        unsafe { *pointer.add(*offset) == 0 }
    })?;
    // SAFETY: the scan found a NUL within `maximum`, so this byte slice is bounded.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    CString::new(bytes).ok()
}
