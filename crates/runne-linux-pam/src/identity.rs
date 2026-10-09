use std::ffi::CString;

use crate::ffi;
use crate::types::ReauthenticationError;

pub fn current_uid() -> Result<u32, ReauthenticationError> {
    let uid = ffi::real_uid();
    if uid != ffi::effective_uid() {
        return Err(ReauthenticationError::IdentityUnavailable);
    }
    Ok(uid)
}

pub fn username_for_uid(uid: u32) -> Result<CString, ReauthenticationError> {
    ffi::username_for_uid(uid).map_err(|()| ReauthenticationError::IdentityUnavailable)
}

pub fn verify_pam_user(pam_user: &CString, expected_uid: u32) -> Result<(), ReauthenticationError> {
    if pam_user.as_bytes().is_empty()
        || ffi::uid_for_username(pam_user.as_c_str())
            .map_err(|()| ReauthenticationError::IdentityUnavailable)?
            != expected_uid
    {
        return Err(ReauthenticationError::IdentityUnavailable);
    }
    Ok(())
}
