#![allow(unsafe_code)]

use std::mem::MaybeUninit;
use std::num::NonZeroU32;

use sha2::{Digest, Sha256};

use crate::MacOsProcessIdentityError;

const DOMAIN: &[u8] = b"runne.macos-process-identity.v1";

pub fn observe(pid: NonZeroU32) -> Result<[u8; 32], MacOsProcessIdentityError> {
    let pid = i32::try_from(pid.get()).map_err(|_| MacOsProcessIdentityError)?;
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
        .map_err(|_| MacOsProcessIdentityError)?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is a valid writable buffer of the exact requested size.
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if bytes != size {
        return Err(MacOsProcessIdentityError);
    }
    // SAFETY: an exact-sized result means the kernel initialized all fields.
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != u32::try_from(pid).map_err(|_| MacOsProcessIdentityError)?
        || info.pbi_start_tvsec == 0
        || info.pbi_start_tvusec >= 1_000_000
    {
        return Err(MacOsProcessIdentityError);
    }
    Ok(digest(pid, info.pbi_start_tvsec, info.pbi_start_tvusec))
}

fn digest(pid: i32, seconds: u64, microseconds: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(pid.to_be_bytes());
    digest.update(seconds.to_be_bytes());
    digest.update(microseconds.to_be_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_uses_the_pinned_macos_kernel_tuple_layout() {
        assert_eq!(
            digest(42, 1_700_000_000, 123_456),
            [
                0x61, 0x00, 0x10, 0x3f, 0xa7, 0x3e, 0xee, 0x25, 0x5f, 0x47, 0x7c, 0xa0, 0xb3, 0xfb,
                0xad, 0x54, 0x68, 0x14, 0x44, 0x70, 0x2d, 0x07, 0x5d, 0x4f, 0x2b, 0x3e, 0x36, 0x7c,
                0x58, 0xa2, 0x77, 0x47,
            ]
        );
    }
}
