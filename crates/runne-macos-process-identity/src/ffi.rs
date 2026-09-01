#![allow(unsafe_code)]

use std::mem::MaybeUninit;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::MacOsProcessIdentityError;

const DOMAIN: &[u8] = b"runne.macos-process-identity.v1";
const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
const VM_PROT_EXECUTE: u32 = 4;
const MAX_REGIONS: usize = 16_384;

#[derive(Eq, PartialEq)]
pub struct ExecutableVnodeIdentity {
    device: u32,
    inode: u64,
    links: u16,
}

impl ExecutableVnodeIdentity {
    pub fn matches_file(&self, metadata: &std::fs::Metadata) -> bool {
        u64::from(self.device) == metadata.dev()
            && self.inode == metadata.ino()
            && self.links == 1
            && metadata.nlink() == 1
    }
}

#[repr(C)]
struct ProcRegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    object_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[repr(C)]
struct ProcRegionWithPathInfo {
    region: ProcRegionInfo,
    vnode: libc::vnode_info_path,
}

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

pub fn observe_executable_vnode(
    pid: NonZeroU32,
    expected_path: &Path,
) -> Result<ExecutableVnodeIdentity, MacOsProcessIdentityError> {
    let expected = expected_path.as_os_str().as_bytes();
    observe_matching_executable_vnode(pid, |path, _identity| path == expected)
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "private package module and crate-root tests share this scanner"
)]
pub(crate) fn observe_executable_vnode_matching_file(
    pid: NonZeroU32,
    expected: &std::fs::File,
) -> Result<ExecutableVnodeIdentity, MacOsProcessIdentityError> {
    let metadata = expected.metadata().map_err(|_| MacOsProcessIdentityError)?;
    observe_matching_executable_vnode(pid, |_path, identity| identity.matches_file(&metadata))
}

fn observe_matching_executable_vnode(
    pid: NonZeroU32,
    matches: impl Fn(&[u8], &ExecutableVnodeIdentity) -> bool,
) -> Result<ExecutableVnodeIdentity, MacOsProcessIdentityError> {
    let pid = i32::try_from(pid.get()).map_err(|_| MacOsProcessIdentityError)?;
    let size = i32::try_from(std::mem::size_of::<ProcRegionWithPathInfo>())
        .map_err(|_| MacOsProcessIdentityError)?;
    let mut address = 0_u64;
    for _ in 0..MAX_REGIONS {
        let mut info = MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
        // SAFETY: `info` is a writable buffer with the exact requested layout.
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                address,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if bytes != size {
            return Err(MacOsProcessIdentityError);
        }
        // SAFETY: an exact-sized result means the kernel initialized all fields.
        let info = unsafe { info.assume_init() };
        let next = info
            .region
            .address
            .checked_add(info.region.size)
            .filter(|next| *next > address)
            .ok_or(MacOsProcessIdentityError)?;
        let path = vnode_path_bytes(&info.vnode)?;
        if info.region.protection & VM_PROT_EXECUTE != 0 {
            let stat = info.vnode.vip_vi.vi_stat;
            let identity = ExecutableVnodeIdentity {
                device: stat.vst_dev,
                inode: stat.vst_ino,
                links: stat.vst_nlink,
            };
            if matches(path, &identity) {
                return Ok(identity);
            }
        }
        address = next;
    }
    Err(MacOsProcessIdentityError)
}

fn vnode_path_bytes(vnode: &libc::vnode_info_path) -> Result<&[u8], MacOsProcessIdentityError> {
    let bytes = unsafe {
        std::slice::from_raw_parts(
            vnode.vip_path.as_ptr().cast::<u8>(),
            std::mem::size_of_val(&vnode.vip_path),
        )
    };
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(MacOsProcessIdentityError)?;
    Ok(&bytes[..end])
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
