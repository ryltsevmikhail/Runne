#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

const CONTROL_BYTES: usize = 4096;
// XNU pins UIPC_MAX_CMSG_FD to 512 at commit
// f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, bsd/kern/uipc_usrreq.c.
const XNU_UIPC_MAX_CMSG_FD: libc::c_uint = 512;
const DARWIN_CMSG_ALIGNMENT: usize = size_of::<u32>();
const HEADER_BYTES: usize = align_4(size_of::<libc::cmsghdr>());
// SAFETY: CMSG_SPACE is a pure size calculation for a bounded payload length.
const XNU_MAX_RIGHTS_SPACE: usize = unsafe { libc::CMSG_SPACE(XNU_UIPC_MAX_CMSG_FD * 4) as usize };
const _: () = assert!(CONTROL_BYTES >= XNU_MAX_RIGHTS_SPACE);
const _: () = assert!(size_of::<libc::c_int>() == 4);
const _: () = assert!(16 >= std::mem::align_of::<libc::cmsghdr>());

#[repr(C, align(16))]
struct AlignedControl<const N: usize>([MaybeUninit<u8>; N]);

pub(super) struct RawSegment {
    pub(super) bytes: usize,
    pub(super) descriptors: Vec<OwnedFd>,
    pub(super) truncated: bool,
}

pub(super) fn receive(socket: BorrowedFd<'_>, bytes: &mut [u8]) -> io::Result<RawSegment> {
    receive_with_control::<CONTROL_BYTES>(socket, bytes)
}

fn receive_with_control<const N: usize>(
    socket: BorrowedFd<'_>,
    bytes: &mut [u8],
) -> io::Result<RawSegment> {
    let mut control = AlignedControl([MaybeUninit::new(0); N]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe {
        // SAFETY: An all-zero msghdr is a valid base before assigning the two
        // caller-owned buffers used by recvmsg.
        std::mem::zeroed()
    };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = N.try_into().map_err(|_| invalid_record())?;

    let received = unsafe {
        // SAFETY: socket is borrowed for this call; iov and control point to
        // writable live buffers whose exact lengths are recorded in message.
        libc::recvmsg(socket.as_raw_fd(), &raw mut message, libc::MSG_DONTWAIT)
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        // Darwin may install rights whose numbers do not fit in msg_control.
        // Process teardown is the only way to close those unnamed entries.
        std::process::abort();
    }
    let control_len = message.msg_controllen as usize;
    if control_len > N {
        std::process::abort();
    }
    let descriptors = parse_control(&control, control_len)?;
    Ok(RawSegment {
        bytes: usize::try_from(received).map_err(io::Error::other)?,
        descriptors,
        truncated: message.msg_flags & libc::MSG_TRUNC != 0,
    })
}

fn parse_control<const N: usize>(
    control: &AlignedControl<N>,
    length: usize,
) -> io::Result<Vec<OwnedFd>> {
    if length > N {
        return Err(invalid_record());
    }
    let bytes = unsafe {
        // SAFETY: length is bounded above by N, and the entire aligned buffer
        // is initialized before recvmsg, including untouched padding bytes.
        std::slice::from_raw_parts(control.0.as_ptr().cast::<u8>(), length)
    };
    let mut state = ParseState::default();
    let mut offset = 0;
    while length.saturating_sub(offset) >= HEADER_BYTES {
        let header = unsafe {
            // SAFETY: the range check above covers one complete header; an
            // unaligned read avoids imposing a stronger alignment contract.
            std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<libc::cmsghdr>())
        };
        let message_len = header.cmsg_len as usize;
        let Some(end) = offset.checked_add(message_len) else {
            state.rejected = true;
            break;
        };
        if message_len < HEADER_BYTES || end > length {
            state.rejected = true;
            break;
        }
        let payload = &bytes[offset + HEADER_BYTES..end];
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            state.adopt_rights(payload);
        } else {
            state.rejected = true;
        }
        if end == length {
            offset = end;
            break;
        }
        let Some(next) = checked_align_4(end) else {
            state.rejected = true;
            break;
        };
        if next <= offset || next > length {
            state.rejected = true;
            break;
        }
        offset = next;
    }
    if offset != length {
        state.rejected = true;
    }
    state.finish()
}

#[derive(Default)]
struct ParseState {
    descriptors: Vec<OwnedFd>,
    seen: BTreeSet<libc::c_int>,
    rejected: bool,
    first_error: Option<io::Error>,
}

impl ParseState {
    fn adopt_rights(&mut self, payload: &[u8]) {
        if payload.is_empty() {
            self.rejected = true;
            return;
        }
        if !payload.len().is_multiple_of(size_of::<libc::c_int>()) {
            self.rejected = true;
        }
        for raw in payload.chunks_exact(size_of::<libc::c_int>()) {
            let mut encoded = [0; size_of::<libc::c_int>()];
            encoded.copy_from_slice(raw);
            let raw = libc::c_int::from_ne_bytes(encoded);
            if raw < 0 {
                self.rejected = true;
                continue;
            }
            if !self.seen.insert(raw) {
                self.rejected = true;
                continue;
            }
            let descriptor = unsafe {
                // SAFETY: a non-CTRUNC SCM_RIGHTS payload returned by the
                // Darwin kernel transfers ownership of each visible fd.
                OwnedFd::from_raw_fd(raw)
            };
            match add_and_verify_cloexec(&descriptor) {
                Ok(()) => self.descriptors.push(descriptor),
                Err(error) => {
                    self.rejected = true;
                    if self.first_error.is_none() {
                        self.first_error = Some(error);
                    }
                }
            }
        }
    }

    fn finish(self) -> io::Result<Vec<OwnedFd>> {
        if let Some(error) = self.first_error {
            return Err(error);
        }
        if self.rejected {
            return Err(invalid_record());
        }
        Ok(self.descriptors)
    }
}

fn add_and_verify_cloexec(descriptor: &OwnedFd) -> io::Result<()> {
    let original = fcntl(descriptor, FcntlArg::F_GETFD).map_err(io::Error::from)?;
    let flags = FdFlag::from_bits_retain(original) | FdFlag::FD_CLOEXEC;
    fcntl(descriptor, FcntlArg::F_SETFD(flags)).map_err(io::Error::from)?;
    let verified = fcntl(descriptor, FcntlArg::F_GETFD).map_err(io::Error::from)?;
    FdFlag::from_bits_retain(verified)
        .contains(FdFlag::FD_CLOEXEC)
        .then_some(())
        .ok_or_else(invalid_record)
}

const fn align_4(value: usize) -> usize {
    (value + (DARWIN_CMSG_ALIGNMENT - 1)) & !(DARWIN_CMSG_ALIGNMENT - 1)
}

fn checked_align_4(value: usize) -> Option<usize> {
    value
        .checked_add(DARWIN_CMSG_ALIGNMENT - 1)
        .map(|value| value & !(DARWIN_CMSG_ALIGNMENT - 1))
}

fn invalid_record() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid writer handoff control")
}

#[cfg(test)]
#[path = "raw_recvmsg_macos_tests.rs"]
mod tests;
#[cfg(test)]
pub(super) use tests::{
    control_buffer_covers_xnu_ceiling as test_control_buffer_covers_xnu_ceiling,
    parse_duplicate_rights as test_parse_duplicate_rights,
    parse_negative_then_rights as test_parse_negative_then_rights,
    parse_partial_rights as test_parse_partial_rights,
    parse_rights_then_malformed as test_parse_rights_then_malformed,
    parse_rights_then_trailing as test_parse_rights_then_trailing,
    parse_unknown_then_rights as test_parse_unknown_then_rights,
    receive_with_tiny_control as test_receive_with_tiny_control,
    send_with_descriptors as test_send_with_descriptors,
};
