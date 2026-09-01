#![cfg(test)]

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, IntoRawFd as _, OwnedFd};

use super::*;

pub(in crate::writer_endpoint_handoff) const fn control_buffer_covers_xnu_ceiling() -> bool {
    CONTROL_BYTES >= XNU_MAX_RIGHTS_SPACE
}

pub(in crate::writer_endpoint_handoff) fn receive_with_tiny_control(
    socket: BorrowedFd<'_>,
    bytes: &mut [u8],
) {
    let _ = receive_with_control::<16>(socket, bytes);
}

pub(in crate::writer_endpoint_handoff) fn parse_unknown_then_rights(
    descriptor: OwnedFd,
) -> io::Result<()> {
    parse_fixture(descriptor, true)
}

pub(in crate::writer_endpoint_handoff) fn parse_rights_then_malformed(
    descriptor: OwnedFd,
) -> io::Result<()> {
    parse_fixture(descriptor, false)
}

pub(in crate::writer_endpoint_handoff) fn parse_negative_then_rights(
    descriptor: OwnedFd,
) -> io::Result<()> {
    parse_rights_fixture(descriptor, &[-1], &[], 0)
}

pub(in crate::writer_endpoint_handoff) fn parse_duplicate_rights(
    descriptor: OwnedFd,
) -> io::Result<()> {
    parse_rights_fixture(descriptor, &[], &[0], 0)
}

pub(in crate::writer_endpoint_handoff) fn parse_partial_rights(
    descriptor: OwnedFd,
) -> io::Result<()> {
    let raw = descriptor.into_raw_fd();
    let payload = size_of::<libc::c_int>() + 1;
    let mut control = AlignedControl([MaybeUninit::new(0); 64]);
    write_header(&mut control, 0, libc::SOL_SOCKET, libc::SCM_RIGHTS, payload);
    for (slot, byte) in control.0[HEADER_BYTES..HEADER_BYTES + size_of::<libc::c_int>()]
        .iter_mut()
        .zip(raw.to_ne_bytes())
    {
        *slot = MaybeUninit::new(byte);
    }
    control.0[HEADER_BYTES + size_of::<libc::c_int>()] = MaybeUninit::new(0xa5);
    parse_control(&control, HEADER_BYTES + payload).map(drop)
}

pub(in crate::writer_endpoint_handoff) fn parse_rights_then_trailing(
    descriptor: OwnedFd,
) -> io::Result<()> {
    parse_rights_fixture(descriptor, &[], &[], 1)
}

pub(in crate::writer_endpoint_handoff) fn send_with_descriptors(
    socket: BorrowedFd<'_>,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> io::Result<usize> {
    let maximum = usize::try_from(XNU_UIPC_MAX_CMSG_FD).map_err(|_| invalid_record())?;
    if descriptors.is_empty() || descriptors.len() > maximum {
        return Err(invalid_record());
    }
    let payload = descriptors.len() * size_of::<libc::c_int>();
    let mut control = AlignedControl([MaybeUninit::new(0); CONTROL_BYTES]);
    write_header(&mut control, 0, libc::SOL_SOCKET, libc::SCM_RIGHTS, payload);
    for (index, descriptor) in descriptors.iter().enumerate() {
        let start = HEADER_BYTES + index * size_of::<libc::c_int>();
        for (slot, byte) in control.0[start..start + size_of::<libc::c_int>()]
            .iter_mut()
            .zip(descriptor.as_raw_fd().to_ne_bytes())
        {
            *slot = MaybeUninit::new(byte);
        }
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe {
        // SAFETY: zero is a valid base for the send-only msghdr fields filled below.
        std::mem::zeroed()
    };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = align_4(HEADER_BYTES + payload)
        .try_into()
        .map_err(|_| invalid_record())?;
    let sent = unsafe {
        // SAFETY: both buffers are live for the call, the control header and
        // payload are fully initialized, and every borrowed fd remains owned.
        libc::sendmsg(socket.as_raw_fd(), &raw const message, 0)
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(sent).map_err(io::Error::other)
    }
}

fn parse_fixture(descriptor: OwnedFd, unknown_first: bool) -> io::Result<()> {
    let mut control = AlignedControl([MaybeUninit::new(0); 64]);
    let first = if unknown_first {
        write_header(&mut control, 0, 0x7fff, 0x7fff, 4);
        16
    } else {
        0
    };
    write_header(&mut control, first, libc::SOL_SOCKET, libc::SCM_RIGHTS, 4);
    let raw = descriptor.into_raw_fd();
    for (slot, byte) in control.0[first + HEADER_BYTES..first + HEADER_BYTES + 4]
        .iter_mut()
        .zip(raw.to_ne_bytes())
    {
        *slot = MaybeUninit::new(byte);
    }
    let length = if unknown_first {
        first + 16
    } else {
        write_header_length(
            &mut control,
            16,
            libc::SOL_SOCKET,
            libc::SCM_RIGHTS,
            HEADER_BYTES - 1,
        );
        16 + HEADER_BYTES
    };
    parse_control(&control, length).map(drop)
}

fn parse_rights_fixture(
    descriptor: OwnedFd,
    prefix: &[libc::c_int],
    duplicate_indexes: &[usize],
    trailing: usize,
) -> io::Result<()> {
    let raw = descriptor.into_raw_fd();
    let mut values = prefix.to_vec();
    values.push(raw);
    for index in duplicate_indexes {
        values.push(values[*index]);
    }
    let payload = values.len() * size_of::<libc::c_int>();
    let mut control = AlignedControl([MaybeUninit::new(0); 64]);
    write_header(&mut control, 0, libc::SOL_SOCKET, libc::SCM_RIGHTS, payload);
    for (index, value) in values.into_iter().enumerate() {
        let start = HEADER_BYTES + index * size_of::<libc::c_int>();
        for (slot, byte) in control.0[start..start + size_of::<libc::c_int>()]
            .iter_mut()
            .zip(value.to_ne_bytes())
        {
            *slot = MaybeUninit::new(byte);
        }
    }
    let length = HEADER_BYTES + payload + trailing;
    if trailing != 0 {
        control.0[length - 1] = MaybeUninit::new(0xa5);
    }
    parse_control(&control, length).map(drop)
}

fn write_header<const N: usize>(
    control: &mut AlignedControl<N>,
    offset: usize,
    level: libc::c_int,
    kind: libc::c_int,
    payload: usize,
) {
    write_header_length(control, offset, level, kind, HEADER_BYTES + payload);
}

fn write_header_length<const N: usize>(
    control: &mut AlignedControl<N>,
    offset: usize,
    level: libc::c_int,
    kind: libc::c_int,
    message_len: usize,
) {
    assert!(offset <= N && N - offset >= size_of::<libc::cmsghdr>());
    let header = libc::cmsghdr {
        cmsg_len: message_len.try_into().expect("fixture cmsg length fits"),
        cmsg_level: level,
        cmsg_type: kind,
    };
    unsafe {
        // SAFETY: the assertion above bounds a complete header at this offset;
        // unaligned write matches the production parser's unaligned read.
        std::ptr::write_unaligned(control.0.as_mut_ptr().add(offset).cast(), header);
    }
}
