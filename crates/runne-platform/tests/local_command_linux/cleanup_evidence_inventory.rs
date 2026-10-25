use super::validation::{ENTRY_MAX, Entry, INVENTORY_MAX};
use super::{Result, refuse};
use rustix::fs::{AtFlags, statat};
use std::fs::File;
use std::os::fd::AsRawFd;

// Decode Linux getdents64 records without casting unaligned byte storage.
// Actual capture and pure malformed/cap regressions share this parser.
pub(super) fn append(raw: &[u8], entries: &mut Vec<Entry>, total: &mut usize) -> Result<()> {
    *total = total.checked_add(raw.len()).ok_or_else(refuse)?;
    if *total > INVENTORY_MAX {
        return Err(refuse());
    }
    let mut offset = 0;
    while offset < raw.len() {
        let row = &raw[offset..];
        if row.len() < 20 || entries.len() == ENTRY_MAX {
            return Err(refuse());
        }
        let len = u16::from_ne_bytes([row[16], row[17]]) as usize;
        if len < 24 || len % 8 != 0 || len > row.len() {
            return Err(refuse());
        }
        let ino = u64::from_ne_bytes(row[..8].try_into().map_err(|_| refuse())?);
        let name_end = row[19..len]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(refuse)?;
        let name = &row[19..19 + name_end];
        if name.is_empty() || name.len() > 255 || name.contains(&b'/') || ino == 0 {
            return Err(refuse());
        }
        let name = std::str::from_utf8(name).map_err(|_| refuse())?.to_owned();
        entries.push(Entry {
            name,
            kind: row[18],
            ino,
        });
        offset += len;
    }
    Ok(())
}
pub(super) fn capture(a: &File) -> Result<(Vec<Entry>, usize)> {
    let mut entries = Vec::new();
    let mut total = 0;
    loop {
        let mut buffer = [0u8; 4096];
        // SAFETY: fd is held; the kernel may write only the provided buffer length.
        let got = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                a.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if got < 0 || got as usize > buffer.len() {
            return Err(refuse());
        }
        if got == 0 {
            break;
        } // Real EOF, never inferred from a short nonzero batch.
        append(&buffer[..got as usize], &mut entries, &mut total)?;
    }
    for entry in &entries {
        let s = statat(a, entry.name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(|_| refuse())?;
        let mode = match entry.kind {
            libc::DT_DIR => libc::S_IFDIR,
            libc::DT_REG => libc::S_IFREG,
            _ => return Err(refuse()),
        };
        if s.st_ino != entry.ino || s.st_mode & libc::S_IFMT != mode {
            return Err(refuse());
        }
    }
    Ok((entries, total))
}
