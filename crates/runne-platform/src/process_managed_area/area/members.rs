use super::super::ManagedAreaError;
use rustix::fs::{Mode, OFlags, fstatfs, openat};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::Instant;

const MAX_GROUPS: usize = 128;
const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_MEMBERS: usize = 4096;
const MAX_CONTROL_BYTES: u64 = 128 * 1024;

pub(super) fn open_control(
    group: &File,
    name: &str,
    write: bool,
) -> Result<File, ManagedAreaError> {
    let flags = if write {
        OFlags::WRONLY
    } else {
        OFlags::RDONLY
    };
    let fd: OwnedFd = openat(
        group,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ManagedAreaError::Unavailable)?;
    Ok(File::from(fd))
}

pub(super) fn write_control(group: &File, name: &str, value: &str) -> Result<(), ManagedAreaError> {
    open_control(group, name, true)?
        .write_all(value.as_bytes())
        .map_err(|_| ManagedAreaError::Unavailable)
}

fn bounded_text(file: File) -> Result<String, ManagedAreaError> {
    let mut bytes = Vec::new();
    file.take(MAX_CONTROL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ManagedAreaError::Unavailable)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err(ManagedAreaError::Unverified);
    }
    String::from_utf8(bytes).map_err(|_| ManagedAreaError::Unverified)
}

pub(super) fn is_populated(group: &File) -> Result<bool, ManagedAreaError> {
    let text = bounded_text(open_control(group, "cgroup.events", false)?)?;
    let mut value = None;
    let mut frozen_seen = false;
    for line in text.lines() {
        let (key, field) = line.split_once(' ').ok_or(ManagedAreaError::Unverified)?;
        if field != "0" && field != "1" {
            return Err(ManagedAreaError::Unverified);
        }
        match key {
            "populated" if value.is_none() => value = Some(field == "1"),
            "frozen" if !frozen_seen => frozen_seen = true,
            _ => return Err(ManagedAreaError::Unverified),
        }
    }
    value.ok_or(ManagedAreaError::Unverified)
}

pub(super) fn read_pids(group: &File) -> Result<Vec<u32>, ManagedAreaError> {
    let text = bounded_text(open_control(group, "cgroup.procs", false)?)?;
    let mut result = Vec::new();
    for line in text.lines() {
        if result.len() == MAX_MEMBERS {
            return Err(ManagedAreaError::Unverified);
        }
        let pid = line
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or(ManagedAreaError::Unverified)?;
        result.push(pid);
    }
    Ok(result)
}

pub(super) fn process_is_stopped(pid: u32) -> Result<bool, ManagedAreaError> {
    Ok(process_stat(pid)?.is_some_and(|(_, state)| state == "T" || state == "t"))
}

fn process_start_identity(pid: u32) -> Result<Option<String>, ManagedAreaError> {
    Ok(process_stat(pid)?.map(|(start, _)| start))
}

fn process_stat(pid: u32) -> Result<Option<(String, String)>, ManagedAreaError> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ManagedAreaError::Unavailable),
    };
    let tail = stat
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .ok_or(ManagedAreaError::Unverified)?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    let state = fields
        .first()
        .ok_or(ManagedAreaError::Unverified)?
        .to_string();
    let start = fields
        .get(19)
        .ok_or(ManagedAreaError::Unverified)?
        .to_string();
    Ok(Some((start, state)))
}

pub(super) fn signal_current_members(
    root: &File,
    signal: Signal,
    deadline: Instant,
) -> Result<(), ManagedAreaError> {
    let groups = groups(root, deadline)?;
    let mut signalled = 0usize;
    for group in &groups {
        if Instant::now() >= deadline {
            return Ok(());
        }
        for pid in read_pids(group)? {
            if Instant::now() >= deadline || signalled == MAX_MEMBERS {
                return Ok(());
            }
            signal_if_still_member(group, pid, signal)?;
            signalled += 1;
        }
    }
    Ok(())
}

fn signal_if_still_member(group: &File, pid: u32, signal: Signal) -> Result<(), ManagedAreaError> {
    let pid_number = i32::try_from(pid).map_err(|_| ManagedAreaError::Unverified)?;
    let Some(before) = process_start_identity(pid)? else {
        return Ok(());
    };
    let pidfd = match pidfd_open(
        Pid::from_raw(pid_number).ok_or(ManagedAreaError::Unverified)?,
        PidfdFlags::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::SRCH => return Ok(()),
        Err(_) => return Err(ManagedAreaError::Unavailable),
    };
    if process_start_identity(pid)?.as_deref() != Some(before.as_str())
        || !read_pids(group)?.contains(&pid)
    {
        return Ok(());
    }
    match pidfd_send_signal(&pidfd, signal) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
        Err(_) => Err(ManagedAreaError::Unavailable),
    }
}

fn groups(root: &File, deadline: Instant) -> Result<Vec<File>, ManagedAreaError> {
    let mut groups = vec![
        root.try_clone()
            .map_err(|_| ManagedAreaError::Unavailable)?,
    ];
    let mut index = 0;
    let mut entries_seen = 0;
    while index < groups.len() {
        if Instant::now() >= deadline
            || groups.len() > MAX_GROUPS
            || entries_seen >= MAX_DIRECTORY_ENTRIES
        {
            return Ok(groups);
        }
        let path = PathBuf::from(format!("/proc/self/fd/{}", groups[index].as_raw_fd()));
        let entries = std::fs::read_dir(path).map_err(|_| ManagedAreaError::Unavailable)?;
        for entry in entries {
            if Instant::now() >= deadline
                || entries_seen == MAX_DIRECTORY_ENTRIES
                || groups.len() == MAX_GROUPS
            {
                return Ok(groups);
            }
            entries_seen += 1;
            let entry = entry.map_err(|_| ManagedAreaError::Unavailable)?;
            let kind = entry
                .file_type()
                .map_err(|_| ManagedAreaError::Unavailable)?;
            if kind.is_file() {
                continue;
            }
            if kind.is_symlink() || !kind.is_dir() {
                return Err(ManagedAreaError::Unverified);
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ManagedAreaError::Unverified);
            };
            let child = openat(
                &groups[index],
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| ManagedAreaError::Unverified)?;
            if fstatfs(&child)
                .map_err(|_| ManagedAreaError::Unavailable)?
                .f_type
                != 0x6367_7270
            {
                return Err(ManagedAreaError::Unverified);
            }
            groups.push(File::from(child));
        }
        index += 1;
    }
    Ok(groups)
}
