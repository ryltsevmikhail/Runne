use super::validation::{self, CONTROL_MAX, Expected, Observation, Stat};
use super::{Backend, Observed, Result, emit_to, inventory, refuse};
use runne_platform::process_managed_area::LinuxManagedArea;
use rustix::fs::{
    AtFlags, CWD, Mode, OFlags, ResolveFlags, fstat, fstatfs, openat, openat2, statat,
};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub(super) struct Native {
    pub area: LinuxManagedArea,
    pub expected: Expected,
}
pub(super) struct Held {
    h: File,
    a: File,
    path: PathBuf,
    observation: Observation,
}
impl Observed for Held {
    fn observation(&self) -> &Observation {
        &self.observation
    }
}
fn flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}
fn open_h(path: &std::path::Path) -> Result<File> {
    let raw = path.as_os_str().as_bytes();
    if raw.len() > 4096
        || !raw.starts_with(b"/")
        || raw[1..]
            .split(|b| *b == b'/')
            .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(refuse());
    }
    let fd = openat2(
        CWD,
        path,
        flags() | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| refuse())?;
    Ok(File::from(fd))
}
fn open_a(h: &File, name: &str) -> Result<File> {
    Ok(File::from(
        openat(h, name, flags() | OFlags::DIRECTORY, Mode::empty()).map_err(|_| refuse())?,
    ))
}
fn stat(fd: &File) -> Result<Stat> {
    let s = fstat(fd).map_err(|_| refuse())?;
    if s.st_mode & libc::S_IFMT != libc::S_IFDIR
        || fstatfs(fd).map_err(|_| refuse())?.f_type != 0x6367_7270
    {
        return Err(refuse());
    }
    Ok(Stat {
        dev: s.st_dev,
        ino: s.st_ino,
        uid: s.st_uid,
        gid: s.st_gid,
    })
}
// cap+1 leaves room to distinguish a real EOF from reaching the read limit.
pub(super) fn bounded(file: impl Read, cap: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((cap + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(refuse());
    }
    Ok(bytes)
}
fn control(a: &File, name: &str) -> Result<Vec<u8>> {
    let fd = File::from(openat(a, name, flags(), Mode::empty()).map_err(|_| refuse())?);
    let s = fstat(&fd).map_err(|_| refuse())?;
    if s.st_mode & libc::S_IFMT != libc::S_IFREG
        || fstatfs(&fd).map_err(|_| refuse())?.f_type != 0x6367_7270
    {
        return Err(refuse());
    }
    bounded(fd, CONTROL_MAX)
}
fn boot() -> Result<[u8; 16]> {
    let fd = openat2(
        CWD,
        "/proc/sys/kernel/random/boot_id",
        flags(),
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| refuse())?;
    let raw = bounded(File::from(fd), 37)?;
    if raw.len() != 37 || raw[36] != b'\n' {
        return Err(refuse());
    }
    let mut digits = Vec::with_capacity(32);
    for (i, b) in raw[..36].iter().copied().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if b != b'-' {
                return Err(refuse());
            }
        } else {
            digits.push(match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => return Err(refuse()),
            });
        }
    }
    let mut id = [0; 16];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        id[i] = pair[0] * 16 + pair[1];
    }
    Ok(id)
}
impl Backend for Native {
    type Held = Held;
    fn expected(&self) -> &Expected {
        &self.expected
    }
    fn capture(&mut self) -> Result<Held> {
        let path = super::super::scope().ok_or_else(refuse)?;
        let h = open_h(&path)?;
        let name = format!("runne-{}", super::hex(&self.expected.binding));
        let a = open_a(&h, &name)?;
        let mut observation = Observation {
            boot: boot()?,
            h: stat(&h)?,
            a: stat(&a)?,
            name,
            procs: None,
            procs_eof: false,
            events: Vec::new(),
            events_eof: false,
            entries: Vec::new(),
            inventory_eof: false,
            inventory_bytes: 0,
        };
        validation::identity(&self.expected, &observation)?;
        // A newly opened directory has a fresh cursor. No /proc/fd path or dup cursor.
        let (entries, bytes) = inventory::capture(&a)?;
        observation.entries = entries;
        observation.inventory_bytes = bytes;
        observation.inventory_eof = true;
        observation.procs = Some(control(&a, "cgroup.procs")?);
        observation.procs_eof = true;
        observation.events = control(&a, "cgroup.events")?;
        observation.events_eof = true;
        Ok(Held {
            h,
            a,
            path,
            observation,
        })
    }
    fn emit(&mut self, held: &Held) -> Result<()> {
        emit_to(
            &mut std::io::stderr().lock(),
            &self.expected,
            &held.observation,
        )
    }
    fn revalidate(&mut self, held: &Held) -> Result<()> {
        let h = open_h(&held.path)?;
        let a = open_a(&h, &held.observation.name)?;
        let mut fresh = held.observation.clone();
        fresh.boot = boot()?;
        fresh.h = stat(&held.h)?;
        fresh.a = stat(&held.a)?;
        validation::identity(&self.expected, &fresh)?;
        if stat(&h)? != fresh.h || stat(&a)? != fresh.a {
            return Err(refuse());
        }
        // Check the A name relative to the original held H as well as reopened H.
        let named = statat(
            &held.h,
            held.observation.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| refuse())?;
        if named.st_mode & libc::S_IFMT != libc::S_IFDIR
            || named.st_dev != fresh.a.dev
            || named.st_ino != fresh.a.ino
            || named.st_uid != fresh.a.uid
            || named.st_gid != fresh.a.gid
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn remove(self, held: Held) -> Result<()> {
        // Keep both genuine observation descriptors alive through the unchanged unlink API.
        let result = self.area.remove_empty().map_err(|_| refuse());
        drop(held);
        result
    }
}
