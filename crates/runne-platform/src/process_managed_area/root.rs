use super::{LinuxManagedArea, ManagedAreaBinding, ManagedAreaError, ManagedAreaIdentity};
use rustix::fs::{
    AtFlags, CWD, Mode, OFlags, ResolveFlags, fstat, fstatfs, openat, openat2, unlinkat,
};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

#[path = "root/creation.rs"]
mod creation;

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// Descriptor-held authority for one delegated cgroup-v2 directory.
#[derive(Clone)]
pub struct LinuxManagedAreaRoot {
    directory: Arc<File>,
    device: u64,
    inode: u64,
    boot_id: [u8; 16],
}

impl LinuxManagedAreaRoot {
    /// Opens a cgroup-v2 directory without following any path symlink.
    pub fn open(path: &Path) -> Result<Self, ManagedAreaError> {
        let fd = openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| ManagedAreaError::Unavailable)?;
        Self::from_fd(File::from(fd))
    }

    /// Creates an empty unique child area bound to one TaskRun attempt.
    /// Requires an exclusive root-area writer through creation/publication or rollback.
    /// This contract, also required by removal, is not enforced against same-UID writers.
    pub fn create_area(
        &self,
        binding: ManagedAreaBinding,
    ) -> Result<LinuxManagedArea, ManagedAreaError> {
        creation::create(self, binding)
    }

    /// Reopens an existing area only when root, boot, inode, and binding match.
    pub fn reopen_area(
        &self,
        identity: ManagedAreaIdentity,
        binding: ManagedAreaBinding,
    ) -> Result<LinuxManagedArea, ManagedAreaError> {
        if !identity.matches_binding(binding)
            || identity.boot_id != self.boot_id
            || identity.root_device != self.device
            || identity.root_inode != self.inode
        {
            return Err(ManagedAreaError::Unverified);
        }
        let name = area_name(binding);
        let area_fd =
            open_area(self.directory.as_ref(), &name).map_err(|_| ManagedAreaError::Unverified)?;
        check_cgroup2(&area_fd).map_err(|_| ManagedAreaError::Unverified)?;
        let metadata = fstat(&area_fd).map_err(|_| ManagedAreaError::Unverified)?;
        if metadata.st_dev != identity.area_device || metadata.st_ino != identity.area_inode {
            return Err(ManagedAreaError::Unverified);
        }
        Ok(LinuxManagedArea::new(
            Arc::clone(&self.directory),
            File::from(area_fd),
            name.clone(),
            identity.clone(),
        ))
    }

    /// Observes absence of this exact bound name without changing cgroup state.
    /// This does not prove cancellation, execution history, or recursive emptiness.
    pub fn area_is_absent(&self, identity: &ManagedAreaIdentity) -> Result<bool, ManagedAreaError> {
        if identity.boot_id != self.boot_id
            || identity.root_device != self.device
            || identity.root_inode != self.inode
        {
            return Err(ManagedAreaError::Unverified);
        }
        let name = area_name(identity.binding);
        let area_fd = match openat(
            self.directory.as_ref(),
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(true),
            Err(_) => return Err(ManagedAreaError::Unverified),
        };
        check_cgroup2(&area_fd).map_err(|_| ManagedAreaError::Unverified)?;
        let metadata = fstat(&area_fd).map_err(|_| ManagedAreaError::Unverified)?;
        if metadata.st_dev != identity.area_device || metadata.st_ino != identity.area_inode {
            return Err(ManagedAreaError::Unverified);
        }
        Ok(false)
    }

    /// Removes an exact empty area if it remains after a durable terminal receipt.
    /// Returns `false` only when its deterministic name is already absent.
    /// As with `remove_empty`, this requires one exclusive root-area writer because cgroupfs
    /// offers no atomic compare-and-unlink operation.
    pub fn remove_area_if_present(
        &self,
        identity: ManagedAreaIdentity,
    ) -> Result<bool, ManagedAreaError> {
        if identity.boot_id != self.boot_id
            || identity.root_device != self.device
            || identity.root_inode != self.inode
        {
            return Err(ManagedAreaError::Unverified);
        }
        let name = area_name(identity.binding);
        let area_fd = match openat(
            self.directory.as_ref(),
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
            Err(_) => return Err(ManagedAreaError::Unverified),
        };
        check_cgroup2(&area_fd).map_err(|_| ManagedAreaError::Unverified)?;
        let metadata = fstat(&area_fd).map_err(|_| ManagedAreaError::Unverified)?;
        if metadata.st_dev != identity.area_device || metadata.st_ino != identity.area_inode {
            return Err(ManagedAreaError::Unverified);
        }
        let area = LinuxManagedArea::new(
            Arc::clone(&self.directory),
            File::from(area_fd),
            name.clone(),
            identity.clone(),
        );
        area.require_empty()?;
        let current = openat(
            self.directory.as_ref(),
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ManagedAreaError::Unverified)?;
        let current_stat = fstat(&current).map_err(|_| ManagedAreaError::Unverified)?;
        if current_stat.st_dev != identity.area_device || current_stat.st_ino != identity.area_inode
        {
            return Err(ManagedAreaError::Unverified);
        }
        unlinkat(self.directory.as_ref(), name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| ManagedAreaError::Unverified)?;
        Ok(true)
    }

    fn from_fd(directory: File) -> Result<Self, ManagedAreaError> {
        check_cgroup2(&directory)?;
        let metadata = fstat(&directory).map_err(|_| ManagedAreaError::Unavailable)?;
        let boot_id = read_boot_id()?;
        Ok(Self {
            directory: Arc::new(directory),
            device: metadata.st_dev,
            inode: metadata.st_ino,
            boot_id,
        })
    }
}

fn check_cgroup2(fd: &impl std::os::fd::AsFd) -> Result<(), ManagedAreaError> {
    let stat = fstatfs(fd).map_err(|_| ManagedAreaError::Unavailable)?;
    if stat.f_type != CGROUP2_SUPER_MAGIC {
        return Err(ManagedAreaError::Unavailable);
    }
    Ok(())
}

fn open_area(root: &File, name: &str) -> Result<OwnedFd, ManagedAreaError> {
    openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ManagedAreaError::Unavailable)
}

fn read_boot_id() -> Result<[u8; 16], ManagedAreaError> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| ManagedAreaError::Unavailable)?;
    let mut digits = [0; 32];
    let mut index = 0;
    for byte in raw.bytes().filter(|byte| *byte != b'-' && *byte != b'\n') {
        if index == digits.len() || !byte.is_ascii_hexdigit() {
            return Err(ManagedAreaError::Unverified);
        }
        digits[index] = byte.to_ascii_lowercase();
        index += 1;
    }
    if index != digits.len() {
        return Err(ManagedAreaError::Unverified);
    }
    let mut output = [0; 16];
    for (index, pair) in digits.chunks_exact(2).enumerate() {
        output[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    (output != [0; 16])
        .then_some(output)
        .ok_or(ManagedAreaError::Unverified)
}

fn hex(byte: u8) -> Result<u8, ManagedAreaError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ManagedAreaError::Unverified),
    }
}

pub(super) fn area_name(binding: ManagedAreaBinding) -> String {
    let mut name = String::from("runne-");
    for byte in binding
        .task_run
        .iter()
        .chain(binding.attempt.iter())
        .chain(binding.nonce.iter())
    {
        use std::fmt::Write;
        let _ = write!(name, "{byte:02x}");
    }
    name
}
