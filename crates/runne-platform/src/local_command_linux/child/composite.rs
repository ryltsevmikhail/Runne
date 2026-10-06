//! Prepares reserved control-plane trees for broad same-user process scopes.
use super::super::LinuxCommandError;
use rustix::fs::{Mode, OFlags, ResolveFlags, fstat, openat2};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

#[path = "composite/devices.rs"]
mod devices;
#[path = "composite/namespace.rs"]
mod namespace;
#[path = "composite/policy_digest.rs"]
mod policy_digest;
pub(in crate::local_command_linux) use namespace::{enter_child, map_child_identity};

const MAX_TREE_NODES: usize = 4096;
const MAX_TREE_DEPTH: usize = 64;

pub(super) struct ProtectedTree {
    root: File,
    members: Vec<File>,
    regular_files: Vec<usize>,
}

pub(in crate::local_command_linux) struct PreparedComposite {
    trees: Vec<ProtectedTree>,
    devices: devices::SafeDevices,
}

type ChildDescriptors = (
    Vec<OwnedFd>,
    Vec<CString>,
    Vec<usize>,
    Vec<CString>,
    Vec<CString>,
);

impl PreparedComposite {
    pub(in crate::local_command_linux) fn preflight_namespaces() -> Result<(), LinuxCommandError> {
        namespace::preflight_namespaces()
    }

    pub(in crate::local_command_linux) fn admit(
        roots: &[&File],
    ) -> Result<Self, LinuxCommandError> {
        validate_host_shape(roots)?;
        namespace::validate_host_mounts()?;
        let mut trees = Vec::with_capacity(roots.len());
        for root in roots {
            trees.push(ProtectedTree::scan(root)?);
        }
        Ok(Self {
            trees,
            devices: devices::SafeDevices::open()?,
        })
    }

    pub(in crate::local_command_linux) fn validate(
        roots: &[&File],
        workspace: &File,
        cwd: &File,
    ) -> Result<Self, LinuxCommandError> {
        namespace::validate_host_mounts()?;
        validate_roots_disjoint(roots, workspace, cwd)?;
        Self::admit(roots)
    }

    pub(in crate::local_command_linux) fn protected_policy_digest(
        roots: &[&File],
    ) -> Result<runne_application::permission_modes::IntegrityDigest, LinuxCommandError> {
        validate_host_shape(roots)?;
        policy_digest::digest(roots)
    }

    pub(in crate::local_command_linux) fn roots(&self) -> Vec<&File> {
        self.trees.iter().map(|tree| &tree.root).collect()
    }

    pub(in crate::local_command_linux) fn validate_for(
        &self,
        workspace: &File,
        cwd: &File,
    ) -> Result<Self, LinuxCommandError> {
        Self::validate(&self.roots(), workspace, cwd)
    }

    pub(in crate::local_command_linux) fn validate_workspace_bound(
        &self,
        workspace: &File,
        cwd: &File,
    ) -> Result<(), LinuxCommandError> {
        for tree in &self.trees {
            if is_ancestor(&tree.root, workspace)?
                || is_ancestor(workspace, &tree.root)?
                || is_ancestor(&tree.root, cwd)?
                || is_ancestor(cwd, &tree.root)?
            {
                return Err(LinuxCommandError::CompositePolicyUnenforceable);
            }
        }
        Ok(())
    }

    pub(in crate::local_command_linux) fn child_descriptors(
        &self,
    ) -> Result<ChildDescriptors, LinuxCommandError> {
        let mut descriptors = Vec::new();
        let mut targets = Vec::with_capacity(self.trees.len());
        let mut regular = Vec::new();
        for tree in &self.trees {
            let root = duplicate(tree.root.as_raw_fd())?;
            let root_number = root.as_raw_fd();
            descriptors.push(root);
            let target_path = std::fs::read_link(format!("/proc/self/fd/{root_number}"))
                .map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
            targets.push(
                CString::new(target_path.as_os_str().as_bytes())
                    .map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?,
            );
            for (member_index, member) in tree.members.iter().enumerate() {
                let child_index = descriptors.len();
                descriptors.push(duplicate(member.as_raw_fd())?);
                if tree.regular_files.contains(&member_index) {
                    regular.push(child_index);
                }
            }
        }
        let (device_targets, device_source_paths) =
            self.devices.child_descriptors(&mut descriptors)?;
        Ok((
            descriptors,
            targets,
            regular,
            device_targets,
            device_source_paths,
        ))
    }
}

fn validate_roots_disjoint(
    roots: &[&File],
    workspace: &File,
    cwd: &File,
) -> Result<(), LinuxCommandError> {
    for (index, root) in roots.iter().enumerate() {
        if is_ancestor(root, workspace)? || is_ancestor(root, cwd)? {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        for other in roots.iter().skip(index + 1) {
            if overlaps(root, other)? {
                return Err(LinuxCommandError::CompositePolicyUnenforceable);
            }
        }
    }
    Ok(())
}

fn overlaps(left: &File, right: &File) -> Result<bool, LinuxCommandError> {
    Ok(is_ancestor(left, right)? || is_ancestor(right, left)?)
}

fn validate_host_shape(roots: &[&File]) -> Result<(), LinuxCommandError> {
    if roots.is_empty() || roots.len() > 64 {
        return Err(LinuxCommandError::CompositePolicyUnenforceable);
    }
    for (index, root) in roots.iter().enumerate() {
        let stat = fstat(*root).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        for other in roots.iter().skip(index + 1) {
            let candidate =
                fstat(*other).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
            if (candidate.st_dev == stat.st_dev && candidate.st_ino == stat.st_ino)
                || is_ancestor(root, other)?
                || is_ancestor(other, root)?
            {
                return Err(LinuxCommandError::CompositePolicyUnenforceable);
            }
        }
    }
    Ok(())
}

fn is_ancestor(ancestor: &File, descendant: &File) -> Result<bool, LinuxCommandError> {
    let base = fstat(ancestor).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
    let mut current = descendant
        .try_clone()
        .map_err(|_| LinuxCommandError::Unavailable)?;
    for _ in 0..256 {
        let stat = fstat(&current).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        if stat.st_dev == base.st_dev && stat.st_ino == base.st_ino {
            return Ok(true);
        }
        let parent = unsafe {
            libc::openat(
                current.as_raw_fd(),
                c"..".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if parent < 0 {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        let next = unsafe { File::from_raw_fd(parent) };
        let parent_stat =
            fstat(&next).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        if parent_stat.st_dev == stat.st_dev && parent_stat.st_ino == stat.st_ino {
            return Ok(false);
        }
        current = next;
    }
    Err(LinuxCommandError::CompositePolicyUnenforceable)
}

impl ProtectedTree {
    fn scan(root: &File) -> Result<Self, LinuxCommandError> {
        let stat = fstat(root).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        let mut tree = Self {
            root: root
                .try_clone()
                .map_err(|_| LinuxCommandError::Unavailable)?,
            members: Vec::new(),
            regular_files: Vec::new(),
        };
        tree.members.push(
            root.try_clone()
                .map_err(|_| LinuxCommandError::Unavailable)?,
        );
        scan_directory(root, stat.st_dev, 0, &mut tree)?;
        Ok(tree)
    }
}

fn scan_directory(
    directory: &File,
    root_device: u64,
    depth: usize,
    tree: &mut ProtectedTree,
) -> Result<(), LinuxCommandError> {
    if depth > MAX_TREE_DEPTH || tree.members.len() > MAX_TREE_NODES {
        return Err(LinuxCommandError::CompositePolicyUnenforceable);
    }
    let path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries =
        std::fs::read_dir(path).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
    for entry in entries {
        let entry = entry.map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        let name = CString::new(entry.file_name().as_bytes())
            .map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        let fd = openat2(
            directory,
            name.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        let member = File::from(fd);
        let stat = fstat(&member).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        if stat.st_dev != root_device {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                tree.members.push(
                    member
                        .try_clone()
                        .map_err(|_| LinuxCommandError::Unavailable)?,
                );
                scan_directory(&member, root_device, depth + 1, tree)?;
            }
            libc::S_IFREG if stat.st_nlink == 1 => {
                tree.regular_files.push(tree.members.len());
                tree.members.push(member);
            }
            _ => return Err(LinuxCommandError::CompositePolicyUnenforceable),
        }
        if tree.members.len() > MAX_TREE_NODES {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
    }
    Ok(())
}

fn duplicate(fd: i32) -> Result<OwnedFd, LinuxCommandError> {
    let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if result < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}
