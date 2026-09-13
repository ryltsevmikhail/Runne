use std::fs::File;
use std::os::fd::AsFd as _;
use std::path::{Component, Path, PathBuf};

use nix::dir::Dir;
use rustix::fs::{Mode, OFlags, fchmod, fstat, mkdirat, open, openat};

#[path = "fs/journal.rs"]
mod journal;
use journal::{
    JOURNALS, RetainedJournal, copy_journal, select_latest, validate_destination_entries,
};

const BASE: &str = "qualification-runs";
const UPDATES: &str = "updates";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Identity {
    device: i32,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    size: u64,
}

pub(super) struct RunRootState {
    source_parent: RetainedDirectory,
    source_profile: RetainedDirectory,
    source_updates: RetainedDirectory,
    base: RetainedDirectory,
    root: RetainedDirectory,
    destination_updates: RetainedDirectory,
    source_path: PathBuf,
    parent_path: PathBuf,
    root_path: PathBuf,
    journals: [RetainedJournal; 3],
}

struct RetainedDirectory {
    file: File,
    identity: Identity,
    private: bool,
}

impl RunRootState {
    pub(super) fn create(source_profile: &Path, directory_name: &str) -> Option<Self> {
        valid_directory_name(directory_name)?;
        let source_path = source_profile.to_path_buf();
        let parent_path = source_profile.parent()?.to_path_buf();
        let source_profile = RetainedDirectory::open_source(&source_path)?;
        let source_updates = RetainedDirectory::open_at_source(&source_profile.file, UPDATES)?;
        let parent = RetainedDirectory::open_source(&parent_path)?;
        let base = RetainedDirectory::open_or_create_private(&parent.file, BASE)?;
        mkdirat(&base.file, directory_name, Mode::from_raw_mode(0o700)).ok()?;
        let root = RetainedDirectory::open_at_private(&base.file, directory_name)?;
        mkdirat(&root.file, UPDATES, Mode::from_raw_mode(0o700)).ok()?;
        let base = base.refresh()?;
        let root = root.refresh()?;
        let destination_updates = RetainedDirectory::open_at_private(&root.file, UPDATES)?;
        validate_root_entries(&root.file)?;
        let selected = select_latest(&source_updates.file)?;
        let journals = [
            copy_journal(
                &source_updates.file,
                &destination_updates.file,
                &selected[0],
                JOURNALS[0],
            )?,
            copy_journal(
                &source_updates.file,
                &destination_updates.file,
                &selected[1],
                JOURNALS[1],
            )?,
            copy_journal(
                &source_updates.file,
                &destination_updates.file,
                &selected[2],
                JOURNALS[2],
            )?,
        ];
        destination_updates.file.sync_all().ok()?;
        root.file.sync_all().ok()?;
        base.file.sync_all().ok()?;
        parent.file.sync_all().ok()?;
        let destination_updates = destination_updates.refresh()?;
        let root_path = parent_path.join(BASE).join(directory_name);
        let source_parent = parent.refresh()?;
        source_parent.matches_path(&parent_path)?;
        Some(Self {
            source_parent,
            source_profile,
            source_updates,
            base,
            root,
            destination_updates,
            source_path,
            parent_path,
            root_path,
            journals,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.root_path
    }

    pub(super) fn revalidate(&self) -> Option<()> {
        self.source_parent.matches_path(&self.parent_path)?;
        self.source_profile.matches_path(&self.source_path)?;
        self.source_updates
            .matches_at(&self.source_profile.file, UPDATES)?;
        let parent = RetainedDirectory::open_source(&self.parent_path)?;
        self.base.matches_at(&parent.file, BASE)?;
        self.root
            .matches_at(&self.base.file, self.directory_name()?)?;
        validate_root_entries(&self.root.file)?;
        self.destination_updates
            .matches_at(&self.root.file, UPDATES)?;
        let selected = select_latest(&self.source_updates.file)?;
        selected
            .iter()
            .zip(&self.journals)
            .all(|(name, journal)| name == journal.name())
            .then_some(())?;
        for journal in &self.journals {
            journal.revalidate_source(&self.source_updates.file)?;
        }
        validate_destination_entries(&self.destination_updates.file, &self.journals)
    }

    fn directory_name(&self) -> Option<&str> {
        self.root_path.file_name()?.to_str()
    }
}

impl RetainedDirectory {
    fn refresh(mut self) -> Option<Self> {
        let fresh = inspect_directory(&self.file, self.private)?;
        (fresh.device == self.identity.device
            && fresh.inode == self.identity.inode
            && fresh.uid == self.identity.uid
            && fresh.mode == self.identity.mode)
            .then_some(())?;
        self.identity = fresh;
        Some(self)
    }
    fn open_source(path: &Path) -> Option<Self> {
        Self::source(open_absolute_directory(path)?)
    }
    fn open_at_source(parent: &File, name: &str) -> Option<Self> {
        Self::source(open_directory_at(parent, name)?)
    }
    fn open_at_private(parent: &File, name: &str) -> Option<Self> {
        Self::private(open_directory_at(parent, name)?)
    }
    fn open_or_create_private(parent: &File, name: &str) -> Option<Self> {
        if let Some(existing) = open_directory_at(parent, name) {
            return Self::private(existing);
        }
        mkdirat(parent, name, Mode::from_raw_mode(0o700)).ok()?;
        let file = open_directory_at(parent, name)?;
        fchmod(&file, Mode::from_raw_mode(0o700)).ok()?;
        Self::private(file)
    }
    fn source(file: File) -> Option<Self> {
        Some(Self {
            identity: inspect_directory(&file, false)?,
            file,
            private: false,
        })
    }
    fn private(file: File) -> Option<Self> {
        Some(Self {
            identity: inspect_directory(&file, true)?,
            file,
            private: true,
        })
    }
    fn matches_path(&self, path: &Path) -> Option<()> {
        self.matches(&open_absolute_directory(path)?)
    }
    fn matches_at(&self, parent: &File, name: &str) -> Option<()> {
        self.matches(&open_directory_at(parent, name)?)
    }
    fn matches(&self, file: &File) -> Option<()> {
        (inspect_directory(file, self.private)? == self.identity).then_some(())
    }
}

fn open_absolute_directory(path: &Path) -> Option<File> {
    path.is_absolute().then_some(())?;
    let mut current = File::from(open("/", directory_flags(), Mode::empty()).ok()?);
    for component in path.components() {
        if matches!(component, Component::RootDir) {
            continue;
        }
        let Component::Normal(name) = component else {
            return None;
        };
        current = open_directory_at(&current, name)?;
    }
    Some(current)
}

fn open_directory_at(parent: &File, name: impl rustix::path::Arg) -> Option<File> {
    Some(File::from(
        openat(parent, name, directory_flags(), Mode::empty()).ok()?,
    ))
}

fn inspect_directory(file: &File, private: bool) -> Option<Identity> {
    runne_macos_file_security::require_no_extended_acl(file.as_fd()).ok()?;
    let identity = identity(file)?;
    (identity.mode & 0o170_000 == 0o040_000
        && identity.uid == rustix::process::geteuid().as_raw()
        && if private {
            identity.mode & 0o777 == 0o700
        } else {
            identity.mode & 0o022 == 0
        })
    .then_some(identity)
}

fn validate_root_entries(root: &File) -> Option<()> {
    let clone = root.try_clone().ok()?;
    let mut entries = Dir::from_fd(clone.into()).ok()?;
    let mut updates = false;
    for entry in entries.iter() {
        let entry = entry.ok()?;
        let name = entry.file_name().to_str().ok()?;
        if name == "." || name == ".." {
            continue;
        }
        (!updates && name == UPDATES).then_some(())?;
        updates = true;
    }
    updates.then_some(())
}

pub(super) fn identity(file: &File) -> Option<Identity> {
    let stat = fstat(file).ok()?;
    Some(Identity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: u32::from(stat.st_mode),
        links: u64::from(stat.st_nlink),
        size: stat.st_size.try_into().ok()?,
    })
}

fn valid_directory_name(value: &str) -> Option<()> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then_some(())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
