use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsFd as _;

use nix::dir::Dir;
use rustix::fs::{Mode, OFlags, fchmod, openat};
use sha2::{Digest as _, Sha256};

use super::{Identity, identity};

const SCAN_LIMIT: usize = 128;
pub(super) const JOURNALS: [JournalSpec; 3] = [
    JournalSpec::new("install-state.json", 16 * 1024),
    JournalSpec::new("trust-state.json", 4 * 1024),
    JournalSpec::new("installed-metadata.json", 1024 * 1024),
];

#[derive(Clone, Copy)]
pub(super) struct JournalSpec {
    base: &'static str,
    maximum: u64,
}
impl JournalSpec {
    const fn new(base: &'static str, maximum: u64) -> Self {
        Self { base, maximum }
    }
}

pub(super) struct RetainedJournal {
    source_name: String,
    source: Identity,
    destination: Identity,
    digest: [u8; 32],
    maximum: u64,
}

impl RetainedJournal {
    pub(super) fn name(&self) -> &str {
        &self.source_name
    }

    pub(super) fn revalidate_source(&self, directory: &File) -> Option<()> {
        let file = open_checked_file(directory, self.name(), self.maximum)?;
        let (bytes, digest) = read_checked(&file, self.maximum)?;
        (digest == self.digest
            && inspect_regular(&file, self.maximum)? == self.source
            && bytes.len() as u64 == self.source.size)
            .then_some(())
    }
}

pub(super) fn copy_journal(
    source: &File,
    destination: &File,
    name: &str,
    spec: JournalSpec,
) -> Option<RetainedJournal> {
    let source_file = open_checked_file(source, name, spec.maximum)?;
    let source_identity = inspect_regular(&source_file, spec.maximum)?;
    let (bytes, digest) = read_checked(&source_file, spec.maximum)?;
    let mut output = File::from(
        openat(
            destination,
            name,
            create_flags(),
            Mode::from_raw_mode(0o600),
        )
        .ok()?,
    );
    fchmod(&output, Mode::from_raw_mode(0o600)).ok()?;
    output.write_all(&bytes).ok()?;
    output.sync_all().ok()?;
    let destination_file = open_checked_file(destination, name, spec.maximum)?;
    let destination = inspect_regular(&destination_file, spec.maximum)?;
    let (_, output_digest) = read_checked(&destination_file, spec.maximum)?;
    (output_digest == digest).then_some(RetainedJournal {
        source_name: name.into(),
        source: source_identity,
        destination,
        digest,
        maximum: spec.maximum,
    })
}

pub(super) fn select_latest(directory: &File) -> Option<[String; 3]> {
    let clone = directory.try_clone().ok()?;
    let mut directory = Dir::from_fd(clone.into()).ok()?;
    let mut selected: [Option<(u64, String)>; 3] = std::array::from_fn(|_| None);
    let mut count = 0_usize;
    for entry in directory.iter() {
        let name = entry.ok()?.file_name().to_str().ok()?.to_owned();
        if name == "." || name == ".." {
            continue;
        }
        count = count.checked_add(1)?;
        (count <= SCAN_LIMIT).then_some(())?;
        for (index, spec) in JOURNALS.iter().enumerate() {
            let Some(rest) = name.strip_prefix(spec.base) else {
                continue;
            };
            let sequence = sequence(rest)?;
            if selected[index]
                .as_ref()
                .is_none_or(|(prior, _)| sequence > *prior)
            {
                selected[index] = Some((sequence, name.clone()));
            }
        }
    }
    Some([
        selected[0].take()?.1,
        selected[1].take()?.1,
        selected[2].take()?.1,
    ])
}

pub(super) fn validate_destination_entries(
    directory: &File,
    journals: &[RetainedJournal; 3],
) -> Option<()> {
    let clone = directory.try_clone().ok()?;
    let mut scan = Dir::from_fd(clone.into()).ok()?;
    let mut count = 0_usize;
    for entry in scan.iter() {
        let entry = entry.ok()?;
        let name = entry.file_name().to_str().ok()?;
        if name == "." || name == ".." {
            continue;
        }
        count = count.checked_add(1)?;
        (count <= 3 && journals.iter().any(|journal| journal.name() == name)).then_some(())?;
    }
    (count == 3).then_some(())?;
    for journal in journals {
        let source = open_checked_file(directory, journal.name(), journal.maximum)?;
        let (bytes, source_digest) = read_checked(&source, journal.maximum)?;
        (source_digest == journal.digest
            && inspect_regular(&source, journal.maximum)? == journal.destination
            && bytes.len() as u64 == journal.source.size)
            .then_some(())?;
    }
    Some(())
}

fn sequence(rest: &str) -> Option<u64> {
    let digits = rest.strip_prefix('.')?.strip_suffix(".json")?;
    let value = digits.parse::<u64>().ok()?;
    (value > 0 && value.to_string() == digits).then_some(value)
}

fn open_checked_file(parent: impl std::os::fd::AsFd, name: &str, maximum: u64) -> Option<File> {
    let file = File::from(openat(parent, name, read_flags(), Mode::empty()).ok()?);
    inspect_regular(&file, maximum)?;
    Some(file)
}

fn inspect_regular(file: &File, maximum: u64) -> Option<Identity> {
    runne_macos_file_security::require_no_extended_acl(file.as_fd()).ok()?;
    let value = identity(file)?;
    (value.mode & 0o170_000 == 0o100_000
        && value.uid == rustix::process::geteuid().as_raw()
        && value.mode & 0o022 == 0
        && value.links == 1
        && value.size <= maximum)
        .then_some(value)
}

fn read_checked(file: &File, maximum: u64) -> Option<(Vec<u8>, [u8; 32])> {
    let before = inspect_regular(file, maximum)?;
    let mut reader = file.try_clone().ok()?;
    reader.seek(SeekFrom::Start(0)).ok()?;
    let mut bytes = vec![0_u8; usize::try_from(before.size).ok()?];
    reader.read_exact(&mut bytes).ok()?;
    let mut extra = [0_u8; 1];
    (reader.read(&mut extra).ok()? == 0).then_some(())?;
    (before == inspect_regular(file, maximum)?)
        .then_some((bytes.clone(), Sha256::digest(bytes).into()))
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
fn create_flags() -> OFlags {
    OFlags::WRONLY
        | OFlags::CREATE
        | OFlags::EXCL
        | OFlags::NONBLOCK
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC
}
