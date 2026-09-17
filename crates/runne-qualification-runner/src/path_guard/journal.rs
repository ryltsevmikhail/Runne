use std::fs::File;
use std::os::fd::AsFd as _;

use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{GuardedRoot, require_no_extended_acl, verify_database};
use crate::QualificationReplayLedgerError;

const JOURNAL_NAME: &str = "ledger.sqlite3-journal";

pub struct JournalWitness {
    file: File,
    identity: JournalIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct JournalIdentity {
    device: u64,
    inode: u64,
}

impl GuardedRoot {
    pub fn open_existing_journal(
        &self,
    ) -> Result<Option<JournalWitness>, QualificationReplayLedgerError> {
        match fs::openat(
            &self.fd,
            JOURNAL_NAME,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => {
                verify_database(&fd, self.uid)?;
                let file = File::from(fd);
                Ok(Some(JournalWitness {
                    identity: identity(&file)?,
                    file,
                }))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(_) => Err(QualificationReplayLedgerError),
        }
    }

    pub fn verify_journal_recovered(
        &self,
        journal: Option<JournalWitness>,
    ) -> Result<(), QualificationReplayLedgerError> {
        if let Some(journal) = journal {
            let stat = fs::fstat(&journal.file).map_err(|_| QualificationReplayLedgerError)?;
            if identity(&journal.file)? != journal.identity
                || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != self.uid
                || stat.st_mode & 0o777 != 0o600
                || stat.st_nlink != 0
            {
                return Err(QualificationReplayLedgerError);
            }
        }
        match fs::openat(
            &self.fd,
            JOURNAL_NAME,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) | Err(_) => Err(QualificationReplayLedgerError),
        }
    }
}

#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::useless_conversion,
        reason = "Linux exposes st_dev as u64; retain the checked conversion required by macOS signed st_dev"
    )
)]
fn identity(file: &File) -> Result<JournalIdentity, QualificationReplayLedgerError> {
    require_no_extended_acl(file.as_fd())?;
    let stat = fs::fstat(file).map_err(|_| QualificationReplayLedgerError)?;
    (stat.st_dev != 0 && stat.st_ino != 0)
        .then_some(JournalIdentity {
            device: stat
                .st_dev
                .try_into()
                .map_err(|_| QualificationReplayLedgerError)?,
            inode: stat.st_ino,
        })
        .ok_or(QualificationReplayLedgerError)
}
