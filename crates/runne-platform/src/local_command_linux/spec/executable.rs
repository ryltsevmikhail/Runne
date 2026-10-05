use super::{LinuxCommandError, LinuxCommandExecutable};
use std::fs::File;

impl LinuxCommandExecutable<'_> {
    pub(in crate::local_command_linux) fn file(&self) -> &File {
        match self {
            Self::HeldFile(file) => file,
            Self::SealedSnapshot(snapshot) => snapshot.file(),
        }
    }

    pub(in crate::local_command_linux) fn is_sealed_snapshot(&self) -> bool {
        matches!(self, Self::SealedSnapshot(_))
    }

    pub(in crate::local_command_linux) fn validate_provenance(
        &self,
    ) -> Result<(), LinuxCommandError> {
        if let Self::SealedSnapshot(snapshot) = self {
            snapshot.validate_seals()?;
        }
        Ok(())
    }
}
