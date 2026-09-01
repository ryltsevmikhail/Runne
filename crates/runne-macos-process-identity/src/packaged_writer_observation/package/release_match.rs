use std::path::PathBuf;

use super::{PackageRole, PackagedWriterArtifacts};
use crate::MacOsPackagedWriterObservationError;

impl PackagedWriterArtifacts {
    pub(crate) const fn desktop_digest(&self) -> &[u8; 32] {
        self.desktop.digest()
    }

    pub(crate) const fn writer_digest(&self) -> &[u8; 32] {
        self.writer.digest()
    }

    pub(crate) const fn daemon_digest(&self) -> &[u8; 32] {
        self.daemon.digest()
    }

    pub(crate) const fn contract_digest(&self) -> &[u8; 32] {
        self.contract.digest()
    }

    pub(crate) fn desktop_main_executable(
        &self,
    ) -> Result<PathBuf, MacOsPackagedWriterObservationError> {
        let executable = self.application_path.join("Contents/MacOS/runne-desktop");
        self.require_main_locator(&executable, PackageRole::Desktop)?;
        Ok(executable)
    }
}
