use runne_qualification_bootstrap_policy::QualificationBootstrapPolicy;

use crate::{Error, Result, protected_file::ProtectedFile};

const EXECUTABLE_PATH: &str = "/opt/gocode/sourcecraft/bin/runne-qualification-root-service";

/// Constructed only after the installed image matches the running main image.
pub struct AdmittedExecutable(ProtectedFile);

impl AdmittedExecutable {
    pub fn load(policy: &QualificationBootstrapPolicy) -> Result<Self> {
        if std::env::current_exe().map_err(|_| Error)? != std::path::Path::new(EXECUTABLE_PATH) {
            return Err(Error);
        }
        let value = Self(ProtectedFile::load(EXECUTABLE_PATH, 268_435_456, false)?);
        value.revalidate(policy)?;
        Ok(value)
    }

    pub fn revalidate(&self, policy: &QualificationBootstrapPolicy) -> Result<()> {
        if self.0.digest() != policy.root_consume().image_sha256() {
            return Err(Error);
        }
        self.0.require_current_executable()
    }
}
