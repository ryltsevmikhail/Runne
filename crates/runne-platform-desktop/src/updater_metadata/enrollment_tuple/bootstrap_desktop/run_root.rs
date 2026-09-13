//! Descriptor-rooted fresh filesystem state for one qualification run.

use std::path::Path;

#[path = "run_root/fs.rs"]
mod fs;

#[cfg(test)]
#[path = "run_root/tests.rs"]
mod tests;

/// Fresh, private run state copied from the admitted signed journal generations.
pub(super) struct FreshQualificationRunRoot {
    state: fs::RunRootState,
}

impl FreshQualificationRunRoot {
    /// Creates exactly one private run root beside the fixed source profile.
    pub(super) fn create(source_profile: &Path, run_id: &str) -> Option<Self> {
        fs::RunRootState::create(source_profile, run_id).map(|state| Self { state })
    }

    /// Returns the fixed private root for the sealed run preparation.
    pub(super) fn path(&self) -> &Path {
        self.state.path()
    }

    /// Rechecks all retained source and copied journal identities and content.
    pub(super) fn revalidate(&self) -> Option<()> {
        self.state.revalidate()
    }
}
