use std::path::{Path, PathBuf};

use crate::directory_files::verify_regular_for_process;
use crate::identity::{DirectoryHandle, NativeHandleError};
use crate::path::ValidatedWindowsPath;
use crate::relative::open_relative_file;

impl DirectoryHandle {
    /// Resolves one validated regular file to a short-lived shell target.
    ///
    /// # Errors
    ///
    /// Returns a closed error when traversal, reparse points, or native file
    /// identity validation fails.
    pub fn open_editor_file_path(&self, path: &Path) -> Result<PathBuf, NativeHandleError> {
        let components = ValidatedWindowsPath::relative(path)?;
        let (name, parents) = components.split_last().ok_or(NativeHandleError::Rejected)?;
        let parent_path = parents.iter().fold(PathBuf::new(), |mut path, part| {
            path.push(part);
            path
        });
        let parent = if parents.is_empty() {
            self.try_clone()?
        } else {
            self.open_relative_directory(&parent_path)?
        };
        let file = open_relative_file(parent.owned_handle(), name)?;
        verify_regular_for_process(&file)?;
        super::process_files::final_path_for_editor(&file)
    }
}
