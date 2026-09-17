use super::{
    open_rooted_file, NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError,
    OpenedNativeEnrollmentFile,
};

const GUI_EXECUTOR_NAME: &str = "runne-qualification-gui-executor";
const GUI_EXECUTOR_PATH: &[&str] = &["Contents", "MacOS", GUI_EXECUTOR_NAME];

impl NativeEnrollmentArtifactPathsV1 {
    pub(in crate::updater_metadata) fn resolve_current_gui_executor(
    ) -> Result<(Self, OpenedNativeEnrollmentFile), NativeEnrollmentTupleError> {
        let executable =
            std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let paths = Self::from_macos_package_executable(&executable, GUI_EXECUTOR_NAME, false)?;
        let executor = paths.open_current_gui_executor()?;
        paths.confirm_current_gui_executor(&executor)?;
        Ok((paths, executor))
    }

    pub(in crate::updater_metadata) fn confirm_current_gui_executor(
        &self,
        executor: &OpenedNativeEnrollmentFile,
    ) -> Result<(), NativeEnrollmentTupleError> {
        self.confirm_current()?;
        self.matches_current_gui_executor(executor)?;
        executor.confirm_current_executable()?;
        self.matches_current_gui_executor(executor)?;
        self.confirm_current()
    }

    fn open_current_gui_executor(
        &self,
    ) -> Result<OpenedNativeEnrollmentFile, NativeEnrollmentTupleError> {
        self.confirm_current()?;
        let executor =
            OpenedNativeEnrollmentFile::new(open_rooted_file(&self.root, GUI_EXECUTOR_PATH)?)?;
        self.matches_current_gui_executor(&executor)?;
        Ok(executor)
    }

    fn matches_current_gui_executor(
        &self,
        executor: &OpenedNativeEnrollmentFile,
    ) -> Result<(), NativeEnrollmentTupleError> {
        let current = open_rooted_file(&self.root, GUI_EXECUTOR_PATH)?;
        executor
            .matches_file(&current)?
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}
