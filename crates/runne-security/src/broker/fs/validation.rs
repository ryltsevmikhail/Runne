impl FilesystemBroker {
    #[cfg(any(not(target_os = "windows"), test))]
    fn find_root(&self, root_id: &str) -> Result<&WorkspaceRoot, FsBrokerError> {
        self.roots
            .iter()
            .find(|root| root.root_id == root_id)
            .ok_or(FsBrokerError::RootNotFound)
    }

    #[cfg(not(target_os = "windows"))]
    fn find_root_for_root_handle(
        &self,
        root: &RootHandle,
    ) -> Result<&WorkspaceRoot, FsBrokerError> {
        self.validate_root_handle(root)?;
        self.find_root(&root.root_id)
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_root_handle(&self, handle: &RootHandle) -> Result<(), FsBrokerError> {
        self.binding
            .matches(&handle.binding)
            .then_some(())
            .ok_or(FsBrokerError::PermissionDenied)?;
        #[cfg(unix)]
        {
            let fd = handle
                .fd
                .as_ref()
                .ok_or_else(|| FsBrokerError::Io("missing root descriptor".into()))?;
            super::fs_unix::root_is_admitted(fd, &handle.identity)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_fs_handle(&self, handle: &FsHandle) -> Result<(), FsBrokerError> {
        self.binding
            .matches(&handle.binding)
            .then_some(())
            .ok_or(FsBrokerError::PermissionDenied)
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_created_handle(&self, handle: &CreatedFsHandle) -> Result<(), FsBrokerError> {
        self.binding
            .matches(&handle.binding)
            .then_some(())
            .ok_or(FsBrokerError::PermissionDenied)
    }
}

#[cfg(unix)]
fn handle_fd(handle: &FsHandle) -> Result<&OwnedFd, FsBrokerError> {
    handle
        .fd
        .as_ref()
        .ok_or_else(|| FsBrokerError::Io("missing file descriptor".into()))
}

#[cfg(unix)]
fn file_from_held_fd(handle: &FsHandle) -> Result<fs::File, FsBrokerError> {
    let fd = handle_fd(handle)?;
    // Дескриптор дублируется с CLOEXEC, сохраняя исходный descriptor у handle.
    let duplicate = rustix::io::fcntl_dupfd_cloexec(fd, 0)
        .map_err(|error| FsBrokerError::Io(error.to_string()))?;
    Ok(fs::File::from(duplicate))
}
