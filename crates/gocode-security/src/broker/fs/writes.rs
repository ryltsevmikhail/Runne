#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};

impl FilesystemBroker {
    pub fn write_with_revalidation(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
        data: &[u8],
        expected_identity: &FsIdentity,
    ) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, path, data, expected_identity);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (self, root, path, data, expected_identity);
            Err(FsBrokerError::MutationUnavailable)
        }
    }

    /// Consumes the one-shot creation capability before publication.
    ///
    /// ```compile_fail
    /// use gocode_security::broker::fs::{CreatedFsHandle, FilesystemBroker};
    ///
    /// fn retry(broker: &FilesystemBroker, handle: CreatedFsHandle) {
    ///     let _ = broker.write_created(handle, b"first");
    ///     let _ = broker.write_created(handle, b"second");
    /// }
    /// ```
    pub fn write_created(
        &self,
        handle: CreatedFsHandle,
        data: &[u8],
    ) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle, data);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            #[cfg(unix)]
            {
                self.validate_created_handle(&handle)?;
                let CreatedFsHandle {
                    root_id,
                    fd,
                    parent_fd,
                    final_name,
                    ..
                } = handle;
                let workspace_root = self.find_root(&root_id)?;
                if !workspace_root.policy.write_allowed {
                    return Err(FsBrokerError::PermissionDenied);
                }
                let fd = fd
                    .ok_or_else(|| FsBrokerError::Io("missing file descriptor".into()))?;
                let duplicate = rustix::io::fcntl_dupfd_cloexec(&fd, 0)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                stage_file(duplicate, data)?;
                let parent = parent_fd
                    .ok_or_else(|| FsBrokerError::Io("missing parent descriptor".into()))?;
                super::fs_unix::commit_create(&parent, &fd, &final_name)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let _ = (self, handle, data);
                Err(FsBrokerError::BackendUnavailable)
            }
        }
    }
}

#[cfg(unix)]
fn stage_file(fd: OwnedFd, data: &[u8]) -> Result<(), FsBrokerError> {
    let mut file = fs::File::from(fd);
    file.set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| file.write_all(data))
        .and_then(|()| file.sync_all())
        .map_err(|error| FsBrokerError::Io(error.to_string()))
}
