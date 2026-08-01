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
        #[cfg(unix)]
        {
            let _ = (self, root, path, data, expected_identity);
            Err(FsBrokerError::MutationUnavailable)
        }
        #[cfg(all(not(unix), not(target_os = "windows")))]
        {
            self.validate_root_handle(root)?;
            let workspace_root = self.find_root_for_root_handle(root)?;
            if !workspace_root.policy.write_allowed {
                return Err(FsBrokerError::PermissionDenied);
            }
            let handle = self.resolve(root, path)?;
            let mut file = OpenOptions::new()
                .write(true)
                .open(&handle.path)
                .map_err(|error| FsBrokerError::Io(error.to_string()))?;
            let metadata = file
                .metadata()
                .map_err(|error| FsBrokerError::Io(error.to_string()))?;
            let current_identity = FsIdentity {
                inode: 0,
                device: 0,
            };
            if current_identity != *expected_identity {
                return Err(FsBrokerError::IdentityMismatch);
            }
            file.set_len(0)
                .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
                .and_then(|()| file.write_all(data))
                .and_then(|()| file.flush())
                .map_err(|error| FsBrokerError::Io(error.to_string()))
        }
    }

    pub fn write_created(
        &self,
        handle: &CreatedFsHandle,
        data: &[u8],
    ) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle, data);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_created_handle(handle)?;
            #[cfg(unix)]
            {
                let _ = (handle, data);
                Err(FsBrokerError::MutationUnavailable)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let workspace_root = self.find_root(&handle.root_id)?;
                if !workspace_root.policy.write_allowed {
                    return Err(FsBrokerError::PermissionDenied);
                }
                fs::write(&handle.path, data).map_err(|error| FsBrokerError::Io(error.to_string()))
            }
        }
    }
}
