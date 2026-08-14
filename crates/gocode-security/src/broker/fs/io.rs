impl FilesystemBroker {
    pub fn read(&self, handle: &FsHandle) -> Result<Vec<u8>, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_fs_handle(handle)?;
            let workspace_root = self.find_root(&handle.root_id)?;
            if !workspace_root.policy.read_allowed {
                return Err(FsBrokerError::PermissionDenied);
            }
            #[cfg(unix)]
            {
                let mut file = file_from_held_fd(handle)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok(contents)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                fs::read(&handle.path).map_err(|error| FsBrokerError::Io(error.to_string()))
            }
        }
    }

    pub fn list(&self, handle: &FsHandle) -> Result<Vec<String>, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_fs_handle(handle)?;
            let workspace_root = self.find_root(&handle.root_id)?;
            if !workspace_root.policy.read_allowed {
                return Err(FsBrokerError::PermissionDenied);
            }
            #[cfg(unix)]
            {
                rustix::fs::Dir::read_from(handle_fd(handle)?)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?
                    .filter_map(|entry| match entry {
                        Ok(entry) => {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            (!matches!(name.as_str(), "." | "..")).then_some(Ok(name))
                        }
                        Err(error) => Some(Err(FsBrokerError::Io(error.to_string()))),
                    })
                    .collect()
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let entries = fs::read_dir(&handle.path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                entries
                    .map(|entry| {
                        entry
                            .map(|entry| entry.file_name().to_string_lossy().to_string())
                            .map_err(|error| FsBrokerError::Io(error.to_string()))
                    })
                    .collect()
            }
        }
    }

    pub fn create(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<CreatedFsHandle, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, relative);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_root_handle(root)?;
            #[cfg(unix)]
            {
                let workspace_root = self.find_root_for_root_handle(root)?;
                if !workspace_root.policy.create_allowed {
                    return Err(FsBrokerError::PermissionDenied);
                }
                let candidate = workspace_root
                    .canonical_path
                    .join(relative.components.join("/"));
                self.validate_sensitive_path(&candidate)?;
                let root_fd = root
                    .fd
                    .as_ref()
                    .ok_or_else(|| FsBrokerError::Io("missing root descriptor".into()))?;
                let parent = super::fs_unix::parent_nofollow(root_fd, &relative.components)?;
                super::fs_unix::ensure_absent(&parent.directory, &parent.final_name)?;
                let fd = super::fs_unix::create_unnamed(&parent.directory)?;
                Ok(CreatedFsHandle {
                    root_id: root.root_id.clone(),
                    binding: self.binding.clone(),
                    fd: Some(fd),
                    parent_fd: Some(parent.directory),
                    final_name: parent.final_name,
                })
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let _ = (root, relative);
                Err(FsBrokerError::BackendUnavailable)
            }
        }
    }

    pub fn delete(&self, handle: &FsHandle) -> Result<(), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, handle);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_fs_handle(handle)?;
            #[cfg(unix)]
            {
                let _ = handle;
                Err(FsBrokerError::MutationUnavailable)
            }
            #[cfg(all(not(unix), not(target_os = "windows")))]
            {
                let _ = handle;
                Err(FsBrokerError::BackendUnavailable)
            }
        }
    }
}
