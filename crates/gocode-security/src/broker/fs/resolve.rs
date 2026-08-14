impl FilesystemBroker {
    pub fn resolve(
        &self,
        root: &RootHandle,
        relative: &CanonicalPath,
    ) -> Result<FsHandle, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, relative);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.validate_root_handle(root)?;
            let workspace_root = self.find_root_for_root_handle(root)?;
            #[cfg(unix)]
            let fd = {
                let root_fd = root
                    .fd
                    .as_ref()
                    .ok_or_else(|| FsBrokerError::Io("missing root descriptor".into()))?;
                let resolution = super::fs_unix::resolve_nofollow(
                    root_fd,
                    &relative.components,
                    rustix::fs::OFlags::RDONLY,
                )?;
                resolution.file_fd
            };
            #[cfg(all(not(unix), not(target_os = "windows")))]
            let canonical = {
                let mut current = workspace_root.canonical_path.clone();
                for component in &relative.components {
                    current.push(component);
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                    if metadata.file_type().is_symlink() {
                        return Err(FsBrokerError::SymlinkEscapesRoot);
                    }
                }
                let full_path = workspace_root
                    .canonical_path
                    .join(relative.components.join("/"));
                fs::canonicalize(&full_path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?
            };
            #[cfg(not(unix))]
            if !canonical.starts_with(&workspace_root.canonical_path) {
                return Err(FsBrokerError::SymlinkEscapesRoot);
            }
            #[cfg(unix)]
            let canonical = workspace_root
                .canonical_path
                .join(relative.components.join("/"));
            self.validate_sensitive_path(&canonical)?;
            Ok(FsHandle {
                root_id: root.root_id.clone(),
                binding: self.binding.clone(),
                #[cfg(not(unix))]
                path: canonical,
                #[cfg(unix)]
                fd: Some(fd),
            })
        }
    }

    // `st_dev` signedness differs across Unix targets, so the checked
    // conversion is meaningful even where a given target aliases it to `u64`.
    #[allow(clippy::useless_conversion)]
    pub fn resolve_and_identity(
        &self,
        root: &RootHandle,
        path: &CanonicalPath,
    ) -> Result<(FsHandle, FsIdentity), FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root, path);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let handle = self.resolve(root, path)?;
            #[cfg(unix)]
            {
                let stat = rustix::fs::fstat(handle_fd(&handle)?)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok((
                    handle,
                    FsIdentity {
                        inode: stat.st_ino,
                        device: u64::try_from(stat.st_dev)
                            .map_err(|_| FsBrokerError::Io("negative device identity".into()))?,
                    },
                ))
            }
            #[cfg(not(unix))]
            {
                let _metadata = fs::metadata(&handle.path)
                    .map_err(|error| FsBrokerError::Io(error.to_string()))?;
                Ok((
                    handle,
                    FsIdentity {
                        inode: 0,
                        device: 0,
                    },
                ))
            }
        }
    }
}
