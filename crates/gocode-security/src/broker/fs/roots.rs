impl FilesystemBroker {
    pub fn new(roots: Vec<WorkspaceRoot>) -> Self {
        #[cfg(not(target_os = "windows"))]
        {
            Self {
                roots,
                binding: BrokerBinding::new(),
            }
        }
        #[cfg(all(target_os = "windows", test))]
        {
            Self { roots }
        }
        #[cfg(all(target_os = "windows", not(test)))]
        {
            let _ = roots;
            Self {}
        }
    }

    pub fn open_root(&self, root_id: &str) -> Result<RootHandle, FsBrokerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (self, root_id);
            Err(FsBrokerError::BackendUnavailable)
        }
        #[cfg(not(target_os = "windows"))]
        if self.roots.iter().any(|root| root.root_id == root_id) {
            Ok(RootHandle {
                root_id: root_id.to_string(),
                binding: self.binding.clone(),
            })
        } else {
            Err(FsBrokerError::RootNotFound)
        }
    }
}
