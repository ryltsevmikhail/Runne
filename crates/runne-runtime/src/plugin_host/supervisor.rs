impl RuntimeExtensionSupervisor {
    /// Constructs an empty supervisor.
    pub fn new() -> Self {
        Self {
            roots: BTreeMap::new(),
            tasks: JoinSet::new(),
            task_roots: HashMap::new(),
        }
    }

    /// Registers ownership before the root future can be constructed or polled.
    pub fn register_root(
        &mut self,
        binding: ExtensionRootBinding,
        root: Arc<dyn ExtensionRootPort>,
    ) -> Result<(), ExtensionSupervisorError> {
        if self.roots.contains_key(&binding.root_id) {
            return Err(ExtensionSupervisorError::DuplicateRoot);
        }
        let cancellation = CancellationToken::new();
        let registration = Arc::new(AtomicBool::new(false));
        let lease = RuntimeRootLease {
            root_id: binding.root_id.clone(),
            kind: binding.kind,
            generation: binding.generation,
            authority_digest: binding.authority_digest,
            registration: Arc::clone(&registration),
        };
        let root_id = binding.root_id.clone();
        self.roots.insert(
            root_id.clone(),
            RootRecord {
                binding,
                state: ExtensionRootState::Running,
                cancellation: cancellation.clone(),
                abort_handle: None,
                _registration: Arc::clone(&registration),
            },
        );
        registration.store(true, Ordering::Release);
        let task_cancellation = cancellation.clone();
        let task_root_id = root_id.clone();
        let abort_handle = self.tasks.spawn(async move {
            let exit = root.run(lease, task_cancellation).await;
            (task_root_id, exit)
        });
        let task_id = abort_handle.id();
        self.task_roots.insert(task_id, root_id.clone());
        self.roots
            .get_mut(&root_id)
            .ok_or(ExtensionSupervisorError::TaskFailed)?
            .abort_handle = Some(abort_handle);
        Ok(())
    }

    /// Fences every root not owned by the exact current generation.
    pub fn fence_stale_generations(&mut self, current_generation: u64) {
        for record in self.roots.values_mut() {
            if record.binding.generation != current_generation
                && matches!(record.state, ExtensionRootState::Running)
            {
                record.state = ExtensionRootState::Fenced;
                record.cancellation.cancel();
            }
        }
    }

    /// Immediately fences one root after containment/broker loss.
    pub fn containment_lost(&mut self, root_id: &str) -> Result<(), ExtensionSupervisorError> {
        let record = self
            .roots
            .get_mut(root_id)
            .ok_or(ExtensionSupervisorError::RootNotFound)?;
        if matches!(record.state, ExtensionRootState::Running) {
            record.state = ExtensionRootState::Fenced;
            record.cancellation.cancel();
        }
        Ok(())
    }

    /// Begins drain by cancelling every still-running owned root.
    pub fn begin_drain(&mut self) {
        for record in self.roots.values_mut() {
            if matches!(record.state, ExtensionRootState::Running) {
                record.state = ExtensionRootState::Draining;
                record.cancellation.cancel();
            }
        }
    }

    /// Forcibly aborts one owned root. The subsequent join receipt is
    /// `Uncertain` because backend cleanup cannot be proven by cancellation.
    pub fn abort_root(&mut self, root_id: &str) -> Result<(), ExtensionSupervisorError> {
        let record = self
            .roots
            .get_mut(root_id)
            .ok_or(ExtensionSupervisorError::RootNotFound)?;
        if !matches!(
            record.state,
            ExtensionRootState::Terminal | ExtensionRootState::Uncertain
        ) {
            record.state = ExtensionRootState::Fenced;
            record
                .abort_handle
                .as_ref()
                .ok_or(ExtensionSupervisorError::TaskFailed)?
                .abort();
        }
        Ok(())
    }

    /// Joins one root and records only terminal or uncertain teardown.
    pub async fn join_next(&mut self) -> Result<ExtensionRootReceipt, ExtensionSupervisorError> {
        let joined = self
            .tasks
            .join_next_with_id()
            .await
            .ok_or(ExtensionSupervisorError::RootNotFound)?;
        let (task_id, root_id, state) = match joined {
            Ok((task_id, (returned_root_id, exit))) => {
                let registered_root_id = self
                    .task_roots
                    .remove(&task_id)
                    .ok_or(ExtensionSupervisorError::TaskFailed)?;
                if returned_root_id != registered_root_id {
                    return Err(ExtensionSupervisorError::TaskFailed);
                }
                let state = match exit {
                    ExtensionRootExit::Terminal => ExtensionRootState::Terminal,
                    ExtensionRootExit::Uncertain => ExtensionRootState::Uncertain,
                };
                (task_id, registered_root_id, state)
            }
            Err(error) => {
                let task_id = error.id();
                let root_id = self
                    .task_roots
                    .remove(&task_id)
                    .ok_or(ExtensionSupervisorError::TaskFailed)?;
                (task_id, root_id, ExtensionRootState::Uncertain)
            }
        };
        debug_assert!(!self.task_roots.contains_key(&task_id));
        self.roots
            .get_mut(&root_id)
            .ok_or(ExtensionSupervisorError::RootNotFound)?
            .state = state;
        Ok(ExtensionRootReceipt { root_id, state })
    }

    /// Current state for one registered root.
    pub fn state(&self, root_id: &str) -> Option<ExtensionRootState> {
        self.roots.get(root_id).map(|record| record.state)
    }

    /// Count of roots that have not reached terminal/uncertain teardown.
    pub fn active_roots(&self) -> usize {
        self.roots
            .values()
            .filter(|record| {
                !matches!(
                    record.state,
                    ExtensionRootState::Terminal | ExtensionRootState::Uncertain
                )
            })
            .count()
    }
}

impl Default for RuntimeExtensionSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
