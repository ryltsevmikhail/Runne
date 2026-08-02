/// Fail-closed registry lookup boundary for an opaque package authority.
pub trait PluginAuthorityPort {
    /// Returns a verifier only when registry-owned authority is available.
    fn verifier_for(
        &self,
        source: &PluginPackageSource,
    ) -> Result<PluginPackageVerifier, PluginAuthorityPortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActiveBindingKey {
    activation_id: crate::PluginActivationId,
    generation: PluginGeneration,
    negotiation_snapshot: [u8; 32],
}

type HookDispatchRecord = ([u8; 32], Option<PluginHookDisposition>);
type HookDispatchRecords = BTreeMap<PluginHookDispatchJournalKey, HookDispatchRecord>;

#[derive(Debug, Default)]
struct InMemoryPluginHookDispatchJournal {
    records: Mutex<HookDispatchRecords>,
}

impl PluginHookDispatchJournal for InMemoryPluginHookDispatchJournal {
    fn claim_or_lookup(
        &self,
        key: &PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchJournalResult, PluginHookDispatchJournalError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?;
        match records.get(key) {
            Some((stored_digest, outcome)) => Ok(PluginHookDispatchJournalResult::Existing {
                request_digest: *stored_digest,
                outcome: *outcome,
            }),
            None => {
                records.insert(key.clone(), (request_digest, None));
                Ok(PluginHookDispatchJournalResult::Fresh)
            }
        }
    }

    fn complete(
        &self,
        key: &PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchJournalError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?;
        match records.get_mut(key) {
            Some((stored_digest, outcome))
                if stored_digest == &request_digest && outcome.is_none() =>
            {
                *outcome = Some(disposition);
                Ok(())
            }
            Some((stored_digest, Some(stored_outcome)))
                if stored_digest == &request_digest && stored_outcome == &disposition =>
            {
                Ok(())
            }
            Some(_) => Err(PluginHookDispatchJournalError::Conflict),
            None => Err(PluginHookDispatchJournalError::Unavailable),
        }
    }

    fn has_open_dispatches(&self) -> Result<bool, PluginHookDispatchJournalError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?
            .values()
            .any(|(_, outcome)| outcome.is_none()))
    }

    fn next_recovered_dispatch(
        &self,
    ) -> Result<Option<PluginHookRecoveredDispatch>, PluginHookDispatchJournalError> {
        Ok(None)
    }

    fn quarantine_recovered(
        &self,
        _: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchJournalError> {
        Err(PluginHookDispatchJournalError::Conflict)
    }
}

/// Immutable, registry-owned package authority lookup implementation.
pub struct PluginAuthorityRegistry {
    authorities: Box<[PluginPackageAuthority]>,
    active_bindings: Mutex<BTreeSet<ActiveBindingKey>>,
    hook_dispatch_journal: Arc<dyn PluginHookDispatchJournal>,
    transition_gate: Mutex<()>,
}

impl fmt::Debug for PluginAuthorityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginAuthorityRegistry")
            .field("authorities", &self.authorities)
            .field("active_bindings", &self.active_bindings)
            .field("hook_dispatch_journal", &"<opaque durable journal>")
            .field("transition_gate", &self.transition_gate)
            .finish()
    }
}

impl Default for PluginAuthorityRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl PluginAuthorityRegistry {
    pub(crate) fn with_active_transition<R>(
        &self,
        activation: &crate::PluginActivationSnapshot,
        operation: impl FnOnce() -> R,
    ) -> Result<R, ()> {
        let _transition = self.transition_gate.lock().map_err(|_| ())?;
        if !activation.is_dispatchable(self) {
            return Err(());
        }
        Ok(operation())
    }

    /// Creates a fail-closed registry with no package authorities.
    pub fn empty() -> Self {
        Self {
            authorities: Box::new([]),
            active_bindings: Mutex::new(BTreeSet::new()),
            hook_dispatch_journal: Arc::new(InMemoryPluginHookDispatchJournal::default()),
            transition_gate: Mutex::new(()),
        }
    }

    /// Loads the crate-owned immutable registry policy shipped with this host.
    pub fn built_in() -> Self {
        Self::built_in_with_hook_dispatch_journal(Arc::new(
            InMemoryPluginHookDispatchJournal::default(),
        ))
    }

    /// Loads built-in package policy with a repository-owned durable hook journal.
    ///
    /// Production composition must inject storage that survives process restart.
    pub fn built_in_with_hook_dispatch_journal(
        hook_dispatch_journal: Arc<dyn PluginHookDispatchJournal>,
    ) -> Self {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::try_new(
                BUILTIN_PACKAGE_BYTES.to_vec(),
                BUILTIN_MANIFEST_BYTES.to_vec(),
                BUILTIN_ENTRYPOINT_BYTES.to_vec(),
                BUILTIN_PROTOCOL_PROFILE_BYTES.to_vec(),
                BUILTIN_TRUST_BINDING_BYTES.to_vec(),
            )
            .expect("embedded package satisfies the production capture boundary"),
            PluginClass::Extension,
        );
        Self::from_trusted_loader_with_hook_dispatch_journal(
            vec![
                PluginPackageAuthority::issue(
                    &source,
                    PluginClass::Extension,
                    PluginTrust::Restricted,
                )
                .expect("embedded manifest/profile are valid"),
            ],
            Arc::clone(&hook_dispatch_journal),
        )
        .unwrap_or_else(|_| Self {
            authorities: Box::new([]),
            active_bindings: Mutex::new(BTreeSet::new()),
            hook_dispatch_journal,
            transition_gate: Mutex::new(()),
        })
    }

    #[cfg(test)]
    fn from_trusted_loader(
        authorities: Vec<PluginPackageAuthority>,
    ) -> Result<Self, TrustedRegistryLoadError> {
        Self::from_trusted_loader_with_hook_dispatch_journal(
            authorities,
            Arc::new(InMemoryPluginHookDispatchJournal::default()),
        )
    }

    fn from_trusted_loader_with_hook_dispatch_journal(
        authorities: Vec<PluginPackageAuthority>,
        hook_dispatch_journal: Arc<dyn PluginHookDispatchJournal>,
    ) -> Result<Self, TrustedRegistryLoadError> {
        if authorities.is_empty()
            || authorities
                .iter()
                .enumerate()
                .any(|(index, authority)| authorities[index + 1..].contains(authority))
        {
            return Err(TrustedRegistryLoadError::InvalidSnapshot);
        }
        Ok(Self {
            authorities: authorities.into_boxed_slice(),
            active_bindings: Mutex::new(BTreeSet::new()),
            hook_dispatch_journal,
            transition_gate: Mutex::new(()),
        })
    }

    /// Advances the immutable registry snapshot without accepting caller-selected
    /// generation or metadata. Existing read leases become stale.
    pub fn advance(&mut self) -> Result<(), RegistryAdvanceError> {
        let _transition = self
            .transition_gate
            .lock()
            .map_err(|_| RegistryAdvanceError::Unavailable)?;
        if self
            .hook_dispatch_journal
            .has_open_dispatches()
            .map_err(|_| RegistryAdvanceError::Unavailable)?
        {
            return Err(RegistryAdvanceError::OpenDispatch);
        }
        let generation = self
            .authorities
            .first()
            .map(|authority| authority.activation.generation)
            .ok_or(RegistryAdvanceError::Unavailable)?;
        let next = PluginGeneration::new(
            generation
                .get()
                .checked_add(1)
                .ok_or(RegistryAdvanceError::Exhausted)?,
        )
        .ok_or(RegistryAdvanceError::Exhausted)?;
        if self
            .authorities
            .iter()
            .any(|authority| authority.activation.generation != generation)
        {
            return Err(RegistryAdvanceError::Unavailable);
        }
        self.authorities = self
            .authorities
            .iter()
            .map(|authority| authority.at_generation(next))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.active_bindings
            .get_mut()
            .map_err(|_| RegistryAdvanceError::Unavailable)?
            .clear();
        Ok(())
    }
}
