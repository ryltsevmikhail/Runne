#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Returned only by the crate-owned registry evolution boundary.
pub enum RegistryAdvanceError {
    Unavailable,
    Exhausted,
    OpenDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedRegistryLoadError {
    InvalidSnapshot,
    MalformedAuthority,
}

impl PluginAuthorityPort for PluginAuthorityRegistry {
    fn verifier_for(
        &self,
        source: &PluginPackageSource,
    ) -> Result<PluginPackageVerifier, PluginAuthorityPortError> {
        self.authorities
            .iter()
            .find(|authority| authority.matches_content(source))
            .cloned()
            .map(PluginPackageVerifier::new)
            .ok_or(PluginAuthorityPortError::Unavailable)
    }
}

impl PluginGenerationPort for PluginAuthorityRegistry {
    fn acquire_read_lease(
        &self,
        activation_id: &crate::PluginActivationId,
    ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
        let generation = self
            .authorities
            .first()
            .map(|authority| authority.activation.generation)
            .ok_or(PluginGenerationPortError::Unavailable)?;
        Ok(PluginGenerationReadLease::issued(
            activation_id.clone(),
            generation,
        ))
    }

    fn ready_compare_and_set(
        &self,
        lease: &PluginGenerationReadLease,
    ) -> Result<(), PluginGenerationPortError> {
        match self.authorities.first() {
            Some(authority) if authority.activation.generation == lease.generation() => Ok(()),
            _ => Err(PluginGenerationPortError::Unavailable),
        }
    }

    fn publish_active(
        &self,
        lease: &PluginGenerationReadLease,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> Result<PluginActiveFence, PluginGenerationPortError> {
        if !self.authorities.iter().any(|authority| {
            authority.activation.generation == lease.generation()
                && authority.activation.negotiation_snapshot == negotiation_snapshot
        }) {
            return Err(PluginGenerationPortError::Unavailable);
        }
        self.active_bindings
            .lock()
            .map_err(|_| PluginGenerationPortError::Unavailable)?
            .insert(ActiveBindingKey {
                activation_id: lease.activation_id().clone(),
                generation: lease.generation(),
                negotiation_snapshot: negotiation_snapshot.into_bytes(),
            });
        Ok(PluginActiveFence::issued(lease, negotiation_snapshot))
    }

    fn validate_active(&self, fence: &PluginActiveFence) -> Result<(), PluginGenerationPortError> {
        let current = self.authorities.iter().any(|authority| {
            fence.generation() == authority.activation.generation
                && fence.negotiation_snapshot() == authority.activation.negotiation_snapshot
        });
        let published = self
            .active_bindings
            .lock()
            .map_err(|_| PluginGenerationPortError::Unavailable)?
            .contains(&ActiveBindingKey {
                activation_id: fence.activation_id().clone(),
                generation: fence.generation(),
                negotiation_snapshot: fence.negotiation_snapshot().into_bytes(),
            });
        if current && published {
            Ok(())
        } else {
            Err(PluginGenerationPortError::Unavailable)
        }
    }
}

impl PluginHookDispatchAuthorityPort for PluginAuthorityRegistry {
    fn claim(
        &self,
        activation: &crate::PluginActivationSnapshot,
        definition: &crate::PluginHookDefinition,
        invocation: &crate::PluginHookInvocation,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchClaimResult, PluginHookDispatchError> {
        let _transition = self
            .transition_gate
            .lock()
            .map_err(|_| PluginHookDispatchError::AuthorityUnavailable)?;
        if definition.plugin_id() != activation.plugin_id() || !activation.is_dispatchable(self) {
            return Err(PluginHookDispatchError::AuthorityUnavailable);
        }
        let claim = PluginHookDispatchClaim::new(
            activation,
            definition.plugin_id().clone(),
            invocation.invocation_id().clone(),
            definition.hook_id().clone(),
            request_digest,
        );
        match self
            .hook_dispatch_journal
            .claim_or_lookup(claim.key(), request_digest)
            .map_err(map_hook_journal_error)?
        {
            PluginHookDispatchJournalResult::Existing {
                request_digest: stored_digest,
                ..
            } if stored_digest != request_digest => Err(PluginHookDispatchError::IntentConflict),
            PluginHookDispatchJournalResult::Existing {
                outcome: Some(outcome),
                ..
            } => Ok(PluginHookDispatchClaimResult::Existing(outcome)),
            PluginHookDispatchJournalResult::Existing { outcome: None, .. } => Ok(
                PluginHookDispatchClaimResult::Existing(PluginHookDisposition::Uncertain),
            ),
            PluginHookDispatchJournalResult::Fresh => {
                Ok(PluginHookDispatchClaimResult::Fresh(claim))
            }
        }
    }

    fn complete(
        &self,
        claim: PluginHookDispatchClaim,
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchError> {
        self.hook_dispatch_journal
            .complete(claim.key(), *claim.request_digest(), disposition)
            .map_err(map_hook_journal_error)
    }

    fn quarantine_recovered(
        &self,
        recovered: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchError> {
        let _transition = self
            .transition_gate
            .lock()
            .map_err(|_| PluginHookDispatchError::AuthorityUnavailable)?;
        self.hook_dispatch_journal
            .quarantine_recovered(recovered)
            .map_err(map_hook_journal_error)
    }
}

fn map_hook_journal_error(error: PluginHookDispatchJournalError) -> PluginHookDispatchError {
    match error {
        PluginHookDispatchJournalError::Unavailable => {
            PluginHookDispatchError::AuthorityUnavailable
        }
        PluginHookDispatchJournalError::Conflict => PluginHookDispatchError::IntentConflict,
    }
}

/// Failure to obtain a registry-owned package verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginAuthorityPortError {
    /// No registry authority was issued for the captured source.
    Unavailable,
}

impl fmt::Display for PluginAuthorityPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plugin package authority unavailable")
    }
}

impl std::error::Error for PluginAuthorityPortError {}

/// Typed rejection of package authority verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageVerificationError {
    /// The package digest differed from the authority record.
    PackageDigestMismatch,
    /// The manifest digest differed from the authority record.
    ManifestDigestMismatch,
    /// The entrypoint digest differed from the authority record.
    EntrypointDigestMismatch,
    /// The manifest class differed from the registry-authorized class.
    DeclaredClassMismatch,
    /// The registry trust-binding evidence differed from the authority record.
    TrustBindingDigestMismatch,
    /// The complete protocol profile digest differed from the authority record.
    ProtocolProfileDigestMismatch,
}

impl fmt::Display for PluginPackageVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PackageDigestMismatch => "plugin package digest mismatch",
            Self::ManifestDigestMismatch => "plugin manifest digest mismatch",
            Self::EntrypointDigestMismatch => "plugin entrypoint digest mismatch",
            Self::DeclaredClassMismatch => "plugin declared class mismatch",
            Self::TrustBindingDigestMismatch => "plugin trust binding digest mismatch",
            Self::ProtocolProfileDigestMismatch => "plugin protocol profile digest mismatch",
        })
    }
}

impl std::error::Error for PluginPackageVerificationError {}
