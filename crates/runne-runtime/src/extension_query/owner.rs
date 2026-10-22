use super::owner_state::OwnerState;
use super::*;
use std::sync::RwLock;
/// CONFIDENTIAL/INTERNAL accepted snapshot. No production source/session admission.
pub(super) struct ConfiguredExtensionRegistry {
    pub(super) state: RwLock<OwnerState>,
    scope: RegistryScope,
    version: SnapshotVersion,
    records: Vec<ConfiguredMetadata>,
}
impl ConfiguredExtensionRegistry {
    pub(super) fn new(expected: RegistryExpectation, records: Vec<ConfiguredMetadata>) -> Self {
        Self {
            state: RwLock::new(OwnerState {
                epoch: 1,
                closed: false,
            }),
            scope: expected.scope,
            version: expected.version,
            records,
        }
    }
    pub(super) fn capture(
        file: std::fs::File,
        expected: RegistryExpectation,
    ) -> Result<Self, MetadataQueryError> {
        capture::capture(file, expected)
    }
    pub(super) fn query(&self, request: QueryRequest) -> Result<MetadataReply, MetadataQueryError> {
        // Validate only owner-independent scope syntax before observing the lock.
        if !valid_uuid(request.context.project.as_bytes())
            || runne_api::ApiPrincipalId::new(request.context.principal.as_str()).is_err()
        {
            return Err(MetadataQueryError::InvalidRequest);
        }
        let guard = self
            .state
            .read()
            .map_err(|_| MetadataQueryError::InternalUnavailable)?;
        self.query_guarded(request, &guard)
    }
    pub(super) fn query_guarded(
        &self,
        request: QueryRequest,
        state: &OwnerState,
    ) -> Result<MetadataReply, MetadataQueryError> {
        use MetadataQueryError::{
            InvalidRequest, NotFound, OwnerClosed, ScopeDenied, StaleGeneration, StaleSnapshot,
            UnsupportedContract,
        };
        let c = &request.context;
        if c.principal != self.scope.principal || c.project != self.scope.project {
            return Err(ScopeDenied);
        }
        if state.closed {
            return Err(OwnerClosed);
        }
        if c.contract_version != 1 {
            return Err(UnsupportedContract);
        }
        if c.runtime_incarnation == [0; 16]
            || !bounded_revision(c.runtime_generation)
            || !bounded_revision(c.owner_epoch)
            || !bounded_revision(request.expected_snapshot.registration_revision)
            || matches!(&request.query,Query::Get{key} if !valid_id(&key.id.0))
        {
            return Err(InvalidRequest);
        }
        if c.runtime_incarnation != self.scope.runtime_incarnation
            || c.runtime_generation != self.scope.runtime_generation
            || c.owner_epoch != state.epoch
        {
            return Err(StaleGeneration);
        }
        if request.expected_snapshot != self.version {
            return Err(StaleSnapshot);
        }
        let selected = |r: &&ConfiguredMetadata| match &request.query {
            Query::List { kind } => kind.is_none_or(|k| k == r.key().kind),
            Query::Get { key } => *key == r.key(),
        };
        if matches!(request.query, Query::Get { .. }) && !self.records.iter().any(|r| selected(&r))
        {
            return Err(NotFound);
        }
        // Accounting BEFORE reply Vec allocation/cloning, while same read guard is held.
        digest::reply_budget(digest::projected_len(
            &self.scope,
            self.records.iter().filter(selected),
        )?)?;
        let records = self.records.iter().filter(selected).cloned().collect();
        Ok(MetadataReply {
            scope: self.scope.clone(),
            owner_epoch: state.epoch,
            snapshot: self.version.clone(),
            records,
        })
    }
    pub(super) fn close(&self, expected: u64) -> Result<(), MetadataQueryError> {
        self.state
            .write()
            .map_err(|_| MetadataQueryError::InternalUnavailable)?
            .close(expected)
    }
}
impl std::fmt::Debug for ConfiguredExtensionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfiguredExtensionRegistry(<opaque>)")
    }
}
