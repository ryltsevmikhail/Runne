use gocode_local_store::{
    AppliedReplayEvent, LocalStore, ReplayApplyOutcome, ReplayCheckpoint, ReplayScopeKey,
    ReplayStoreError, ReplayTransition,
};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CanonicalReplayPayload, ConversationMessageRole,
    ConversationReplayPayload, ReplayAggregateKind, ReplayDelivery, replay_persistence_digest,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppCoreError, ConversationMessageSummary, ConversationRecoveryDisposition,
    ConversationSnapshot, ConversationTimelineUpdate, StoredConversationReference,
    StoredConversationReferenceV2,
};

const PROJECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableRuntimeIdentity {
    pub authority: String,
    pub principal: String,
    pub lineage: String,
    pub profile_id: String,
    pub schema_hash: String,
    pub capability_digest: String,
    pub binding_digest: String,
    pub launch_generation: u64,
}

impl StableRuntimeIdentity {
    pub fn from_client(client: &AuthenticatedRuntimeClient) -> Self {
        let session = client.session_info();
        Self {
            authority: session.authority_id.clone(),
            principal: session.principal_id.clone(),
            lineage: session.event_log_lineage_id.clone(),
            profile_id: session.profile_id.clone(),
            schema_hash: session.schema_hash.clone(),
            capability_digest: session.capability_digest.clone(),
            binding_digest: client.replay_persistence_binding().digest().to_owned(),
            launch_generation: session.launch_generation,
        }
    }

    pub fn matches_reference(&self, reference: &StoredConversationReferenceV2) -> bool {
        [
            self.authority == reference.runtime_authority,
            self.principal == reference.principal,
            self.lineage == reference.lineage,
            self.profile_id == reference.profile_id,
            self.schema_hash == reference.schema_hash,
            self.capability_digest == reference.capability_digest,
        ]
        .into_iter()
        .all(std::convert::identity)
    }

    pub fn bind_reference(
        &self,
        reference: &StoredConversationReference,
    ) -> StoredConversationReferenceV2 {
        StoredConversationReferenceV2 {
            schema_version: 2,
            conversation_id: reference.conversation_id(),
            workspace_id: reference.workspace_id(),
            create_command_id: reference.create_command_id(),
            idempotency_key: reference.idempotency_key().to_owned(),
            runtime_authority: self.authority.clone(),
            principal: self.principal.clone(),
            lineage: self.lineage.clone(),
            profile_id: self.profile_id.clone(),
            schema_hash: self.schema_hash.clone(),
            capability_digest: self.capability_digest.clone(),
        }
    }

    pub fn scope(&self, reference: &StoredConversationReference) -> ReplayScopeKey {
        ReplayScopeKey {
            runtime_authority: self.authority.clone(),
            principal: self.principal.clone(),
            lineage: self.lineage.clone(),
            scope: format!("conversation:{}", reference.conversation_id()),
            binding_digest: self.binding_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationProjection {
    schema_version: u32,
    conversation_id: String,
    workspace_id: String,
    projection_revision: u64,
    stream_version: u64,
    messages: Vec<ConversationMessageSummary>,
    closed: bool,
}

impl StoredConversationProjection {
    fn empty(reference: &StoredConversationReference) -> Self {
        Self {
            schema_version: PROJECTION_SCHEMA_VERSION,
            conversation_id: reference.conversation_id().to_string(),
            workspace_id: reference.workspace_id().to_string(),
            projection_revision: 0,
            stream_version: 0,
            messages: Vec::new(),
            closed: false,
        }
    }

    fn snapshot(self) -> ConversationSnapshot {
        ConversationSnapshot {
            conversation_id: self.conversation_id,
            projection_revision: self.projection_revision,
            stream_version: self.stream_version,
            messages: self.messages,
            recovery: ConversationRecoveryDisposition::Live,
        }
    }
}
