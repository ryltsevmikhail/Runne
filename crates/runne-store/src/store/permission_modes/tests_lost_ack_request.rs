//! Test-only receipt lookup data. Never a serialized native owner or approval.
use crate::codec::{IdempotencyScopeCodec, StoreCodec};
use crate::store::StoreTransaction;
use runne_application::{
    fingerprint::CommandFingerprint,
    ports::{AggregateScope, CommandCommit, CommitError, IdempotencyScope, ReceiptLookup, RuntimeAuthorityId, UnitOfWork},
};
use runne_domain::id::{CommandId, IdempotencyKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    version: u8,
    run: [u8; 16],
    command: [u8; 16],
    key: String,
    scope: Vec<u8>,
    fingerprint: [u8; 32],
}

impl Request {
    pub(super) fn of(payload: &CommandCommit, run: [u8; 16]) -> Self {
        Self {
            version: 1,
            run,
            command: *payload.command_id.as_bytes(),
            key: payload.idempotency_key.as_str().into(),
            scope: IdempotencyScopeCodec.encode(&payload.idempotency_scope).unwrap(),
            fingerprint: *payload.command_fingerprint.as_bytes(),
        }
    }

    pub(super) fn decode(bytes: &[u8], run: &[u8; 16]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 16_384 {
            return Err("request size");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "request encoding")?;
        if value.version != 1 || &value.run != run || value.scope.len() > 4096 {
            return Err("request context");
        }
        runne_domain::id::validate_uuid_v7_bytes(&value.command).map_err(|_| "command identity")?;
        IdempotencyKey::new(value.key.clone()).map_err(|_| "request key")?;
        let scope = IdempotencyScopeCodec.decode(&value.scope).map_err(|_| "request scope")?;
        let check = |id: &[u8; 16]| {
            runne_domain::id::validate_uuid_v7_bytes(id).map_err(|_| "aggregate identity")
        };
        match &scope.aggregate_scope {
            AggregateScope::ExistingTaskRun { taskrun_id } => check(taskrun_id.as_bytes())?,
            AggregateScope::ExistingConversation { conversation_id } => check(conversation_id.as_bytes())?,
            AggregateScope::NewTaskRun { conversation_id, workspace_id }
            | AggregateScope::NewConversation { conversation_id, workspace_id } => {
                check(conversation_id.as_bytes())?;
                check(workspace_id.as_bytes())?;
            }
        }
        if IdempotencyScopeCodec.encode(&scope).map_err(|_| "request scope")? != value.scope {
            return Err("noncanonical scope");
        }
        Ok(value)
    }

    // The fresh process must separately validate authority/lineage/trust and
    // byte-identical original request. This helper grants no process capability.
    pub(super) fn lookup(
        &self,
        store: &StoreTransaction,
        authority: &RuntimeAuthorityId,
    ) -> Result<ReceiptLookup, CommitError> {
        let scope: IdempotencyScope = IdempotencyScopeCodec.decode(&self.scope)
            .expect("only validated immutable request");
        assert_eq!(&scope.runtime_authority_id, authority);
        store.lookup_receipt(
            CommandId::from_bytes(self.command),
            &IdempotencyKey::new(self.key.clone()).unwrap(),
            &scope,
            &CommandFingerprint::from_bytes(self.fingerprint),
        )
    }
}

#[path = "tests_lost_ack_request_tests.rs"]
mod tests;

#[path = "tests_lost_ack_lookup_tests.rs"]
mod lookup_tests;
