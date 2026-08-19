use std::{
    cell::Cell,
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use super::*;
use crate::{
    PluginAuthorityPort, PluginAuthorityRegistry, PluginClass, PluginGenerationPortError,
    PluginHookClockPort, PluginHookDefinition, PluginHookDescriptorAuthorityPort,
    PluginHookDispatchAuthorityPort, PluginHookDispatchError, PluginHookDispatchJournal,
    PluginHookDispatchJournalError, PluginHookDispatchJournalKey, PluginHookDispatchJournalResult,
    PluginHookDisposition, PluginHookFailurePolicy, PluginHookId, PluginHookInvocation,
    PluginHookInvocationId, PluginProcessPortError, PluginToolDescriptor,
    PluginToolDescriptorAuthorityPort, PluginTransportPortError, activate_plugin_tools,
    dispatch_hooks, verify_plugin_hook_descriptors, verify_plugin_tool_descriptors,
};
use runne_plugin_protocol::bootstrap::{HostExecutionIdentity, PluginHello};
use runne_plugin_protocol::digest::ProfileDigest;
use runne_plugin_protocol::id::{PluginId, PluginIdentity, ProfileId};
use runne_plugin_protocol::profile::{BoundedProfileRefVec, ProtocolProfileRef};
use runne_tools::{
    EffectAdmission, GateStage, ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort,
    ToolDispatchRequest, ToolExecutionHandle, ToolExecutorError, ToolExecutorPort, ToolGateway,
    ToolId, ToolOutputBounds, ToolVersion,
};
use serde_json::json;

type SharedHookRecord = ([u8; 32], Option<PluginHookDisposition>);
type SharedHookRecords = BTreeMap<PluginHookDispatchJournalKey, SharedHookRecord>;

#[derive(Default)]
struct SharedHookJournal {
    records: Mutex<SharedHookRecords>,
    prior_owner_fenced: Mutex<bool>,
}

impl SharedHookJournal {
    fn fence_prior_owner_for_recovery(&self) {
        *self.prior_owner_fenced.lock().unwrap() = true;
    }
}

impl PluginHookDispatchJournal for SharedHookJournal {
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
    ) -> Result<Option<crate::PluginHookRecoveredDispatch>, PluginHookDispatchJournalError> {
        if !*self
            .prior_owner_fenced
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?
        {
            return Ok(None);
        }
        let records = self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?;
        Ok(records
            .iter()
            .find(|(_, (_, outcome))| outcome.is_none())
            .map(|(key, (digest, _))| {
                crate::PluginHookRecoveredDispatch::new(key.clone(), *digest, [0xa5; 32])
            }))
    }

    fn quarantine_recovered(
        &self,
        recovered: &crate::PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchJournalError> {
        if !*self
            .prior_owner_fenced
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?
            || recovered.recovery_token() != &[0xa5; 32]
        {
            return Err(PluginHookDispatchJournalError::Conflict);
        }
        self.complete(
            recovered.key(),
            *recovered.request_digest(),
            PluginHookDisposition::Uncertain,
        )
    }
}

struct AllowToolAdmission;

impl ToolAdmissionPort for AllowToolAdmission {
    fn check(
        &self,
        stage: GateStage,
        _: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        Ok(if stage == GateStage::EffectAdmission {
            ToolAdmissionDecision::Winner(EffectAdmission {
                permit_id: "plugin-tool-permit".into(),
            })
        } else {
            ToolAdmissionDecision::Passed
        })
    }
}

struct CountingToolExecutor {
    starts: Arc<Mutex<usize>>,
}

impl ToolExecutorPort for CountingToolExecutor {
    type CompletionMode = runne_tools::NoTerminalCompletion;

    fn start(
        &self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError> {
        assert_eq!(admission.permit_id, "plugin-tool-permit");
        assert_eq!(
            request.binding.generation(),
            PluginGeneration::INITIAL.get()
        );
        *self.starts.lock().unwrap() += 1;
        Ok(ToolExecutionHandle {
            execution_id: "plugin-tool-execution".into(),
        })
    }

    fn signal_cancel(&self, _: &ToolExecutionHandle) -> Result<(), ToolExecutorError> {
        Ok(())
    }
}

include!("tests/part1.rs");
include!("tests/part2.rs");
include!("tests/part3.rs");
include!("tests/part4.rs");
include!("tests/part5.rs");
include!("tests/part6.rs");
include!("tests/part7.rs");
include!("tests/part8.rs");
include!("tests/part9.rs");
include!("tests/part10.rs");
include!("tests/part11.rs");
include!("tests/part12.rs");
include!("tests/part13.rs");
include!("tests/part14.rs");
