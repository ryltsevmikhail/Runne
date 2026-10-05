use runne_application::ports::{ApplicationCommandContext, PrincipalId};
use runne_domain::event::Actor;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
use runne_domain::id::{AttemptId, CycleId, TaskRunId};
use runne_domain::id::{CommandId, IdempotencyKey};
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
use sha2::{Digest, Sha256};

impl super::DaemonAutomaticTaskRuns {
    pub(in crate::application) fn command_context(
        principal: PrincipalId,
        actor: Actor,
    ) -> ApplicationCommandContext {
        let nonce = uuid::Uuid::now_v7();
        ApplicationCommandContext {
            command_id: CommandId::from_bytes(*nonce.as_bytes()),
            idempotency_key: IdempotencyKey::new(format!("taskrun-worker-{nonce}")).unwrap(),
            principal_id: principal,
            actor,
        }
    }

    pub(in crate::application) fn runtime_context() -> ApplicationCommandContext {
        Self::command_context(
            PrincipalId("runne-runtime".into()),
            Actor::new("runne-runtime").expect("static actor is valid"),
        )
    }

    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    pub(in crate::application) fn d2_command_context(
        principal: PrincipalId,
        actor: Actor,
        taskrun: TaskRunId,
        attempt: AttemptId,
        cycle: Option<CycleId>,
        operation: &str,
        proposal_index: Option<u32>,
    ) -> ApplicationCommandContext {
        let mut hash = Sha256::new();
        hash.update(b"RUNNE_D2_COMMAND_CONTEXT_V1\0");
        hash.update(taskrun.as_bytes());
        hash.update(attempt.as_bytes());
        if let Some(cycle) = cycle {
            hash.update(cycle.as_bytes());
        } else {
            hash.update([0; 16]);
        }
        hash.update((operation.len() as u64).to_be_bytes());
        hash.update(operation.as_bytes());
        hash.update(proposal_index.unwrap_or(u32::MAX).to_be_bytes());
        let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().expect("fixed digest");
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let command_id = CommandId::from_bytes(bytes);
        let idempotency_key = IdempotencyKey::new(format!("taskrun-d2-{}", hex::encode(bytes)))
            .expect("bounded deterministic idempotency key");
        ApplicationCommandContext {
            command_id,
            idempotency_key,
            principal_id: principal,
            actor,
        }
    }
}
