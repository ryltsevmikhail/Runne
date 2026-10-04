use runne_application::ports::{ApplicationCommandContext, PrincipalId};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey};

impl super::DaemonAutomaticTaskRuns {
    pub(super) fn command_context(
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
}
