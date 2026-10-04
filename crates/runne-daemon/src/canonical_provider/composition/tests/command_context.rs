use runne_application::ports::{ApplicationCommandContext, PrincipalId};
use runne_domain::{event::Actor, id::IdempotencyKey};

pub(super) fn command_context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("test").unwrap(),
    }
}
