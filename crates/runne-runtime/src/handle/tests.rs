//! Unit tests for the public runtime command handle.

use super::*;
use runne_application::commands::CreateTaskRunInput;
use runne_application::ports::{ApplicationCommandContext, PrincipalId};
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};

#[tokio::test(flavor = "current_thread")]
async fn admission_reservation_is_released_after_ingress_accepts_request() {
    let (sender, mut receiver) = mpsc::channel(1);
    let gate = Arc::new(AdmissionGate::new(1));
    let handle = RuntimeHandle::new(sender, Arc::clone(&gate), Arc::new(Semaphore::new(1)));

    let request = tokio::spawn(async move {
        handle
            .create_task_run(
                ApplicationCommandContext {
                    command_id: "018f2e3a-7000-7000-8000-000000000001".parse().unwrap(),
                    idempotency_key: IdempotencyKey::new("reservation-release").unwrap(),
                    principal_id: PrincipalId("test".to_owned()),
                    actor: Actor::new("test").unwrap(),
                },
                CreateTaskRunInput {
                    conversation_id: "018f2e3a-7000-7000-8000-00000000000a"
                        .parse::<ConversationId>()
                        .unwrap(),
                    workspace_id: "018f2e3a-7000-7000-8000-00000000000b"
                        .parse::<WorkspaceId>()
                        .unwrap(),
                },
            )
            .await
    });

    let admitted = receiver.recv().await.expect("request must reach ingress");
    let next_reservation = gate
        .try_reserve()
        .expect("accepted ingress must release its admission reservation");
    drop(next_reservation);

    let reply = match admitted.request {
        RuntimeRequest::Create { reply, .. } => reply,
        _ => panic!("test submits only create"),
    };
    reply.send(Err(RuntimeError::RuntimeClosed)).unwrap();
    drop(admitted.lease);

    assert_eq!(request.await.unwrap(), Err(RuntimeError::RuntimeClosed));
}
