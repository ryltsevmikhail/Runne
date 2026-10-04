use std::sync::{Arc, atomic::Ordering};

use super::PausedEffect;
use super::claimed_fixture::claimed_job;
use super::support::compose_paused_openai;
use runne_runtime::canonical_provider_execution::CanonicalProviderExecutionService;
use runne_store::provider::ProviderDispatchState;

#[tokio::test(flavor = "current_thread")]
async fn unrevoked_direct_route_consumes_the_final_send_gate_once() {
    let effect = Arc::new(PausedEffect::default());
    let (harness, service) = compose_paused_openai(effect.clone()).await;
    let (job, _) = claimed_job(&harness, &service, None, 0xA3);
    let entered = effect.entered.notified();
    tokio::pin!(entered);
    let execution = Arc::clone(&service);
    let task = tokio::spawn(async move { execution.execute(job).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut entered)
        .await
        .expect("adapter pre-consume barrier");
    effect.release.add_permits(1);
    assert!(matches!(
        task.await.unwrap(),
        Err(crate::canonical_provider::CanonicalProviderExecutionError::Uncertain)
    ));
    assert_eq!(effect.consumes.load(Ordering::SeqCst), 1);
    assert_eq!(effect.sends.load(Ordering::SeqCst), 1);
    let attempt_id = effect.attempt.lock().unwrap().unwrap();
    let dispatch = service
        .dispatch_store
        .get_dispatch(attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(dispatch.state, ProviderDispatchState::Uncertain);
}
