use std::sync::Arc;

/// Serializes a provider operation across admission, delivery and settlement.
#[derive(Clone, Default)]
pub(super) struct ProviderDispatchGate(Arc<tokio::sync::Mutex<()>>);

impl ProviderDispatchGate {
    pub(super) async fn lock(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.0).lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderDispatchGate;

    #[tokio::test]
    async fn second_provider_operation_waits_until_first_settlement_releases_gate() {
        let gate = ProviderDispatchGate::default();
        let dispatch = gate.lock().await;
        let waiting_gate = gate.clone();
        let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel();
        let waiting_dispatch = tokio::spawn(async move {
            let _dispatch = waiting_gate.lock().await;
            let _ = entered_tx.send(());
        });

        tokio::task::yield_now().await;
        assert!(matches!(
            entered_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(dispatch);
        entered_rx.await.unwrap();
        waiting_dispatch.await.unwrap();
    }
}
