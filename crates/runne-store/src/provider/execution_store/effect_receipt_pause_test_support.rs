use std::sync::Arc;

use super::SqliteProviderExecutionStore;

impl SqliteProviderExecutionStore {
    pub(super) fn pause_next_effect_receipt_lock(
        &self,
    ) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *self.effect_receipt_pause.lock().unwrap() =
            Some((Arc::clone(&reached), Arc::clone(&release)));
        (reached, release)
    }
}
