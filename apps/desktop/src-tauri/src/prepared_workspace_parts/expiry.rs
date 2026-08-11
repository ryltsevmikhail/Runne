impl PreparedWorkspaceManager {
    pub(super) fn start_expiry_sweeper(
        &self,
        state: &mut DirectorySelectionState,
    ) -> Result<(), SelectionError> {
        if state.expiry_sweeper_running {
            return Ok(());
        }
        #[cfg(test)]
        if state.expiry_sweeper_start_fails_for_test {
            return Err(SelectionError);
        }
        let sweep_state = std::sync::Arc::clone(&self.state);
        if std::thread::Builder::new()
            .name("gocode-prepared-expiry".into())
            .spawn(move || {
                loop {
                    let deadline = match sweep_state.lock() {
                        Ok(mut state) => {
                            let now = std::time::Instant::now();
                            state.prepared.retain(|_, entry| entry.expires_at > now);
                            state.reservations.retain(|_, entry| entry.expires_at > now);
                            let deadline = state
                                .prepared
                                .values()
                                .map(|entry| entry.expires_at)
                                .chain(state.reservations.values().map(|entry| entry.expires_at))
                                .min();
                            if deadline.is_none() {
                                state.expiry_sweeper_running = false;
                            }
                            deadline
                        }
                        Err(_) => return,
                    };
                    let Some(deadline) = deadline else {
                        return;
                    };
                    std::thread::sleep(
                        deadline.saturating_duration_since(std::time::Instant::now()),
                    );
                }
            })
            .is_err()
        {
            return Err(SelectionError);
        }
        state.expiry_sweeper_running = true;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod expiry_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_spawn_failure_rejects_every_reservation_and_allows_recovery() {
        let selections = crate::directory_selection::DirectorySelectionManager::new(
            std::time::Duration::from_millis(1),
        )
        .unwrap();
        let prepared = selections.prepared_workspaces();
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap();
        prepared
            .state
            .lock()
            .unwrap()
            .expiry_sweeper_start_fails_for_test = true;
        let barrier = Arc::new(Barrier::new(3));
        let reserve = |request| {
            let prepared = prepared.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                prepared.reserve(
                    PreparedWorkspaceBinding::new(
                        "main",
                        1,
                        request,
                        WorkspaceId::from_bytes([4; 16]),
                        1,
                    )
                    .unwrap(),
                    std::time::Instant::now(),
                )
            })
        };
        let first = reserve("first");
        let second = reserve("second");
        barrier.wait();
        assert!(first.join().unwrap().is_err());
        assert!(second.join().unwrap().is_err());
        let state = prepared.state.lock().unwrap();
        assert!(state.reservations.is_empty());
        assert!(state.prepared.is_empty());
        assert!(!state.expiry_sweeper_running);
        drop(state);
        prepared
            .state
            .lock()
            .unwrap()
            .expiry_sweeper_start_fails_for_test = false;
        let reference = prepared
            .reserve(
                PreparedWorkspaceBinding::new(
                    "main",
                    1,
                    "recovered",
                    WorkspaceId::from_bytes([4; 16]),
                    1,
                )
                .unwrap(),
                std::time::Instant::now(),
            )
            .unwrap();
        assert!(prepared.state.lock().unwrap().expiry_sweeper_running);
        prepared.cancel(&reference);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!prepared.state.lock().unwrap().expiry_sweeper_running);
    }
}
