use super::{DaemonError, StoreTransaction};
use runne_application::local_session::LocalSessionService;
use runne_store::execution_node::{LinuxNodeDescriptor, NodeRegistryError};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NODE_TTL_SECONDS: u32 = 30;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub(super) struct LinuxExecutionNode {
    authority_id: [u8; 16],
    daemon_instance_id: [u8; 16],
    launch_generation: u64,
    registered: bool,
}

impl LinuxExecutionNode {
    pub(super) const fn new(
        authority_id: [u8; 16],
        daemon_instance_id: [u8; 16],
        launch_generation: u64,
    ) -> Self {
        Self {
            authority_id,
            daemon_instance_id,
            launch_generation,
            registered: false,
        }
    }

    pub(super) fn register(
        &mut self,
        store: &StoreTransaction,
        sessions: &Arc<Mutex<LocalSessionService>>,
    ) -> Result<(), DaemonError> {
        self.reconcile(store, sessions)
    }

    pub(super) async fn run_until_shutdown<F>(
        self,
        store: StoreTransaction,
        sessions: Arc<Mutex<LocalSessionService>>,
        shutdown: F,
    ) -> Result<(), DaemonError>
    where
        F: Future<Output = Result<(), DaemonError>>,
    {
        self.run_with_interval(store, sessions, shutdown, HEARTBEAT_INTERVAL)
            .await
    }

    async fn run_with_interval<F>(
        mut self,
        store: StoreTransaction,
        sessions: Arc<Mutex<LocalSessionService>>,
        shutdown: F,
        interval: Duration,
    ) -> Result<(), DaemonError>
    where
        F: Future<Output = Result<(), DaemonError>>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = &mut shutdown => return result,
                () = tokio::time::sleep(interval) => {
                    self.reconcile(&store, &sessions)?;
                }
            }
        }
    }

    fn reconcile(
        &mut self,
        store: &StoreTransaction,
        sessions: &Arc<Mutex<LocalSessionService>>,
    ) -> Result<(), DaemonError> {
        let sessions = sessions.lock().map_err(|_| {
            DaemonError::Bootstrap("Linux execution node session unavailable".into())
        })?;
        let binding = sessions.current_binding();
        let generation = binding.ephemeral().launch_generation();
        if binding.stable().authority_id() != &self.authority_id
            || binding.ephemeral().daemon_instance_id().into_bytes() != self.daemon_instance_id
            || generation < self.launch_generation
        {
            return Err(DaemonError::Bootstrap(
                "Linux execution node session ownership changed".into(),
            ));
        }
        if self.registered && generation == self.launch_generation {
            match store.heartbeat_local_linux_node(self.authority_id, generation, NODE_TTL_SECONDS)
            {
                Ok(()) => Ok(()),
                Err(NodeRegistryError::StaleEpoch)
                    if pending_successor_is_current(store, &sessions, generation) =>
                {
                    Ok(())
                }
                Err(error) => Err(registry_error(error)),
            }
        } else {
            match store.register_local_linux_node(
                self.authority_id,
                generation,
                LinuxNodeDescriptor { capacity: 1 },
                NODE_TTL_SECONDS,
            ) {
                Ok(_) => {
                    self.launch_generation = generation;
                    self.registered = true;
                    Ok(())
                }
                Err(NodeRegistryError::StaleEpoch)
                    if pending_successor_is_current(store, &sessions, generation) =>
                {
                    Ok(())
                }
                Err(error) => Err(registry_error(error)),
            }
        }
    }
}

fn pending_successor_is_current(
    store: &StoreTransaction,
    sessions: &LocalSessionService,
    generation: u64,
) -> bool {
    generation
        .checked_add(1)
        .zip(sessions.pending_protected_enrollment_generation())
        .is_some_and(|(expected, pending)| {
            expected == pending
                && store
                    .validate_unconsumed_enrollment_launch_generation(pending)
                    .is_ok()
        })
}

fn registry_error(error: NodeRegistryError) -> DaemonError {
    DaemonError::Bootstrap(format!("Linux execution node lifecycle: {error}"))
}

#[cfg(test)]
#[path = "execution_node_lifecycle_tests.rs"]
mod tests;
