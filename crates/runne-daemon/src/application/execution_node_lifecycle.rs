use super::{DaemonError, StoreTransaction};
use runne_store::execution_node::{LinuxNodeDescriptor, NodeRegistryError};
use std::future::Future;
use std::time::Duration;

const NODE_TTL_SECONDS: u32 = 30;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub(super) struct LinuxExecutionNode {
    authority_id: [u8; 16],
    launch_generation: u64,
}

impl LinuxExecutionNode {
    pub(super) const fn new(authority_id: [u8; 16], launch_generation: u64) -> Self {
        Self {
            authority_id,
            launch_generation,
        }
    }

    pub(super) fn register(self, store: &StoreTransaction) -> Result<(), DaemonError> {
        store
            .register_local_linux_node(
                self.authority_id,
                self.launch_generation,
                LinuxNodeDescriptor { capacity: 1 },
                NODE_TTL_SECONDS,
            )
            .map(|_| ())
            .map_err(registry_error)
    }

    pub(super) async fn run_until_shutdown<F>(
        self,
        store: StoreTransaction,
        shutdown: F,
    ) -> Result<(), DaemonError>
    where
        F: Future<Output = Result<(), DaemonError>>,
    {
        self.run_with_interval(store, shutdown, HEARTBEAT_INTERVAL)
            .await
    }

    async fn run_with_interval<F>(
        self,
        store: StoreTransaction,
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
                    store.heartbeat_local_linux_node(
                        self.authority_id,
                        self.launch_generation,
                        NODE_TTL_SECONDS,
                    ).map_err(registry_error)?;
                }
            }
        }
    }
}

fn registry_error(error: NodeRegistryError) -> DaemonError {
    DaemonError::Bootstrap(format!("Linux execution node lifecycle: {error}"))
}
