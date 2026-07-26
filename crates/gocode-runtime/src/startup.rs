//! Runtime startup — composes gate, channels, supervisor, handle, controller.

use std::marker::PhantomData;
use std::sync::Arc;

use gocode_application::ports::{EventStore, IdGenerator, UnitOfWork};
use gocode_application::service::TaskRunService;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::config::{RuntimeConfig, RuntimeStartError};
use crate::controller::{ControlCommand, RuntimeController, ShutdownOutcome};
use crate::gate::AdmissionGate;
use crate::handle::RuntimeHandle;

/// Identifies a specific runtime generation (instance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeGenerationId(pub u64);

/// Proof that a Tokio runtime handle is valid and borrowed by the caller.
///
/// Carries a phantom lifetime to ensure the Tokio runtime outlives the
/// GOCODE runtime. Not a real resource — just a compile-time guard.
#[derive(Debug)]
pub struct TokioRuntimeContext {
    /// The generation ID for this runtime instance.
    pub generation: RuntimeGenerationId,
    /// A handle to the Tokio runtime for spawning tasks.
    pub executor: tokio::runtime::Handle,
    /// Phantom proof of borrow (caller holds the real Tokio runtime).
    pub lease: BorrowedLease,
}

/// Opaque token proving the caller holds a reference to a Tokio runtime.
///
/// Contains a `PhantomData<&'static ()>` to be `Send + Sync` without `unsafe impl`.
/// Construction requires no actual data — use `BorrowedLease { _phantom: PhantomData }`.
#[derive(Debug)]
pub struct BorrowedLease {
    /// Public for construction by integration tests. Type is `Send + Sync`,
    /// so `BorrowedLease` automatically implements `Send + Sync` safely.
    pub _phantom: PhantomData<&'static ()>,
}

/// The GOCODE runtime — stateless entry point for composition.
pub struct Runtime;

impl Runtime {
    /// Start a borrowed GOCODE runtime on the given Tokio executor.
    ///
    /// Returns a cloneable [`RuntimeHandle`] for submitting commands,
    /// and a [`RuntimeController`] for initiating shutdown.
    ///
    /// The runtime runs as a background task spawned on `ctx.executor`.
    /// It does not capture the ambient Tokio runtime.
    pub fn start_borrowed<E, U, I>(
        ctx: TokioRuntimeContext,
        service: Arc<TaskRunService<E, U, I>>,
        config: RuntimeConfig,
    ) -> Result<(RuntimeHandle, RuntimeController), RuntimeStartError>
    where
        E: EventStore + Send + Sync + 'static,
        U: UnitOfWork + Send + Sync + 'static,
        I: IdGenerator + Send + Sync + 'static,
    {
        config.validate()?;

        // Create channels
        let (ingress_tx, ingress_rx) =
            mpsc::channel::<crate::types::AdmittedRequest>(config.ingress_capacity);
        let (control_tx, control_rx) = mpsc::channel::<ControlCommand>(16);
        let (drain_complete_tx, drain_complete_rx) = oneshot::channel::<ShutdownOutcome>();

        // Create gate and in-flight semaphore
        let gate = Arc::new(AdmissionGate::new(config.max_in_flight_requests));
        let in_flight_sem = Arc::new(Semaphore::new(config.max_in_flight_requests));

        // Cancellation token for workers
        let cancel = tokio_util::sync::CancellationToken::new();

        // Build handle and controller
        let handle = RuntimeHandle::new(
            ingress_tx,
            Arc::clone(&gate),
            Arc::clone(&in_flight_sem),
        );
        let controller = RuntimeController::new(control_tx, drain_complete_rx);

        // Spawn supervisor on the provided executor
        let gate2 = Arc::clone(&gate);
        let config2 = config.clone();
        let cancel2 = cancel.clone();
        ctx.executor.spawn(async move {
            crate::supervisor::run_supervisor(
                ingress_rx,
                control_rx,
                gate2,
                config2,
                cancel2,
                service,
                drain_complete_tx,
            )
            .await;
        });

        Ok((handle, controller))
    }
}
