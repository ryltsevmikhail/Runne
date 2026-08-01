//! Runtime ownership for plugin and MCP root futures.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::task::{AbortHandle, Id, JoinSet};
use tokio_util::sync::CancellationToken;

/// Runtime-owned extension root class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionRootKind {
    /// Out-of-process plugin host root.
    Plugin,
    /// Contained local MCP root.
    McpLocal,
    /// Brokered remote MCP root.
    McpRemote,
}

/// Exact root ownership binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRootBinding {
    root_id: String,
    kind: ExtensionRootKind,
    generation: u64,
    authority_digest: [u8; 32],
}

impl ExtensionRootBinding {
    /// Captures a bounded, generation-bound root identity.
    pub fn new(
        root_id: impl Into<String>,
        kind: ExtensionRootKind,
        generation: u64,
        authority_digest: [u8; 32],
    ) -> Result<Self, ExtensionSupervisorError> {
        let root_id = root_id.into();
        if root_id.is_empty()
            || root_id.len() > 128
            || !root_id.bytes().all(|byte| byte.is_ascii_graphic())
            || generation == 0
            || authority_digest == [0; 32]
        {
            return Err(ExtensionSupervisorError::InvalidBinding);
        }
        Ok(Self {
            root_id,
            kind,
            generation,
            authority_digest,
        })
    }
}

/// Proof passed only after the root is present in the supervisor registry.
#[derive(Debug)]
pub struct RuntimeRootLease {
    root_id: String,
    kind: ExtensionRootKind,
    generation: u64,
    authority_digest: [u8; 32],
    registration: Arc<AtomicBool>,
}

impl RuntimeRootLease {
    /// Whether this lease was issued after successful pre-registration.
    pub fn is_registered(&self) -> bool {
        self.registration.load(Ordering::Acquire)
    }
}

/// Root future exit classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionRootExit {
    /// Backend and cleanup reached terminal state.
    Terminal,
    /// Teardown or external state remains ambiguous.
    Uncertain,
}

/// Runtime supervisor root state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionRootState {
    /// Root is registered and may be polled.
    Running,
    /// Generation/containment loss fenced and cancelled the root.
    Fenced,
    /// Runtime drain cancelled the root.
    Draining,
    /// Root returned complete terminal evidence.
    Terminal,
    /// Root teardown remains ambiguous.
    Uncertain,
}

/// Port that provides an already-composed root future without exposing raw
/// process, SDK or transport handles to the runtime.
pub trait ExtensionRootPort: Send + Sync + 'static {
    /// Runs until cancellation or a backend-owned terminal disposition.
    fn run(
        self: Arc<Self>,
        lease: RuntimeRootLease,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ExtensionRootExit> + Send + 'static>>;
}

/// Runtime ownership failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionSupervisorError {
    /// Binding was empty, unbounded or not generation-bound.
    InvalidBinding,
    /// Root identity was already registered.
    DuplicateRoot,
    /// Requested root was not registered.
    RootNotFound,
    /// Root task failed outside its typed exit contract.
    TaskFailed,
}

struct RootRecord {
    binding: ExtensionRootBinding,
    state: ExtensionRootState,
    cancellation: CancellationToken,
    abort_handle: Option<AbortHandle>,
    _registration: Arc<AtomicBool>,
}

/// Joined root receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRootReceipt {
    root_id: String,
    state: ExtensionRootState,
}

impl ExtensionRootReceipt {
    /// Stable root identity.
    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    /// Terminal or uncertain joined state.
    pub const fn state(&self) -> ExtensionRootState {
        self.state
    }
}

/// Owns plugin/MCP root futures and their cancellation lifecycle.
pub struct RuntimeExtensionSupervisor {
    roots: BTreeMap<String, RootRecord>,
    tasks: JoinSet<(String, ExtensionRootExit)>,
    task_roots: HashMap<Id, String>,
}

include!("plugin_host/supervisor.rs");
