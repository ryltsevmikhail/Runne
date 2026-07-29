use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use gocode_mcp::{
    McpSdkIntegrationEvidence, McpSdkIntegrationProfileId, McpSdkIntegrationProfileRef,
    PRODUCTION_MCP_SDK_ENABLED,
};
use gocode_runtime::{
    ExtensionRootBinding, ExtensionRootExit, ExtensionRootKind, ExtensionRootPort,
    ExtensionRootState, McpActivationError, McpActivationRequest, RuntimeExtensionSupervisor,
    RuntimeRootLease,
};
use tokio_util::sync::CancellationToken;

const _: () = assert!(!PRODUCTION_MCP_SDK_ENABLED);

struct Root {
    polled_with_registered_lease: Arc<AtomicBool>,
    exit: ExtensionRootExit,
}

impl ExtensionRootPort for Root {
    fn run(
        self: Arc<Self>,
        lease: RuntimeRootLease,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ExtensionRootExit> + Send + 'static>> {
        Box::pin(async move {
            self.polled_with_registered_lease
                .store(lease.is_registered(), Ordering::SeqCst);
            cancellation.cancelled().await;
            self.exit
        })
    }
}

struct PanicRoot;

impl ExtensionRootPort for PanicRoot {
    fn run(
        self: Arc<Self>,
        lease: RuntimeRootLease,
        _: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ExtensionRootExit> + Send + 'static>> {
        Box::pin(async move {
            assert!(lease.is_registered());
            panic!("simulated extension root panic");
        })
    }
}

fn binding(id: &str, kind: ExtensionRootKind, generation: u64) -> ExtensionRootBinding {
    ExtensionRootBinding::new(id, kind, generation, [generation as u8; 32]).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn roots_are_registered_before_poll_and_generation_or_containment_loss_cancels() {
    let observed = Arc::new(AtomicBool::new(false));
    let mut supervisor = RuntimeExtensionSupervisor::new();
    supervisor
        .register_root(
            binding("plugin-root", ExtensionRootKind::Plugin, 1),
            Arc::new(Root {
                polled_with_registered_lease: Arc::clone(&observed),
                exit: ExtensionRootExit::Terminal,
            }),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !observed.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(observed.load(Ordering::SeqCst));
    assert_eq!(
        supervisor.state("plugin-root"),
        Some(ExtensionRootState::Running)
    );

    supervisor.fence_stale_generations(2);
    let receipt = supervisor.join_next().await.unwrap();
    assert_eq!(receipt.root_id(), "plugin-root");
    assert_eq!(receipt.state(), ExtensionRootState::Terminal);

    let uncertain = Arc::new(AtomicBool::new(false));
    supervisor
        .register_root(
            binding("mcp-root", ExtensionRootKind::McpLocal, 2),
            Arc::new(Root {
                polled_with_registered_lease: Arc::clone(&uncertain),
                exit: ExtensionRootExit::Uncertain,
            }),
        )
        .unwrap();
    supervisor.containment_lost("mcp-root").unwrap();
    let receipt = supervisor.join_next().await.unwrap();
    assert_eq!(receipt.state(), ExtensionRootState::Uncertain);
}

#[tokio::test]
async fn drain_cancels_every_owned_root_and_preserves_uncertain_teardown() {
    let mut supervisor = RuntimeExtensionSupervisor::new();
    let observations = Arc::new(Mutex::new(Vec::new()));
    for (id, exit) in [
        ("plugin", ExtensionRootExit::Terminal),
        ("mcp-remote", ExtensionRootExit::Uncertain),
    ] {
        let observed = Arc::new(AtomicBool::new(false));
        observations.lock().unwrap().push(Arc::clone(&observed));
        supervisor
            .register_root(
                binding(
                    id,
                    if id == "plugin" {
                        ExtensionRootKind::Plugin
                    } else {
                        ExtensionRootKind::McpRemote
                    },
                    3,
                ),
                Arc::new(Root {
                    polled_with_registered_lease: observed,
                    exit,
                }),
            )
            .unwrap();
    }
    supervisor.begin_drain();
    let first = supervisor.join_next().await.unwrap();
    let second = supervisor.join_next().await.unwrap();
    assert!([first.state(), second.state()].contains(&ExtensionRootState::Uncertain));
    assert_eq!(supervisor.active_roots(), 0);
}

#[tokio::test]
async fn panic_and_forced_abort_preserve_root_identity_as_uncertain() {
    let mut supervisor = RuntimeExtensionSupervisor::new();
    supervisor
        .register_root(
            binding("panic-root", ExtensionRootKind::Plugin, 4),
            Arc::new(PanicRoot),
        )
        .unwrap();
    let panic_receipt = supervisor.join_next().await.unwrap();
    assert_eq!(panic_receipt.root_id(), "panic-root");
    assert_eq!(panic_receipt.state(), ExtensionRootState::Uncertain);
    assert_eq!(supervisor.active_roots(), 0);

    supervisor
        .register_root(
            binding("aborted-root", ExtensionRootKind::McpRemote, 4),
            Arc::new(Root {
                polled_with_registered_lease: Arc::new(AtomicBool::new(false)),
                exit: ExtensionRootExit::Terminal,
            }),
        )
        .unwrap();
    supervisor.abort_root("aborted-root").unwrap();
    let abort_receipt = supervisor.join_next().await.unwrap();
    assert_eq!(abort_receipt.root_id(), "aborted-root");
    assert_eq!(abort_receipt.state(), ExtensionRootState::Uncertain);
    assert_eq!(supervisor.active_roots(), 0);
}

#[test]
fn production_mcp_activation_is_structurally_disabled() {
    assert_eq!(
        McpActivationRequest::production(None, 1, true).activate(1),
        Err(McpActivationError::SdkProfileUnavailable)
    );

    assert_eq!(
        McpSdkIntegrationProfileRef::production(
            McpSdkIntegrationProfileId::new("candidate").unwrap(),
            1,
            McpSdkIntegrationEvidence {
                sdk_version: "2.3.0".into(),
                source_checksum: [1; 32],
                dependency_digest: [2; 32],
                protocol_version: "2025-11-25".into(),
                conformance_digest: [3; 32],
                behavior_evidence_digest: Some([4; 32]),
                platform_evidence_digest: Some([5; 32]),
                supply_chain_evidence_digest: Some([6; 32]),
            },
        ),
        Err(gocode_mcp::SdkProfileUnavailable)
    );
    assert_eq!(
        McpActivationRequest::production(None, 1, false).activate(1),
        Err(McpActivationError::SdkProfileUnavailable)
    );
    assert_eq!(
        McpActivationRequest::production(None, 1, true).activate(2),
        Err(McpActivationError::SdkProfileUnavailable)
    );
    assert_eq!(
        McpActivationRequest::production(None, 1, true).activate(1),
        Err(McpActivationError::SdkProfileUnavailable)
    );
}
