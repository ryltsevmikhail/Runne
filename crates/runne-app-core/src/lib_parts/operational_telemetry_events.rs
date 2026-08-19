#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostLifecycleEventV1 {
    sequence: u64,
    lifecycle: RuntimeLifecycleStatus,
    failure: Option<RuntimeFailureCode>,
    restart_ordinal: Option<u64>,
    runtime_launch_generation: Option<u64>,
    observed_at_unix_seconds: u64,
}

impl HostLifecycleEventV1 {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn lifecycle(&self) -> RuntimeLifecycleStatus {
        self.lifecycle
    }
    #[must_use]
    pub const fn failure(&self) -> Option<RuntimeFailureCode> {
        self.failure
    }
    #[must_use]
    pub const fn restart_ordinal(&self) -> Option<u64> {
        self.restart_ordinal
    }
    #[must_use]
    pub const fn runtime_launch_generation(&self) -> Option<u64> {
        self.runtime_launch_generation
    }
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
}

struct HostLifecycleEventPipeline {
    receiver: tokio::sync::mpsc::Receiver<HostLifecycleEventV1>,
    events: VecDeque<HostLifecycleEventV1>,
}

impl HostLifecycleEventPipeline {
    const fn new(receiver: tokio::sync::mpsc::Receiver<HostLifecycleEventV1>) -> Self {
        Self {
            receiver,
            events: VecDeque::new(),
        }
    }
}
