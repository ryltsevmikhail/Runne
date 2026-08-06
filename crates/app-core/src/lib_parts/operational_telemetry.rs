pub const HOST_LIFECYCLE_CHANNEL_CAPACITY_V1: usize = 64;
pub const HOST_LIFECYCLE_RING_CAPACITY_V1: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostLifecycleEventStatusV1 {
    CompleteSinceAppCoreStart,
    TruncatedSinceAppCoreStart,
    Unavailable,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostLifecycleCurrentV1 {
    lifecycle: RuntimeLifecycleStatus,
    failure: Option<RuntimeFailureCode>,
    restart_ordinal: Option<u64>,
    runtime_launch_generation: Option<u64>,
    observed_at_unix_seconds: u64,
}

impl HostLifecycleCurrentV1 {
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

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTelemetrySectionV1 {
    meta: TelemetrySectionMetaV1,
    snapshot: Option<RuntimeOperationalTelemetrySnapshotV1>,
}

impl RuntimeTelemetrySectionV1 {
    #[must_use]
    pub const fn meta(&self) -> &TelemetrySectionMetaV1 {
        &self.meta
    }
    #[must_use]
    pub const fn snapshot(&self) -> Option<&RuntimeOperationalTelemetrySnapshotV1> {
        self.snapshot.as_ref()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostLifecycleTelemetryV1 {
    meta: TelemetrySectionMetaV1,
    runtime_mode: RuntimeMode,
    current: Option<HostLifecycleCurrentV1>,
    events: Option<Vec<HostLifecycleEventV1>>,
    event_status: HostLifecycleEventStatusV1,
    last_allocated_sequence: Option<u64>,
    producer_dropped_event_count: u64,
    producer_drop_counter_saturated: bool,
    evicted_event_count: u64,
    eviction_counter_saturated: bool,
}

impl HostLifecycleTelemetryV1 {
    #[must_use]
    pub const fn meta(&self) -> &TelemetrySectionMetaV1 {
        &self.meta
    }
    #[must_use]
    pub const fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }
    #[must_use]
    pub const fn current(&self) -> Option<&HostLifecycleCurrentV1> {
        self.current.as_ref()
    }
    #[must_use]
    pub const fn events(&self) -> Option<&Vec<HostLifecycleEventV1>> {
        self.events.as_ref()
    }
    #[must_use]
    pub const fn event_status(&self) -> HostLifecycleEventStatusV1 {
        self.event_status
    }
    #[must_use]
    pub const fn last_allocated_sequence(&self) -> Option<u64> {
        self.last_allocated_sequence
    }
    #[must_use]
    pub const fn producer_dropped_event_count(&self) -> u64 {
        self.producer_dropped_event_count
    }
    #[must_use]
    pub const fn producer_drop_counter_saturated(&self) -> bool {
        self.producer_drop_counter_saturated
    }
    #[must_use]
    pub const fn evicted_event_count(&self) -> u64 {
        self.evicted_event_count
    }
    #[must_use]
    pub const fn eviction_counter_saturated(&self) -> bool {
        self.eviction_counter_saturated
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalTelemetrySnapshotV1 {
    schema_version: u32,
    observed_at_unix_seconds: u64,
    runtime: RuntimeTelemetrySectionV1,
    host_lifecycle: HostLifecycleTelemetryV1,
}

impl OperationalTelemetrySnapshotV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeTelemetrySectionV1 {
        &self.runtime
    }
    #[must_use]
    pub const fn host_lifecycle(&self) -> &HostLifecycleTelemetryV1 {
        &self.host_lifecycle
    }
}

struct HostLifecycleState {
    current: Option<HostLifecycleCurrentV1>,
    restart_ordinal: Option<u64>,
    last_allocated_sequence: Option<u64>,
    event_pipeline_unavailable: bool,
}

impl HostLifecycleState {
    const fn new(mode: RuntimeMode) -> Self {
        let (lifecycle, restart_ordinal, generation) = match mode {
            RuntimeMode::ExternalLocal => (RuntimeLifecycleStatus::External, None, None),
            RuntimeMode::Bundled => (RuntimeLifecycleStatus::Starting, Some(0), Some(0)),
        };
        Self {
            current: Some(HostLifecycleCurrentV1 {
                lifecycle,
                failure: None,
                restart_ordinal,
                runtime_launch_generation: generation,
                observed_at_unix_seconds: 0,
            }),
            restart_ordinal,
            last_allocated_sequence: None,
            event_pipeline_unavailable: false,
        }
    }

    const fn current(&self) -> Option<&HostLifecycleCurrentV1> {
        self.current.as_ref()
    }

    fn validate(
        lifecycle: RuntimeLifecycleStatus,
        failure: Option<RuntimeFailureCode>,
        generation: Option<u64>,
        mode: RuntimeMode,
    ) -> Result<(), AppCoreError> {
        let failure_valid = match lifecycle {
            RuntimeLifecycleStatus::ConfigurationRequired => {
                failure == Some(RuntimeFailureCode::ConfigurationRequired)
            }
            RuntimeLifecycleStatus::Starting
            | RuntimeLifecycleStatus::Ready
            | RuntimeLifecycleStatus::Restarting
            | RuntimeLifecycleStatus::External => failure.is_none(),
            RuntimeLifecycleStatus::Degraded | RuntimeLifecycleStatus::Failed => true,
        };
        let mode_valid = match mode {
            RuntimeMode::ExternalLocal => {
                lifecycle == RuntimeLifecycleStatus::External && generation.is_none()
            }
            RuntimeMode::Bundled => {
                lifecycle != RuntimeLifecycleStatus::External && generation.is_some()
            }
        };
        if failure_valid && mode_valid {
            Ok(())
        } else {
            Err(AppCoreError::StateUnavailable)
        }
    }

    fn tuple_changed(
        &self,
        lifecycle: RuntimeLifecycleStatus,
        failure: Option<RuntimeFailureCode>,
        generation: Option<u64>,
    ) -> bool {
        self.current.as_ref().is_none_or(|current| {
            current.lifecycle != lifecycle
                || current.failure != failure
                || current.runtime_launch_generation != generation
        })
    }

    fn next_restart_ordinal(
        &mut self,
        lifecycle: RuntimeLifecycleStatus,
    ) -> Result<Option<u64>, AppCoreError> {
        if self.restart_ordinal.is_some()
            && lifecycle == RuntimeLifecycleStatus::Restarting
            && self
                .current
                .as_ref()
                .is_none_or(|current| current.lifecycle != lifecycle)
        {
            let next = self.restart_ordinal.and_then(|ordinal| ordinal.checked_add(1));
            if next.is_none() {
                return Err(AppCoreError::StateUnavailable);
            }
            self.restart_ordinal = next;
        }
        Ok(self.restart_ordinal)
    }

    fn allocate_sequence(&mut self) -> Result<u64, AppCoreError> {
        let next = self
            .last_allocated_sequence
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(AppCoreError::StateUnavailable)?;
        self.last_allocated_sequence = Some(next);
        Ok(next)
    }
}
