impl AppCore {
    /// Returns the current operational telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AppCoreError::StateUnavailable`] when the lifecycle state
    /// cannot be locked or the runtime telemetry section cannot be composed.
    pub fn operational_telemetry_snapshot(
        &self,
        observed_at_unix_seconds: u64,
    ) -> Result<OperationalTelemetrySnapshotV1, AppCoreError> {
        let events = self.drain_lifecycle_events();
        let state = self
            .host_lifecycle
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let unavailable = state.event_pipeline_unavailable
            || self.lifecycle_pipeline_closed.load(Ordering::Acquire);
        let current = (!unavailable).then(|| state.current.clone()).flatten();
        let last_allocated_sequence = state.last_allocated_sequence;
        drop(state);
        let producer_dropped_event_count = self.lifecycle_producer_drops.load(Ordering::Acquire);
        let evicted_event_count = self.lifecycle_evictions.load(Ordering::Acquire);
        let event_status = match (unavailable, events.as_ref()) {
            (true, _) | (_, None) => HostLifecycleEventStatusV1::Unavailable,
            (false, Some(_)) if producer_dropped_event_count > 0 || evicted_event_count > 0 => {
                HostLifecycleEventStatusV1::TruncatedSinceAppCoreStart
            }
            (false, Some(_)) => HostLifecycleEventStatusV1::CompleteSinceAppCoreStart,
        };
        let completeness = match (&current, event_status) {
            (None, _) => TelemetryCompletenessV1::Unavailable,
            (Some(_), HostLifecycleEventStatusV1::CompleteSinceAppCoreStart) => {
                TelemetryCompletenessV1::Complete
            }
            (Some(_), _) => TelemetryCompletenessV1::Partial,
        };
        Ok(OperationalTelemetrySnapshotV1 {
            schema_version: 1,
            observed_at_unix_seconds,
            runtime: self.runtime_telemetry_section(observed_at_unix_seconds)?,
            host_lifecycle: HostLifecycleTelemetryV1 {
                meta: if unavailable {
                    unavailable_meta(observed_at_unix_seconds)?
                } else {
                    observed_meta(observed_at_unix_seconds, completeness)?
                },
                runtime_mode: self.runtime_mode,
                current,
                events: if unavailable { None } else { events },
                event_status,
                last_allocated_sequence,
                producer_dropped_event_count,
                producer_drop_counter_saturated: self
                    .lifecycle_producer_drop_saturated
                    .load(Ordering::Acquire),
                evicted_event_count,
                eviction_counter_saturated: self.lifecycle_eviction_saturated.load(Ordering::Acquire),
            },
        })
    }

    fn drain_lifecycle_events(&self) -> Option<Vec<HostLifecycleEventV1>> {
        let mut pipeline = self.lifecycle_event_pipeline.try_lock().ok()?;
        while let Ok(event) = pipeline.receiver.try_recv() {
            if pipeline.events.len() == HOST_LIFECYCLE_RING_CAPACITY_V1 {
                pipeline.events.pop_front();
                increment_counter(
                    &self.lifecycle_evictions,
                    &self.lifecycle_eviction_saturated,
                );
            }
            pipeline.events.push_back(event);
        }
        Some(pipeline.events.iter().cloned().collect())
    }

    fn runtime_telemetry_section(
        &self,
        observed_at_unix_seconds: u64,
    ) -> Result<RuntimeTelemetrySectionV1, AppCoreError> {
        let snapshot = self
            .runtime_client()?
            .and_then(fetch_runtime_telemetry_snapshot);
        let (freshness, completeness) = if snapshot.is_some() {
            (
                TelemetryFreshnessV1::ObservedInCurrentCycle,
                TelemetryCompletenessV1::Complete,
            )
        } else {
            (
                TelemetryFreshnessV1::Unavailable,
                TelemetryCompletenessV1::Unavailable,
            )
        };
        Ok(RuntimeTelemetrySectionV1 {
            meta: TelemetrySectionMetaV1::new(observed_at_unix_seconds, freshness, completeness)
                .map_err(|_| AppCoreError::StateUnavailable)?,
            snapshot,
        })
    }

}

fn fetch_runtime_telemetry_snapshot(
    client: AuthenticatedRuntimeClient,
) -> Option<RuntimeOperationalTelemetrySnapshotV1> {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?
            .block_on(client.operational_telemetry())
            .ok()
    })
    .join()
    .ok()
    .flatten()
}

fn observed_meta(
    observed_at_unix_seconds: u64,
    completeness: TelemetryCompletenessV1,
) -> Result<TelemetrySectionMetaV1, AppCoreError> {
    TelemetrySectionMetaV1::new(
        observed_at_unix_seconds,
        TelemetryFreshnessV1::ObservedInCurrentCycle,
        completeness,
    )
    .map_err(|_| AppCoreError::StateUnavailable)
}

fn unavailable_meta(
    observed_at_unix_seconds: u64,
) -> Result<TelemetrySectionMetaV1, AppCoreError> {
    TelemetrySectionMetaV1::new(
        observed_at_unix_seconds,
        TelemetryFreshnessV1::Unavailable,
        TelemetryCompletenessV1::Unavailable,
    )
    .map_err(|_| AppCoreError::StateUnavailable)
}

fn increment_counter(counter: &AtomicU64, saturated: &AtomicBool) {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current == u64::MAX {
            saturated.store(true, Ordering::Release);
            return;
        }
        let becomes_saturated = current == u64::MAX - 1;
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if becomes_saturated {
                    saturated.store(true, Ordering::Release);
                }
                return;
            }
            Err(actual) => current = actual,
        }
    }
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
