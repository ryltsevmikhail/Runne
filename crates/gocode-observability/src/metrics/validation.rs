#[derive(Debug, Default)]
struct MetricState {
    samples: Vec<MetricSample>,
    canonical_events: BTreeMap<(String, String), MetricSample>,
    counters: BTreeMap<MetricKey, u64>,
    gauges: BTreeMap<MetricKey, u64>,
    histograms: BTreeMap<MetricKey, Vec<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    name: String,
    labels: Vec<(String, String)>,
}

fn validate_sample(sample: &MetricSample) -> Result<MetricKey, MetricError> {
    let expected = metric_kind(&sample.name).ok_or_else(|| MetricError::UnknownMetric {
        name: sample.name.clone(),
    })?;
    if expected != sample.kind {
        return Err(MetricError::InstrumentMismatch {
            name: sample.name.clone(),
            expected,
            actual: sample.kind,
        });
    }
    if sample.labels.len() > MAX_LABELS {
        return Err(MetricError::TooManyLabels {
            max: MAX_LABELS,
            actual: sample.labels.len(),
        });
    }

    let mut labels = sample.labels.clone();
    labels.sort();
    for (index, (key, value)) in labels.iter().enumerate() {
        if !ALLOWED_LABELS.contains(&key.as_str()) {
            return Err(MetricError::ForbiddenLabel { key: key.clone() });
        }
        if index > 0 && labels[index - 1].0 == *key {
            return Err(MetricError::DuplicateLabel { key: key.clone() });
        }
        if value.len() > MAX_LABEL_VALUE_BYTES {
            return Err(MetricError::LabelValueTooLong {
                key: key.clone(),
                max: MAX_LABEL_VALUE_BYTES,
                actual: value.len(),
            });
        }
        if value.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(MetricError::InvalidLabelValue { key: key.clone() });
        }
    }

    if sample.kind == MetricKind::Counter {
        let source_event_id = sample
            .source_event_id
            .as_deref()
            .ok_or(MetricError::MissingSourceEventIdentity)?;
        if source_event_id.is_empty()
            || source_event_id.len() > MAX_SOURCE_EVENT_ID_BYTES
            || source_event_id
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(MetricError::InvalidSourceEventIdentity);
        }
    }

    Ok(MetricKey {
        name: sample.name.clone(),
        labels,
    })
}

fn metric_kind(name: &str) -> Option<MetricKind> {
    match name {
        "gocode_migration_control_commands_total"
        | "gocode_migration_phase_transitions_total"
        | "gocode_migration_routing_cas_total"
        | "gocode_migration_admission_total"
        | "gocode_migration_completion_total"
        | "gocode_migration_drain_completed_total"
        | "gocode_migration_gate_evidence_total"
        | "gocode_migration_canary_errors_total"
        | "gocode_migration_rollback_total"
        | "gocode_migration_stale_fencing_rejections_total"
        | "gocode_migration_exporter_events_total" => Some(MetricKind::Counter),
        "gocode_migration_phase_current"
        | "gocode_migration_drain_active"
        | "gocode_migration_drain_unresolved" => Some(MetricKind::Gauge),
        "gocode_migration_canary_latency_microseconds" => Some(MetricKind::Histogram),
        _ => None,
    }
}
