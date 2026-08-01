
use std::{collections::BTreeMap, sync::Mutex};

const MAX_LABELS: usize = 7;
const MAX_LABEL_VALUE_BYTES: usize = 64;
const MAX_SOURCE_EVENT_ID_BYTES: usize = 128;

const ALLOWED_LABELS: &[&str] = &[
    "deployment_mode",
    "subsystem",
    "outcome",
    "profile_class",
    "error_code",
    "phase",
    "gate_family",
];

/// Supported metric instrument kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotonic replay-idempotent counter.
    Counter,
    /// Current low-cardinality value.
    Gauge,
    /// Base-unit integer observation.
    Histogram,
}

/// One migration metric observation before sink validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSample {
    name: String,
    kind: MetricKind,
    value: u64,
    labels: Vec<(String, String)>,
    source_event_id: Option<String>,
}

impl MetricSample {
    /// Construct a counter observation.
    pub fn counter<K, V, I>(name: impl Into<String>, value: u64, labels: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        Self::new(name, MetricKind::Counter, value, labels)
    }

    /// Construct a gauge observation.
    pub fn gauge<K, V, I>(name: impl Into<String>, value: u64, labels: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        Self::new(name, MetricKind::Gauge, value, labels)
    }

    /// Construct a base-unit integer histogram observation.
    pub fn histogram<K, V, I>(name: impl Into<String>, value: u64, labels: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        Self::new(name, MetricKind::Histogram, value, labels)
    }

    /// Attach the canonical source event used for replay deduplication.
    pub fn with_source_event_id(mut self, source_event_id: impl Into<String>) -> Self {
        self.source_event_id = Some(source_event_id.into());
        self
    }

    fn new<K, V, I>(name: impl Into<String>, kind: MetricKind, value: u64, labels: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        Self {
            name: name.into(),
            kind,
            value,
            labels: labels
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            source_event_id: None,
        }
    }
}

/// Closed metric validation and adapter failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricError {
    /// Metric name is not part of the stable migration schema.
    UnknownMetric {
        /// Rejected metric name.
        name: String,
    },
    /// Sample instrument kind differs from the stable schema.
    InstrumentMismatch {
        /// Metric whose kind was invalid.
        name: String,
        /// Required instrument kind.
        expected: MetricKind,
        /// Attempted instrument kind.
        actual: MetricKind,
    },
    /// Label key is not explicitly allowlisted.
    ForbiddenLabel {
        /// Rejected label key.
        key: String,
    },
    /// One label key appeared more than once.
    DuplicateLabel {
        /// Duplicated label key.
        key: String,
    },
    /// Sample exceeds the bounded label count.
    TooManyLabels {
        /// Maximum allowed label count.
        max: usize,
        /// Attempted label count.
        actual: usize,
    },
    /// Label value exceeds its byte bound.
    LabelValueTooLong {
        /// Label key whose value was oversized.
        key: String,
        /// Maximum value bytes.
        max: usize,
        /// Attempted value bytes.
        actual: usize,
    },
    /// Label value contains a control character.
    InvalidLabelValue {
        /// Label key whose value was invalid.
        key: String,
    },
    /// A canonical counter omitted its source event identity.
    MissingSourceEventIdentity,
    /// Source event identity is empty, oversized or contains controls.
    InvalidSourceEventIdentity,
    /// One source event identity was replayed with changed semantics.
    SourceEventIdentityConflict,
    /// Counter arithmetic exceeded `u64`.
    CounterOverflow,
    /// Sink synchronization state is unavailable.
    Unavailable,
}

/// Adapter contract for privacy-safe migration metrics.
pub trait MigrationMetricSink {
    /// Validate and record one observation atomically.
    fn record(&self, sample: MetricSample) -> Result<(), MetricError>;
}

/// In-memory sink used for deterministic projection and conformance tests.
#[derive(Debug, Default)]
pub struct InMemoryMigrationMetricSink {
    state: Mutex<MetricState>,
}

impl InMemoryMigrationMetricSink {
    /// Return accepted, deduplicated samples in acceptance order.
    pub fn samples(&self) -> Result<Vec<MetricSample>, MetricError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| MetricError::Unavailable)?
            .samples
            .clone())
    }

    /// Sum one counter across its bounded label sets.
    pub fn counter_value(&self, name: &str) -> Result<u64, MetricError> {
        self.state
            .lock()
            .map_err(|_| MetricError::Unavailable)?
            .counters
            .iter()
            .filter(|(key, _)| key.name == name)
            .try_fold(0_u64, |total, (_, value)| {
                total
                    .checked_add(*value)
                    .ok_or(MetricError::CounterOverflow)
            })
    }
}

impl MigrationMetricSink for InMemoryMigrationMetricSink {
    fn record(&self, mut sample: MetricSample) -> Result<(), MetricError> {
        let key = validate_sample(&sample)?;
        sample.labels.clone_from(&key.labels);
        let mut state = self.state.lock().map_err(|_| MetricError::Unavailable)?;

        if sample.kind == MetricKind::Counter {
            let source_event_id = sample
                .source_event_id
                .as_ref()
                .ok_or(MetricError::MissingSourceEventIdentity)?;
            let identity = (sample.name.clone(), source_event_id.clone());
            if let Some(previous) = state.canonical_events.get(&identity) {
                return if previous == &sample {
                    Ok(())
                } else {
                    Err(MetricError::SourceEventIdentityConflict)
                };
            }
            let current = state.counters.get(&key).copied().unwrap_or(0);
            let next = current
                .checked_add(sample.value)
                .ok_or(MetricError::CounterOverflow)?;
            state.counters.insert(key, next);
            state.canonical_events.insert(identity, sample.clone());
        } else if sample.kind == MetricKind::Gauge {
            state.gauges.insert(key, sample.value);
        } else {
            state.histograms.entry(key).or_default().push(sample.value);
        }
        state.samples.push(sample);
        Ok(())
    }
}
