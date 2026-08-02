#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_labels_reject_the_entire_sample() {
        let sink = InMemoryMigrationMetricSink::default();
        let sample = MetricSample::counter(
            "gocode_migration_control_commands_total",
            1,
            [("taskrun_id", "018f2e3a")],
        );
        assert_eq!(
            sink.record(sample),
            Err(MetricError::ForbiddenLabel {
                key: "taskrun_id".into(),
            })
        );
        assert!(sink.samples().unwrap().is_empty());
    }

    #[test]
    fn duplicate_canonical_source_event_is_applied_once() {
        let sink = InMemoryMigrationMetricSink::default();
        let sample = committed_transition_metric("event-0001");
        sink.record(sample.clone()).unwrap();
        sink.record(sample).unwrap();
        assert_eq!(
            sink.counter_value("gocode_migration_phase_transitions_total")
                .unwrap(),
            1
        );
        assert_eq!(sink.samples().unwrap().len(), 1);
    }

    fn committed_transition_metric(source_event_id: &str) -> MetricSample {
        MetricSample::counter(
            "gocode_migration_phase_transitions_total",
            1,
            [("phase", "internal_canary"), ("outcome", "committed")],
        )
        .with_source_event_id(source_event_id)
    }
}
