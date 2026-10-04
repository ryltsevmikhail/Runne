fn project_local_effect(
    state: &str,
    attempt: Option<AttemptId>,
    exit_code: Option<i32>,
    area: Option<&[u8]>,
    cancellation_requested: bool,
    unknown_stop_proven: bool,
) -> Result<(LocalOutcome, LocalStop), EventStoreError> {
    let has_binding = attempt.is_some() && area.is_some();
    let projected = match state {
        "preflight" | "approval_pending" | "approved" | "denied" | "no_effect_terminal" => {
            (LocalOutcome::NotStarted, LocalStop::NotRequested)
        }
        "launch_intent" | "release_reserved" => {
            if !has_binding {
                return Err(EventStoreError::CorruptData);
            }
            (
                LocalOutcome::OutcomeUnknown,
                if cancellation_requested {
                    LocalStop::Requested
                } else {
                    LocalStop::NotRequested
                },
            )
        }
        "running" => {
            if !has_binding {
                return Err(EventStoreError::CorruptData);
            }
            if cancellation_requested {
                (LocalOutcome::OutcomeUnknown, LocalStop::Requested)
            } else {
                (LocalOutcome::Running, LocalStop::NotRequested)
            }
        }
        "cancel_requested" => {
            if !has_binding || !cancellation_requested {
                return Err(EventStoreError::CorruptData);
            }
            (LocalOutcome::OutcomeUnknown, LocalStop::Requested)
        }
        "stop_unconfirmed" => (LocalOutcome::OutcomeUnknown, LocalStop::Unconfirmed),
        "completed" => {
            if !has_binding || exit_code.is_none() {
                return Err(EventStoreError::CorruptData);
            }
            (LocalOutcome::Exited, LocalStop::Confirmed)
        }
        "cancelled" => {
            if !has_binding || !cancellation_requested {
                return Err(EventStoreError::CorruptData);
            }
            (
                if exit_code.is_some() {
                    LocalOutcome::Exited
                } else {
                    LocalOutcome::OutcomeUnknown
                },
                LocalStop::Confirmed,
            )
        }
        "outcome_unknown" => {
            if !has_binding || !unknown_stop_proven {
                return Err(EventStoreError::CorruptData);
            }
            (LocalOutcome::OutcomeUnknown, LocalStop::Confirmed)
        }
        _ => return Err(EventStoreError::CorruptData),
    };
    Ok(projected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_binding() -> (Option<AttemptId>, Option<&'static [u8]>) {
        (Some(AttemptId::from_bytes([1; 16])), Some(&[7; 100]))
    }

    #[test]
    fn local_effect_facts_do_not_confuse_execution_with_stop_attempts() {
        let (attempt, area) = active_binding();
        assert_eq!(
            project_local_effect("running", attempt, None, area, false, false).unwrap(),
            (LocalOutcome::Running, LocalStop::NotRequested)
        );
        assert_eq!(
            project_local_effect("running", attempt, None, area, true, false).unwrap(),
            (LocalOutcome::OutcomeUnknown, LocalStop::Requested)
        );
        assert_eq!(
            project_local_effect("stop_unconfirmed", attempt, None, area, true, false).unwrap(),
            (LocalOutcome::OutcomeUnknown, LocalStop::Unconfirmed)
        );
        assert_eq!(
            project_local_effect("completed", attempt, Some(7), area, false, false).unwrap(),
            (LocalOutcome::Exited, LocalStop::Confirmed)
        );
        assert_eq!(
            project_local_effect("outcome_unknown", attempt, None, area, true, true).unwrap(),
            (LocalOutcome::OutcomeUnknown, LocalStop::Confirmed)
        );
    }
}
