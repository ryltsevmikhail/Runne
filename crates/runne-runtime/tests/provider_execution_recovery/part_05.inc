
impl ProviderTerminalOutboxApplication for IdempotentTerminalApplication {
    fn complete_provider_terminal(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(record.principal_id, "principal-1");
        assert_eq!(record.conversation_id, ConversationId::from_bytes([6; 16]));
        assert_eq!(record.taskrun_id, TaskRunId::from_bytes([7; 16]));
        assert_eq!(record.execution_attempt_id, AttemptId::from_bytes([8; 16]));
        assert_eq!(record.fencing_token, 13);
        let mut committed = self
            .committed
            .lock()
            .map_err(|_| ProviderTerminalApplicationError::Unavailable)?;
        match committed.get(&record.application_idempotency_key) {
            Some(existing) if existing != output => Err(ProviderTerminalApplicationError::Conflict),
            Some(_) => Ok([77; 32]),
            None => {
                committed.insert(record.application_idempotency_key.clone(), output.to_vec());
                Ok([77; 32])
            }
        }
    }
}

struct IgnoringRecoveryObserver;

impl ProviderRecoveryObserver for IgnoringRecoveryObserver {
    fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError> {
        Ok(())
    }
}

static IGNORING_RECOVERY_OBSERVER: IgnoringRecoveryObserver = IgnoringRecoveryObserver;

#[tokio::test(flavor = "current_thread")]
async fn crash_after_application_commit_before_outbox_ack_replays_one_completion_identity() {
    const OUTPUT: &[u8] = b"idempotent-terminal-output-marker-92";
    let fixture = fixture();
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &writer,
        &fixture,
        successful_events(std::str::from_utf8(OUTPUT).unwrap()),
    )
    .await;
    writer.finalize_terminal_output(&context(&fixture)).unwrap();

    let store = FailFirstAcknowledgementStore {
        inner: Arc::clone(&fixture.execution),
        fail_acknowledgement: AtomicBool::new(true),
    };
    let recovery = runtime(&keyring, &store);
    let application = IdempotentTerminalApplication::default();
    assert_eq!(
        recovery.apply_pending_terminal_outputs(&application, &IGNORING_RECOVERY_OBSERVER),
        Err(RuntimeProviderExecutionError::PersistenceUnavailable)
    );
    assert_eq!(
        recovery.apply_pending_terminal_outputs(&application, &IGNORING_RECOVERY_OBSERVER),
        Ok(1)
    );
    assert_eq!(application.calls.load(Ordering::SeqCst), 2);
    assert_eq!(application.committed.lock().unwrap().len(), 1);
    assert!(
        recovery
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
}
