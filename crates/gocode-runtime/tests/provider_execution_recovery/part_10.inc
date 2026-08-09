use gocode_provider::{
    CredentialMatcher, NativeSecretRef, ScannerError, ScannerTerminalDisposition,
    ScannerUncertainReason, SecureStoreError as TailStoreError, TailBinding, WithheldTailStore,
};
use gocode_runtime::provider_redaction::{
    ProviderEventRedactionBoundary, ScannerRecoveryPersistence,
};
use gocode_store::provider::SqliteProviderRecoveryStore;
use zeroize::Zeroizing;

type ExecutionTail = (TailBinding, Zeroizing<Vec<u8>>);

#[derive(Default)]
struct ExecutionTailStore {
    next: Mutex<u8>,
    tails: Mutex<HashMap<NativeSecretRef, ExecutionTail>>,
}

impl WithheldTailStore for ExecutionTailStore {
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, TailStoreError> {
        let mut next = self.next.lock().unwrap();
        *next += 1;
        let mut id = [0_u8; 16];
        id[15] = *next;
        let reference = NativeSecretRef::new(id, 1, binding.digest())?;
        self.tails
            .lock()
            .unwrap()
            .insert(reference, (binding, bytes));
        Ok(reference)
    }

    fn load_tail(
        &self,
        reference: &NativeSecretRef,
        binding: TailBinding,
    ) -> Result<Zeroizing<Vec<u8>>, TailStoreError> {
        let tails = self.tails.lock().unwrap();
        let (stored, bytes) = tails.get(reference).ok_or(TailStoreError::NotFound)?;
        if *stored != binding {
            return Err(TailStoreError::BindingMismatch);
        }
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), TailStoreError> {
        self.tails.lock().unwrap().remove(reference);
        Ok(())
    }

    fn purge_orphaned_tails(
        &self,
        binding: TailBinding,
        retained: Option<NativeSecretRef>,
    ) -> Result<(), TailStoreError> {
        self.tails.lock().unwrap().retain(|reference, (stored, _)| {
            stored.attempt_id() != binding.attempt_id() || Some(*reference) == retained
        });
        Ok(())
    }
}

struct ExecutionMatcher;
const EXECUTION_SECRET: &[u8] = b"credential-token";

impl CredentialMatcher for ExecutionMatcher {
    fn epoch(&self) -> Result<u64, ScannerError> {
        Ok(1)
    }
    fn maximum_match_len(&self) -> Result<usize, ScannerError> {
        Ok(128)
    }
    fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError> {
        Ok(bytes
            .windows(EXECUTION_SECRET.len())
            .any(|window| window == EXECUTION_SECRET))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn authoritative_append_boundary_releases_clean_tail_only_after_completed() {
    let fixture = fixture();
    let recovery = SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap();
    let tails = ExecutionTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &ExecutionMatcher);
    let keyring = MemoryKeyring::default();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &ALLOWING_GUARD,
        &redaction,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = successful_events("clean scanner output");
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events,
    };
    let stream = ProviderStreamId::from_bytes([9; 16]);
    for sequence in 0..4 {
        let item = runtime
            .next_and_commit(
                &provider,
                &stream,
                StreamCursor::new(sequence),
                &context(&fixture),
            )
            .await
            .unwrap();
        match sequence {
            1 => assert!(matches!(
                item.event().kind(),
                ProviderStreamEventKind::ScannerProgress
            )),
            3 => assert!(matches!(
                item.event().kind(),
                ProviderStreamEventKind::ScannerCompleted { text, .. }
                    if text == "clean scanner output"
            )),
            _ => {}
        }
    }

    assert_eq!(
        recovery.load(fixture.attempt_id).unwrap().unwrap().disposition(),
        Some(ScannerTerminalDisposition::Completed)
    );
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn authoritative_append_boundary_blocks_split_secret_before_text_journal() {
    let fixture = fixture();
    let recovery = SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap();
    let tails = ExecutionTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &ExecutionMatcher);
    let keyring = MemoryKeyring::default();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &ALLOWING_GUARD,
        &redaction,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "credential-".into(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::TextDelta {
                text: "token".into(),
            },
        )
        .unwrap(),
    ];
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events,
    };
    let stream = ProviderStreamId::from_bytes([9; 16]);
    for sequence in 0..2 {
        let item = runtime
            .next_and_commit(&provider, &stream, StreamCursor::new(sequence), &context(&fixture))
            .await
            .unwrap();
        if sequence == 1 {
            assert!(matches!(
                item.event().kind(),
                ProviderStreamEventKind::ScannerProgress
            ));
        }
    }
    assert_eq!(
        runtime
            .next_and_commit(&provider, &stream, StreamCursor::new(2), &context(&fixture))
            .await,
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    assert_eq!(
        recovery.load(fixture.attempt_id).unwrap().unwrap().disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected,
        ))
    );
    let recovered = runtime.recover_events(fixture.attempt_id).unwrap();
    let bytes = serde_json::to_vec(&recovered).unwrap();
    assert!(!bytes.windows(EXECUTION_SECRET.len()).any(|window| window == EXECUTION_SECRET));
    assert!(runtime.recover_pending_terminal_outputs().unwrap().is_empty());
}
