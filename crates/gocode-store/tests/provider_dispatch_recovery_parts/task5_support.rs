use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{
    ProviderExecutionError, ProviderExecutionStore, ProviderJournalAppendOutcome,
    ProviderJournalAppendRequest, ProviderJournalKeyBinding, ProviderPollRequest,
    ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding,
};
use gocode_provider::{
    CancelDisposition, CancelRequest, CredentialMatcher, DispatchAttemptId, DispatchError,
    DispatchRequest, NativeSecretRef, PrepareError, PreparedRequest, ProviderCall, ProviderFuture,
    ProviderPort, ProviderPricedUsage, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderStreamItem, ProviderTerminalPricing, ProviderTerminalPricingError, ReconcileRequest,
    ReconciliationDisposition, ScannerError, SecureStoreError, StreamCursor, StreamError,
    TailBinding, WithheldTailStore,
};
use gocode_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};
use zeroize::Zeroizing;

pub(super) const SECRET: &[u8] = b"credential-token";

pub(super) struct SecretProvider;

impl ProviderPort for SecretProvider {
    fn prepare(&self, _call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        Err(PrepareError::RenderedRequestBound)
    }
    fn prepare_for_digest_version(
        &self,
        _call: &ProviderCall,
        _version: gocode_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        Err(PrepareError::RenderedRequestBound)
    }
    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::ProviderStreamId, DispatchError>> {
        Box::pin(async { Err(DispatchError::MaybeDispatched) })
    }
    fn next(
        &self,
        _stream: &gocode_provider::ProviderStreamId,
        _cursor: StreamCursor,
    ) -> ProviderFuture<'_, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async {
            ProviderStreamItem::from_event(
                ProviderStreamEvent::new(
                    0,
                    ProviderStreamEventKind::TextDelta {
                        text: String::from_utf8(SECRET.to_vec()).unwrap(),
                    },
                )
                .unwrap(),
            )
        })
    }
    fn cancel(
        &self,
        _request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { Err(DispatchError::MaybeDispatched) })
    }
    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

#[derive(Default)]
pub(super) struct PublicationCountingStore {
    polls: AtomicUsize,
    journal: AtomicUsize,
    outbox: AtomicUsize,
    uncertain: AtomicUsize,
}

impl PublicationCountingStore {
    pub(super) fn polls(&self) -> usize { self.polls.load(Ordering::SeqCst) }
    pub(super) fn journal_appends(&self) -> usize { self.journal.load(Ordering::SeqCst) }
    pub(super) fn outbox_commits(&self) -> usize { self.outbox.load(Ordering::SeqCst) }
    pub(super) fn uncertain_audits(&self) -> usize { self.uncertain.load(Ordering::SeqCst) }
}

impl ProviderExecutionStore for PublicationCountingStore {
    fn activate_journal_key(&self, _key: ProviderJournalKeyBinding) -> Result<(), ProviderExecutionError> { Ok(()) }
    fn journal_key_reference_count(&self, _key: ProviderJournalKeyBinding) -> Result<u64, ProviderExecutionError> { Ok(0) }
    fn remove_retired_journal_key(&self, _key: ProviderJournalKeyBinding) -> Result<(), ProviderExecutionError> { Ok(()) }
    fn begin_provider_poll(&self, _request: &ProviderPollRequest) -> Result<(), ProviderExecutionError> { self.polls.fetch_add(1, Ordering::SeqCst); Ok(()) }
    fn append_encrypted_event(&self, _request: &ProviderJournalAppendRequest) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> { self.journal.fetch_add(1, Ordering::SeqCst); Ok(ProviderJournalAppendOutcome::Inserted) }
    fn load_encrypted_events(&self, _attempt: DispatchAttemptId) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> { Ok(Vec::new()) }
    fn load_terminal_pricing_binding(&self, _attempt: DispatchAttemptId) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> { Err(ProviderExecutionError::StoreUnavailable) }
    fn pending_terminal_outbox(&self) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> { Ok(Vec::new()) }
    fn acknowledge_terminal_outbox(&self, _id: [u8; 16], _digest: [u8; 32]) -> Result<(), ProviderExecutionError> { Ok(()) }
    fn mark_execution_uncertain(&self, _attempt: DispatchAttemptId, _fence: u64) -> Result<(), ProviderExecutionError> { self.uncertain.fetch_add(1, Ordering::SeqCst); Ok(()) }
}

impl ProviderTerminalPersistence for PublicationCountingStore {
    fn commit_terminal(&self, _request: &ProviderTerminalCommitRequest) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> { self.outbox.fetch_add(1, Ordering::SeqCst); Ok(ProviderTerminalCommitOutcome::Committed) }
}

pub(super) struct FixedPricing;
impl ProviderTerminalPricing for FixedPricing {
    fn price_terminal_usage(&self, _pricing: &[u8; 32], _profile: &[u8; 32], _usage: gocode_provider::ProviderUsage) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> { Err(ProviderTerminalPricingError::Unavailable) }
}

pub(super) struct AllowingGuard;
impl ProhibitedContentPort for AllowingGuard {
    fn inspect(&self, _boundary: CanonicalContentBoundary, _bytes: &[u8]) -> Result<ContentDisposition, ContentGuardError> { Ok(ContentDisposition::Allowed { policy_epoch: 1 }) }
}

pub(super) struct SecretMatcher;
impl CredentialMatcher for SecretMatcher {
    fn epoch(&self) -> Result<u64, ScannerError> { Ok(1) }
    fn maximum_match_len(&self) -> Result<usize, ScannerError> { Ok(SECRET.len()) }
    fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError> { Ok(bytes.windows(SECRET.len()).any(|window| window == SECRET)) }
}

type Tail = (TailBinding, Zeroizing<Vec<u8>>);
#[derive(Default)]
pub(super) struct SecretTailStore { tails: Mutex<HashMap<NativeSecretRef, Tail>> }
impl SecretTailStore { pub(super) fn tail_count(&self) -> usize { self.tails.lock().unwrap().len() } }
impl WithheldTailStore for SecretTailStore {
    fn put_tail(&self, binding: TailBinding, bytes: Zeroizing<Vec<u8>>) -> Result<NativeSecretRef, SecureStoreError> { let mut id = [0; 16]; id[15] = 1; let reference = NativeSecretRef::new(id, 1, binding.digest())?; self.tails.lock().unwrap().insert(reference, (binding, bytes)); Ok(reference) }
    fn load_tail(&self, reference: &NativeSecretRef, binding: TailBinding) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> { let tails = self.tails.lock().unwrap(); let (stored, bytes) = tails.get(reference).ok_or(SecureStoreError::NotFound)?; if *stored != binding { return Err(SecureStoreError::BindingMismatch); } Ok(Zeroizing::new(bytes.to_vec())) }
    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), SecureStoreError> { self.tails.lock().unwrap().remove(reference); Ok(()) }
    fn purge_orphaned_tails(&self, binding: TailBinding, retained: Option<NativeSecretRef>) -> Result<(), SecureStoreError> { self.tails.lock().unwrap().retain(|reference, (stored, _)| stored.attempt_id() != binding.attempt_id() || Some(*reference) == retained); Ok(()) }
}
