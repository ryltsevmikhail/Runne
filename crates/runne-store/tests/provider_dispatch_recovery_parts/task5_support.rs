use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_provider::{
    CancelDisposition, CancelRequest, CredentialMatcher, DispatchError, DispatchRequest,
    NativeSecretRef, PrepareError, PreparedRequest, ProviderCall, ProviderCallDigestVersion,
    ProviderFuture, ProviderPort, ProviderPricedUsage, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem, ProviderTerminalPricing,
    ProviderTerminalPricingError, ReconcileRequest, ReconciliationDisposition, ScannerError,
    SecureStoreError as TailStoreError, StreamCursor, StreamError, TailBinding, WithheldTailStore,
};
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError as JournalStoreError,
};
use zeroize::Zeroizing;

pub(super) const SECRET: &[u8] = b"credential-token";

#[derive(Default)]
pub(super) struct SecretProvider {
    polls: AtomicUsize,
    fail_next: bool,
    pub(super) cancelled: Mutex<Vec<ProviderStreamId>>,
}

impl SecretProvider {
    pub(super) fn failing_stream() -> Self {
        Self { fail_next: true, ..Self::default() }
    }

    pub(super) fn polls(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }
}

impl ProviderPort for SecretProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("stream identity is already durable") })
    }

    fn next(
        &self,
        _stream: &ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'_, Result<ProviderStreamItem, StreamError>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.fail_next {
            return Box::pin(async { Err(StreamError::Closed) });
        }
        let event = match cursor.sequence() {
            0 => ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
            1 => ProviderStreamEvent::new(
                1,
                ProviderStreamEventKind::ToolCallRequested {
                    call_id: "call-1".into(),
                    tool_name: "tool.run".into(),
                    arguments_json: format!(
                        r#"{{"credential":"{}"}}"#,
                        std::str::from_utf8(SECRET).unwrap()
                    ),
                },
            )
            .unwrap(),
            _ => unreachable!("fixture has exactly two provider frames"),
        };
        Box::pin(async move { ProviderStreamItem::from_event(event) })
    }

    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            self.cancelled.lock().unwrap().push(request.stream_id());
            Ok(CancelDisposition::Requested)
        })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

#[derive(Default)]
pub(super) struct MemoryKeyring {
    keys: Mutex<HashMap<ProviderJournalKeyRef, [u8; 32]>>,
}

impl ProviderJournalKeyring for MemoryKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, JournalStoreError> {
        Ok(if self.keys.lock().unwrap().contains_key(&key_ref) {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), JournalStoreError> {
        let bytes = key.with_bytes(|bytes| *bytes);
        let mut keys = self.keys.lock().unwrap();
        if let Some(existing) = keys.get(&key.key_ref()) {
            return if *existing == bytes {
                Ok(())
            } else {
                Err(JournalStoreError::CorruptProviderJournalKey)
            };
        }
        keys.insert(key.key_ref(), bytes);
        Ok(())
    }

    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, JournalStoreError> {
        let bytes = self
            .keys
            .lock()
            .unwrap()
            .get(&key_ref)
            .copied()
            .ok_or(JournalStoreError::ProviderJournalKeyNotFound)?;
        ProviderJournalKeyMaterial::new(key_ref, bytes)
    }

    fn delete_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
        _proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), JournalStoreError> {
        self.keys
            .lock()
            .unwrap()
            .remove(&key_ref)
            .map(|_| ())
            .ok_or(JournalStoreError::ProviderJournalKeyNotFound)
    }
}

pub(super) struct FixedPricing;

impl ProviderTerminalPricing for FixedPricing {
    fn price_terminal_usage(
        &self,
        _pricing: &[u8; 32],
        _profile: &[u8; 32],
        _usage: runne_provider::ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        Err(ProviderTerminalPricingError::Unavailable)
    }
}

pub(super) struct AllowingGuard;

impl ProhibitedContentPort for AllowingGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

pub(super) struct SecretMatcher;

impl CredentialMatcher for SecretMatcher {
    fn epoch(&self) -> Result<u64, ScannerError> {
        Ok(1)
    }

    fn maximum_match_len(&self) -> Result<usize, ScannerError> {
        Ok(SECRET.len())
    }

    fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError> {
        Ok(bytes.windows(SECRET.len()).any(|window| window == SECRET))
    }
}

type Tail = (TailBinding, Zeroizing<Vec<u8>>);

#[derive(Default)]
pub(super) struct SecretTailStore {
    tails: Mutex<HashMap<NativeSecretRef, Tail>>,
}

impl SecretTailStore {
    pub(super) fn tail_count(&self) -> usize {
        self.tails.lock().unwrap().len()
    }
}

impl WithheldTailStore for SecretTailStore {
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, TailStoreError> {
        let mut id = [0; 16];
        id[15] = 1;
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
