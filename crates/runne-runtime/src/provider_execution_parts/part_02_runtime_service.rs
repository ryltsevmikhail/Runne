/// Runtime service that owns journal keys, AEAD, pinned terminal policy and
/// commit-before-next-poll.
pub struct RuntimeProviderExecution<'a, K: ?Sized, S, P> {
    keyring: &'a K,
    store: &'a S,
    pricing: &'a P,
    prohibited_content: &'a dyn ProhibitedContentPort,
    redaction: &'a dyn ProviderEventRedaction,
    random: SystemRandom,
    active_key: Mutex<Option<ProviderJournalKeyBinding>>,
}

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Constructs one service with immutable pricing and prohibited-content
    /// policy pinned for its full lifetime.
    pub fn new(
        keyring: &'a K,
        store: &'a S,
        pricing: &'a P,
        prohibited_content: &'a dyn ProhibitedContentPort,
        redaction: &'a dyn ProviderEventRedaction,
    ) -> Self {
        Self {
            keyring,
            store,
            pricing,
            prohibited_content,
            redaction,
            random: SystemRandom::new(),
            active_key: Mutex::new(None),
        }
    }
}
