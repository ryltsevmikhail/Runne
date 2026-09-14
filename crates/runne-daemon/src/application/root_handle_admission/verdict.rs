/// Daemon-pinned policy generation; signed claims must match this exact value.
pub(crate) const PINNED_POLICY_VERSION: u64 = 1;
fn same_context(
    left: &RootAdmissionVerificationContext,
    right: &RootAdmissionVerificationContext,
) -> bool {
    left.authority_digest() == right.authority_digest()
        && left.session_id() == right.session_id()
        && left.launch_generation() == right.launch_generation()
        && left.principal_digest() == right.principal_digest()
        && left.capability_version() == right.capability_version()
        && left.policy_version() == right.policy_version()
        && left.now_unix_millis() <= right.now_unix_millis()
}
fn expire(state: &mut State, moment: u64) {
    state.pending.retain(|_, item| item.expires_at > moment);
}
fn now() -> Result<u64, RootAdmissionVerifierError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(RootAdmissionVerifierError::Unavailable)
}
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
impl RootHandleAdmissionAuthority {
    /// Test-only view of the retained verdict state: (pending, durable-active).
    pub(crate) fn retained_effect(&self) -> (usize, usize) {
        self.state
            .lock()
            .map(|state| (state.pending.len(), state.active.len()))
            .unwrap_or((usize::MAX, usize::MAX))
    }
}
