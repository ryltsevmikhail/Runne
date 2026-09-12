/// Loads the compile-time context authority for the separately domain-separated proof.
pub fn load() -> Option<crate::context_policy::ContextVerificationPolicy> {
    crate::context_policy::load()
}
