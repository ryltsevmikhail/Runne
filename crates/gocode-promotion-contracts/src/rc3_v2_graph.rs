use crate::{ContractError, Rc3V2Facts, ValidatedRc3V2Payload};

/// Validate exact digest and shared binding coherence across validated RC3 v2 leaves.
///
/// # Errors
/// Returns an error unless manifest, review, and authorization are an exact closed graph.
pub fn validate(
    manifest: &ValidatedRc3V2Payload,
    review: &ValidatedRc3V2Payload,
    authorization: &ValidatedRc3V2Payload,
) -> Result<(), ContractError> {
    use Rc3V2Facts::{Authorization, FinalReview, Manifest};
    let (Manifest(m), FinalReview(r), Authorization(a)) =
        (manifest.facts(), review.facts(), authorization.facts())
    else {
        return Err(ContractError::IncoherentRc3V2Graph);
    };
    (r.manifest == hex(manifest.sha256())
        && a.manifest == hex(manifest.sha256())
        && a.final_review == hex(review.sha256())
        && m.candidate == r.candidate
        && m.candidate == a.candidate
        && m.inventory == r.inventory
        && m.inventory == a.inventory
        && m.report == r.report
        && m.report == a.report
        && m.metadata == r.metadata
        && m.metadata == a.metadata
        && m.human == r.human
        && r.allowlist == a.allowlist
        && r.allowlist_generation == a.allowlist_generation
        && m.destination == r.destination
        && m.destination == a.destination
        && m.channel == r.channel
        && m.channel == a.channel
        && m.effect_scope == r.effect_scope
        && m.effect_scope == a.effect_scope)
        .then_some(())
        .ok_or(ContractError::IncoherentRc3V2Graph)
}
fn hex(bytes: [u8; 32]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            out.push(char::from(TABLE[usize::from(byte >> 4)]));
            out.push(char::from(TABLE[usize::from(byte & 15)]));
            out
        })
}
