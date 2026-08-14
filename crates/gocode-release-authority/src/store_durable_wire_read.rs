use super::{
    CandidateBinding, FileState, IdentityWire, OutboxWire, OutcomeWire, PromotionId,
    PromotionState, RecordWire, StageWire, ThresholdFixtureStoreBinding, TransactionOutcome,
};
use crate::{AuthorityError, Digest};
#[path = "store_durable_wire_identity.rs"]
mod identity;

pub fn into_record(
    file: &FileState,
    binding: &ThresholdFixtureStoreBinding,
) -> Result<(PromotionId, crate::store_machine::Record), AuthorityError> {
    let (id, mut record) = base_record(file, binding)?;
    super::record::restore_scalars(&file.record, &mut record)?;
    super::record::restore_reservation(&file.record, &mut record)?;
    super::record::restore_commands(&file.record, &mut record)?;
    super::record::restore_snapshot(&file.record, &mut record)?;
    super::consistency::validate(file, &record)?;
    crate::store_snapshot::validate(&id, &record)?;
    Ok((id, record))
}

fn base_record(
    file: &FileState,
    binding: &ThresholdFixtureStoreBinding,
) -> Result<(PromotionId, crate::store_machine::Record), AuthorityError> {
    if file.schema_version != "gocode.release.durable-promotion-store/1"
        || file.bootstrap != binding.bootstrap.to_hex()
        || file.profile != binding.profile
        || file.version != binding.version
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let id = PromotionId::try_fixture(&file.promotion)?;
    valid(&file.record)?;
    let r = &file.record;
    let b = &r.binding;
    let candidate = CandidateBinding::from_durable_components(
        d(&b.subject)?,
        d(&b.matrix)?,
        d(&b.bootstrap)?,
        d(&b.candidate)?,
        d(&b.policy)?,
        b.release_facts.as_deref().map(d).transpose()?,
    );
    if candidate.sha256() != d(&b.sha256)? {
        return Err(AuthorityError::BindingMismatch);
    }
    let record = crate::store_machine::Record {
        state: Some(parse_state(&r.state)?),
        binding: Some(candidate),
        revision: r.revision,
        ..Default::default()
    };
    Ok((id, record))
}

pub fn encode(file: &FileState) -> Result<Vec<u8>, AuthorityError> {
    let mut bytes = serde_json::to_vec(file).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub fn decode(
    bytes: &[u8],
    binding: &ThresholdFixtureStoreBinding,
) -> Result<(PromotionId, crate::store_machine::Record), AuthorityError> {
    let file: FileState =
        serde_json::from_slice(bytes).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    (encode(&file)? == bytes)
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    into_record(&file, binding)
}
fn valid(r: &RecordWire) -> Result<(), AuthorityError> {
    canonical(&r.state)?;
    canonical(&r.binding.subject)?;
    for x in r
        .commands
        .iter()
        .map(|x| &x.command)
        .chain(r.completed_verify.iter().map(|x| &x.command))
    {
        canonical(x)?;
    }
    Ok(())
}
fn canonical(x: &str) -> Result<(), AuthorityError> {
    (!x.is_empty() && x.len() <= 4096)
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}
pub fn h(x: Digest) -> String {
    x.to_hex()
}
pub fn opt(x: Option<Digest>) -> Option<String> {
    x.map(h)
}
pub(super) fn d(x: &str) -> Result<Digest, AuthorityError> {
    if x.len() != 64
        || !x
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    let mut bytes = [0; 32];
    for (i, pair) in x.as_bytes().chunks_exact(2).enumerate() {
        bytes[i] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| AuthorityError::NonCanonicalPayload)?,
            16,
        )
        .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    }
    Ok(Digest::from_bytes(bytes))
}
pub(crate) fn bytes(x: &str) -> Result<Vec<u8>, AuthorityError> {
    if x.is_empty() || x.len() > 262_144 || !x.len().is_multiple_of(2) {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    x.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| AuthorityError::NonCanonicalPayload)?,
                16,
            )
            .map_err(|_| AuthorityError::NonCanonicalPayload)
        })
        .collect()
}
pub(super) fn dig(x: Option<&String>) -> Result<Option<Digest>, AuthorityError> {
    x.map(String::as_str).map(d).transpose()
}
pub const fn state(x: PromotionState) -> &'static str {
    match x {
        PromotionState::Rc0Ingested => "rc0_ingested",
        PromotionState::Rc1Review => "rc1_review",
        PromotionState::QualifiedUnsigned => "qualified_unsigned",
        PromotionState::SigningAuthorized => "signing_authorized",
        PromotionState::SignedEnvelopesVerified => "signed_envelopes_verified",
        PromotionState::Rc3Review => "rc3_review",
        PromotionState::PublicationAuthorized => "publication_authorized",
    }
}
fn parse_state(x: &str) -> Result<PromotionState, AuthorityError> {
    match x {
        "rc0_ingested" => Ok(PromotionState::Rc0Ingested),
        "rc1_review" => Ok(PromotionState::Rc1Review),
        "qualified_unsigned" => Ok(PromotionState::QualifiedUnsigned),
        "signing_authorized" => Ok(PromotionState::SigningAuthorized),
        "signed_envelopes_verified" => Ok(PromotionState::SignedEnvelopesVerified),
        "rc3_review" => Ok(PromotionState::Rc3Review),
        "publication_authorized" => Ok(PromotionState::PublicationAuthorized),
        _ => Err(AuthorityError::NonCanonicalPayload),
    }
}
fn identity(x: &crate::StageIssuerIdentity) -> IdentityWire {
    IdentityWire {
        principal: x.principal_id().into(),
        account: x.account_id().into(),
        lane: x.lane_id().into(),
        key: x.key_id().into(),
        signature_profile: x.signature_profile_id().into(),
    }
}
pub fn stage(x: &crate::StoredStage) -> StageWire {
    StageWire {
        sha256: crate::threshold_fixture_wire::hex(&x.sha256),
        bootstrap: h(x.bootstrap),
        issuer: identity(&x.issuer),
        root: identity(&x.root),
    }
}
#[rustfmt::skip]
pub fn outbox(x: &crate::store_stage_trust::ThresholdAckDelivery) -> OutboxWire {
    let (admission, revision) = x.claim();
    let command = match x { crate::store_stage_trust::ThresholdAckDelivery::Pending { .. } => None, crate::store_stage_trust::ThresholdAckDelivery::Delivering { command, .. } => Some(command.clone()) };
    OutboxWire {
        state: match x { crate::store_stage_trust::ThresholdAckDelivery::Pending { .. } => "pending", crate::store_stage_trust::ThresholdAckDelivery::Delivering { .. } => "delivering" }.into(),
        admission: h(admission),
        revision,
        command,
    }
}
pub fn outcome(x: &TransactionOutcome) -> OutcomeWire {
    OutcomeWire {
        state: state(x.state).into(),
        revision: x.revision,
    }
}
pub(super) fn into_outcome(x: &OutcomeWire) -> Result<TransactionOutcome, AuthorityError> {
    Ok(TransactionOutcome {
        state: parse_state(&x.state)?,
        revision: x.revision,
        fixture: true,
    })
}
pub(super) fn into_stage(x: &StageWire) -> Result<crate::StoredStage, AuthorityError> {
    Ok(crate::StoredStage {
        sha256: d(&x.sha256)?.as_bytes(),
        bootstrap: d(&x.bootstrap)?,
        issuer: identity::into_identity(&x.issuer)?,
        root: identity::into_identity(&x.root)?,
    })
}
