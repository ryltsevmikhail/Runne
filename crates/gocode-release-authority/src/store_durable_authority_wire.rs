use crate::AuthorityError;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityWire {
    pub(super) schema_version: String,
    pub(super) bootstrap: String,
    pub(super) profile: String,
    pub(super) version: u64,
    pub(super) authority_instance: String,
    pub(super) generation: u64,
    pub(super) previous_authority_sha256: Option<String>,
    pub(super) promotions: Vec<crate::store_durable_wire::FileState>,
    pub(super) effect_ledger: String,
    pub(super) publication_effect_ledger: String,
    pub(super) publication_effect_ledger_sha256: String,
    pub(super) publication_effect_outer_sha256: String,
}

pub(super) fn encode(wire: &AuthorityWire) -> Result<Vec<u8>, AuthorityError> {
    validate(wire)?;
    let mut bytes = serde_json::to_vec(wire).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(super) fn seal(mut wire: AuthorityWire) -> Result<AuthorityWire, AuthorityError> {
    wire.publication_effect_ledger_sha256 = hash(&crate::store_durable_wire::bytes(
        &wire.publication_effect_ledger,
    )?);
    wire.publication_effect_outer_sha256 = outer_hash(&wire)?;
    Ok(wire)
}

pub(super) fn validate(wire: &AuthorityWire) -> Result<(), AuthorityError> {
    let ledger = crate::store_durable_wire::bytes(&wire.publication_effect_ledger)?;
    if wire.generation == 0
        || wire
            .previous_authority_sha256
            .as_deref()
            .is_some_and(|x| !hex(x))
        || !hex(&wire.publication_effect_ledger_sha256)
        || !hex(&wire.publication_effect_outer_sha256)
        || wire.publication_effect_ledger_sha256 != hash(&ledger)
        || wire.publication_effect_outer_sha256 != outer_hash(wire)?
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}

pub(super) fn file_digest(bytes: &[u8]) -> crate::Digest {
    crate::Digest::from_bytes(Sha256::digest(bytes).into())
}

#[derive(Serialize)]
struct OuterBinding<'a> {
    domain: &'static str,
    schema_version: &'a str,
    bootstrap: &'a str,
    profile: &'a str,
    version: u64,
    authority_instance: &'a str,
    generation: u64,
    previous_authority_sha256: &'a Option<String>,
    promotions: &'a [crate::store_durable_wire::FileState],
    effect_ledger: &'a str,
    publication_effect_ledger: &'a str,
    publication_effect_ledger_sha256: &'a str,
}

fn outer_hash(wire: &AuthorityWire) -> Result<String, AuthorityError> {
    let bytes = serde_json::to_vec(&OuterBinding {
        domain: "gocode.release.publication-effect-outer-binding/1",
        schema_version: &wire.schema_version,
        bootstrap: &wire.bootstrap,
        profile: &wire.profile,
        version: wire.version,
        authority_instance: &wire.authority_instance,
        generation: wire.generation,
        previous_authority_sha256: &wire.previous_authority_sha256,
        promotions: &wire.promotions,
        effect_ledger: &wire.effect_ledger,
        publication_effect_ledger: &wire.publication_effect_ledger,
        publication_effect_ledger_sha256: &wire.publication_effect_ledger_sha256,
    })
    .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    Ok(hash(&bytes))
}

fn hash(bytes: &[u8]) -> String {
    crate::Digest::from_bytes(Sha256::digest(bytes).into()).to_hex()
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
pub fn fixture_successor(
    current: &[u8],
    publication_ledger: &[u8],
) -> Result<Vec<u8>, AuthorityError> {
    let mut wire: AuthorityWire =
        serde_json::from_slice(current).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    if encode(&wire)? != current {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    wire.generation = wire
        .generation
        .checked_add(1)
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    wire.previous_authority_sha256 = Some(file_digest(current).to_hex());
    wire.publication_effect_ledger = crate::threshold_fixture_wire::hex(publication_ledger);
    wire.publication_effect_ledger_sha256.clear();
    wire.publication_effect_outer_sha256.clear();
    encode(&seal(wire)?)
}
