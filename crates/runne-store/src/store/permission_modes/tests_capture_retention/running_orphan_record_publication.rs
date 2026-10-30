//! Marker is last, AFTER collected helper and checked critical record closes.
use super::context::CaseContext;
use super::model::ContextRecord;
use super::record_protocol::{Name, Operation, RECORD_CAP};
use super::record_pump::Failure;
use super::record_transport;
use super::record_validation;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u32,
    context: ContextRecord,
    name: Name,
    value: T,
}

pub(super) fn publish<T: Serialize>(
    context: &CaseContext,
    name: Name,
    value: &T,
) -> Result<String, Failure> {
    context.check_roots();
    let envelope = Envelope {
        version: 1,
        context: context.record.clone(),
        name,
        value,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| Failure::before_spawn("record JSON"))?;
    // Future concrete values are closed and bounded; not a generic serializer allocation bound.
    if bytes.is_empty() || bytes.len() > RECORD_CAP {
        return Err(Failure::before_spawn("envelope cap"));
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    let (_, status) = record_transport::call(context, Operation::Publish, name, &bytes)?;
    record_validation::after_collection(context, status)?;
    let marker = context.root.path.join(format!("{}.complete", name.stem()));
    context
        .deadline
        .try_remaining()
        .map_err(|code| Failure::collected(code, status))?;
    // No file opens/drops/sync/readback or fallible check AFTER this operation.
    DirBuilder::new()
        .mode(0o700)
        .create(marker)
        .map_err(|_| Failure::collected("final exclusive completion marker", status))?;
    Ok(digest)
}

pub(super) fn read<T: DeserializeOwned>(
    context: &CaseContext,
    name: Name,
) -> Result<(T, String), Failure> {
    let (bytes, status) = record_transport::call(context, Operation::Read, name, &[])?;
    let envelope: Envelope<T> = serde_json::from_slice(&bytes)
        .map_err(|_| Failure::collected("closed record JSON", status))?;
    if envelope.version != 1 || envelope.context != context.record || envelope.name != name {
        return Err(Failure::collected(
            "exact record version/context/name",
            status,
        ));
    }
    context
        .deadline
        .try_remaining()
        .map_err(|code| Failure::collected(code, status))?;
    Ok((envelope.value, hex::encode(Sha256::digest(&bytes))))
}
