use super::super::TaskRunSnapshotError;
use super::super::io::{In, Out};
use super::super::refs::{get_context, get_plan, put_context, put_plan};
use crate::id::CycleId;

pub(super) fn put_opt_cycle(out: &mut Out, value: Option<CycleId>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.id(value.as_bytes());
        }
    }
}
pub(super) fn get_opt_cycle(input: &mut In<'_>) -> Result<Option<CycleId>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(CycleId::from_bytes(input.id()?))),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
pub(super) fn put_opt_context(
    out: &mut Out,
    value: Option<&crate::context::ContextManifestRef>,
) -> Result<(), TaskRunSnapshotError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            put_context(out, value)?;
        }
    }
    Ok(())
}
pub(super) fn get_opt_context(
    input: &mut In<'_>,
) -> Result<Option<crate::context::ContextManifestRef>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(get_context(input)?)),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
pub(super) fn put_opt_plan(
    out: &mut Out,
    value: Option<&crate::plan::PlanRevisionRef>,
) -> Result<(), TaskRunSnapshotError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            put_plan(out, value)?;
        }
    }
    Ok(())
}
pub(super) fn get_opt_plan(
    input: &mut In<'_>,
) -> Result<Option<crate::plan::PlanRevisionRef>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(get_plan(input)?)),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
pub(super) fn get_indexes(input: &mut In<'_>) -> Result<Vec<u32>, TaskRunSnapshotError> {
    let count = input.len()?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(input.u32()?);
    }
    Ok(values)
}
pub(super) fn bool(input: &mut In<'_>) -> Result<bool, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
pub(super) fn unique_outcomes(values: &[crate::agent_loop::StepOutcomeRecord]) -> bool {
    let mut indexes = std::collections::BTreeSet::new();
    let mut steps = std::collections::BTreeSet::new();
    values
        .iter()
        .all(|value| indexes.insert(value.proposal_index) && steps.insert(value.step_id))
}
