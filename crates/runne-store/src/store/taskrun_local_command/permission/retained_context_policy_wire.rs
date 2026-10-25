use super::{
    retained_context::{ContextErrorV1, OriginalSemanticProjectionV1},
    retained_context_cursor::Cursor,
};
use ContextErrorV1::{InvalidOriginalData, MalformedWire, UnsupportedWireVersion};
use runne_application::{permission_modes::RetainedRelevantSemanticsV1, project_trust::*};
use runne_domain::id::IntegrityDigest;

pub(super) fn encode_snapshot(
    snapshot: &ProjectTrustEffectPolicySnapshot,
    out: &mut Vec<u8>,
) -> Result<(), ContextErrorV1> {
    if !snapshot.is_valid() {
        return Err(InvalidOriginalData);
    }
    out.push(match snapshot.record.status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    });
    out.extend(snapshot.record.managed_deny_mask.to_be_bytes());
    out.extend(snapshot.record.instance_epoch.to_be_bytes());
    out.extend(snapshot.record.revision.to_be_bytes());
    out.extend(snapshot.policy.version.to_be_bytes());
    for decision in snapshot.policy.decisions() {
        out.push(decision.tag());
    }
    Ok(())
}
pub(super) fn decode_snapshot(
    cursor: &mut Cursor<'_>,
) -> Result<ProjectTrustEffectPolicySnapshot, ContextErrorV1> {
    let status = match cursor.u8()? {
        1 => ProjectTrustStatus::Untrusted,
        2 => ProjectTrustStatus::Trusted,
        3 => ProjectTrustStatus::Managed,
        _ => return Err(MalformedWire),
    };
    let record = ProjectTrustRecord {
        status,
        managed_deny_mask: cursor.u32()?,
        instance_epoch: cursor.u64()?,
        revision: cursor.u64()?,
    };
    let version = cursor.u32()?;
    let mut decisions = [ManagedEffectDecision::Allow; 6];
    for decision in &mut decisions {
        *decision = read_decision(cursor.u8()?)?;
    }
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record,
        policy: ManagedEffectPolicyV1::new(version, decisions),
    };
    if !snapshot.is_valid() {
        return Err(InvalidOriginalData);
    }
    Ok(snapshot)
}
fn read_decision(tag: u8) -> Result<ManagedEffectDecision, ContextErrorV1> {
    match tag {
        1 => Ok(ManagedEffectDecision::Allow),
        2 => Ok(ManagedEffectDecision::Ask),
        3 => Ok(ManagedEffectDecision::Deny),
        _ => Err(MalformedWire),
    }
}

pub(super) fn encode_projection(
    value: OriginalSemanticProjectionV1,
    out: &mut Vec<u8>,
) -> Result<(), ContextErrorV1> {
    out.extend(1u16.to_be_bytes());
    match value {
        OriginalSemanticProjectionV1::UnsupportedV1 => out.extend([0, 1]),
        OriginalSemanticProjectionV1::SupportedV1(value) => {
            if value.evaluator_version != 1 || value.semantics_version != 1 {
                return Err(UnsupportedWireVersion);
            }
            out.push(1);
            out.extend(value.evaluator_version.to_be_bytes());
            out.extend(value.semantics_version.to_be_bytes());
            for provided in value.provided {
                out.push(u8::from(provided));
            }
            for (provided, decision) in value.provided.into_iter().zip(value.decisions) {
                if provided != decision.is_some() {
                    return Err(InvalidOriginalData);
                }
                out.push(decision.map_or(0, ManagedEffectDecision::tag));
            }
            out.extend(value.digest.as_bytes());
        }
    }
    Ok(())
}
pub(super) fn decode_projection(
    cursor: &mut Cursor<'_>,
    preset: u16,
    source: u64,
    command: u64,
) -> Result<OriginalSemanticProjectionV1, ContextErrorV1> {
    if cursor.u16()? != 1 {
        return Err(UnsupportedWireVersion);
    }
    match cursor.u8()? {
        0 => {
            if cursor.u8()? != 1 {
                return Err(MalformedWire);
            }
            Ok(OriginalSemanticProjectionV1::UnsupportedV1)
        }
        1 => {
            let evaluator_version = cursor.u16()?;
            let semantics_version = cursor.u16()?;
            if evaluator_version != 1 || semantics_version != 1 {
                return Err(UnsupportedWireVersion);
            }
            let mut provided = [false; 6];
            for value in &mut provided {
                *value = match cursor.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(MalformedWire),
                };
            }
            let mut decisions = [None; 6];
            for (present, decision) in provided.into_iter().zip(&mut decisions) {
                let tag = cursor.u8()?;
                *decision = if tag == 0 {
                    None
                } else {
                    Some(read_decision(tag)?)
                };
                if present != decision.is_some() {
                    return Err(MalformedWire);
                }
            }
            Ok(OriginalSemanticProjectionV1::SupportedV1(
                RetainedRelevantSemanticsV1 {
                    evaluator_version,
                    semantics_version,
                    preset_version: preset,
                    source_policy_version: source,
                    command_policy_version: command,
                    provided,
                    decisions,
                    digest: IntegrityDigest::from_bytes(cursor.array()?),
                },
            ))
        }
        _ => Err(MalformedWire),
    }
}
