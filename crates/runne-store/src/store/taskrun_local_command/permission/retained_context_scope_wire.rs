use super::{
    codec::CaptureV1,
    retained_context::ContextErrorV1,
    retained_context_cursor::{Cursor, put_option},
};
use ContextErrorV1::{InvalidOriginalData, MalformedWire};
use runne_application::{
    permission_modes::*,
    project_trust::{ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId},
};
use runne_domain::id::{IntegrityDigest, WorkspaceId};
use std::collections::BTreeSet;

pub(super) struct ScopeDataV1 {
    containment: ContainmentStrategy,
    filesystem: FilesystemScope,
    network: NetworkScope,
    children: ChildDelegationScope,
    budget: EffectBudget,
    lifetime_ms: u64,
    protected: IntegrityDigest,
}
impl ScopeDataV1 {
    pub(super) fn reconstruct(
        self,
        c: &CaptureV1,
        snapshot: &ProjectTrustEffectPolicySnapshot,
    ) -> Result<CompositeEffectScope, ContextErrorV1> {
        let permission_scope = PermissionScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                c.runtime_authority_id.clone(),
            ),
            principal_id: runne_api::ApiPrincipalId::new(c.principal_id.clone())
                .map_err(|_| InvalidOriginalData)?,
            workspace_id: WorkspaceId::from_bytes(c.workspace_id),
        };
        let scope = CompositeEffectScope {
            permission_scope,
            filesystem: self.filesystem,
            network: self.network,
            managed_policy: ManagedPolicyCoverage::from_closed_snapshot(
                ProjectTrustProjectId::from_bytes(c.project_id),
                snapshot,
            )
            .ok_or(InvalidOriginalData)?,
            children: self.children,
            budget: self.budget,
            lifetime_ms: self.lifetime_ms,
            containment: self.containment,
            protected_control_plane_policy_digest: self.protected,
        };
        scope.validate().map_err(|_| InvalidOriginalData)?;
        Ok(scope)
    }
}

pub(super) fn encode(
    scope: &CompositeEffectScope,
    out: &mut Vec<u8>,
) -> Result<(), ContextErrorV1> {
    scope.validate().map_err(|_| InvalidOriginalData)?;
    if !scope.managed_policy.is_closed() {
        return Err(InvalidOriginalData);
    }
    out.push(match scope.containment {
        ContainmentStrategy::WorkspaceBoundV1 => 1,
        ContainmentStrategy::SameUserCompositeV1 => 2,
        ContainmentStrategy::SameUserCompositeV2 => 3,
    });
    match &scope.filesystem.posture {
        FilesystemPosture::None => out.push(0),
        FilesystemPosture::BroadSameUser => out.push(2),
        FilesystemPosture::BoundedRoots(roots) => {
            if roots.is_empty() || roots.len() > 64 {
                return Err(InvalidOriginalData);
            }
            out.extend([
                1,
                u8::try_from(roots.len()).map_err(|_| InvalidOriginalData)?,
            ]);
            for root in roots {
                put_root(root, out)?;
            }
        }
    }
    out.push(u8::try_from(scope.filesystem.permissions.len()).map_err(|_| InvalidOriginalData)?);
    for right in &scope.filesystem.permissions {
        out.push(right_tag(*right));
    }
    out.push(match scope.network {
        NetworkScope::None => 0,
        NetworkScope::BroadSameUser => 2,
        _ => return Err(InvalidOriginalData),
    });
    out.push(3);
    match scope.children {
        ChildDelegationScope::None => out.push(0),
        ChildDelegationScope::Unbounded => out.push(2),
        ChildDelegationScope::MaxDepth(depth) => {
            out.push(1);
            out.extend(depth.to_be_bytes());
        }
    }
    put_option(out, scope.budget.max_operations);
    put_option(out, scope.budget.max_bytes);
    out.extend(scope.lifetime_ms.to_be_bytes());
    out.extend(scope.protected_control_plane_policy_digest.as_bytes());
    Ok(())
}
fn put_root(root: &FilesystemRoot, out: &mut Vec<u8>) -> Result<(), ContextErrorV1> {
    if root.components.len() > 256 {
        return Err(InvalidOriginalData);
    }
    let mut joined = if root.components.is_empty() {
        0
    } else {
        root.components.len() - 1
    };
    out.extend(root.root_identity.as_bytes());
    out.extend(
        u16::try_from(root.components.len())
            .map_err(|_| InvalidOriginalData)?
            .to_be_bytes(),
    );
    for part in &root.components {
        if part.is_empty() || part.len() > 255 {
            return Err(InvalidOriginalData);
        }
        joined = joined.checked_add(part.len()).ok_or(InvalidOriginalData)?;
        if joined > 4096 {
            return Err(InvalidOriginalData);
        }
        out.extend(
            u16::try_from(part.len())
                .map_err(|_| InvalidOriginalData)?
                .to_be_bytes(),
        );
        out.extend(part.as_bytes());
    }
    Ok(())
}
fn right_tag(value: FilesystemPermission) -> u8 {
    match value {
        FilesystemPermission::Read => 1,
        FilesystemPermission::Create => 2,
        FilesystemPermission::Write => 3,
        FilesystemPermission::Delete => 4,
    }
}

pub(super) fn decode(cursor: &mut Cursor<'_>) -> Result<ScopeDataV1, ContextErrorV1> {
    let containment = match cursor.u8()? {
        1 => ContainmentStrategy::WorkspaceBoundV1,
        2 => ContainmentStrategy::SameUserCompositeV1,
        3 => ContainmentStrategy::SameUserCompositeV2,
        _ => return Err(MalformedWire),
    };
    let posture = match cursor.u8()? {
        0 => FilesystemPosture::None,
        2 => FilesystemPosture::BroadSameUser,
        1 => {
            let count = usize::from(cursor.u8()?);
            if !(1..=64).contains(&count) {
                return Err(MalformedWire);
            }
            let mut roots = BTreeSet::new();
            for _ in 0..count {
                let root = read_root(cursor)?;
                if roots.last().is_some_and(|previous| previous >= &root) {
                    return Err(MalformedWire);
                }
                roots.insert(root);
            }
            FilesystemPosture::BoundedRoots(roots)
        }
        _ => return Err(MalformedWire),
    };
    let count = cursor.u8()?;
    if count > 4 {
        return Err(MalformedWire);
    }
    let mut permissions = BTreeSet::new();
    let mut previous = 0;
    for _ in 0..count {
        let tag = cursor.u8()?;
        if tag <= previous {
            return Err(MalformedWire);
        }
        previous = tag;
        permissions.insert(match tag {
            1 => FilesystemPermission::Read,
            2 => FilesystemPermission::Create,
            3 => FilesystemPermission::Write,
            4 => FilesystemPermission::Delete,
            _ => return Err(MalformedWire),
        });
    }
    let network = match cursor.u8()? {
        0 => NetworkScope::None,
        2 => NetworkScope::BroadSameUser,
        _ => return Err(MalformedWire),
    };
    if cursor.u8()? != 3 {
        return Err(MalformedWire);
    }
    let children = match cursor.u8()? {
        0 => ChildDelegationScope::None,
        1 => ChildDelegationScope::MaxDepth(cursor.u16()?),
        2 => ChildDelegationScope::Unbounded,
        _ => return Err(MalformedWire),
    };
    let budget = EffectBudget {
        max_operations: cursor.option()?,
        max_bytes: cursor.option()?,
    };
    Ok(ScopeDataV1 {
        containment,
        filesystem: FilesystemScope {
            posture,
            permissions,
        },
        network,
        children,
        budget,
        lifetime_ms: cursor.u64()?,
        protected: IntegrityDigest::from_bytes(cursor.array()?),
    })
}
fn read_root(cursor: &mut Cursor<'_>) -> Result<FilesystemRoot, ContextErrorV1> {
    let identity = IntegrityDigest::from_bytes(cursor.array()?);
    let count = usize::from(cursor.u16()?);
    if count > 256 {
        return Err(MalformedWire);
    }
    let mut components = Vec::new();
    let mut joined = if count == 0 { 0 } else { count - 1 };
    for _ in 0..count {
        let length = usize::from(cursor.u16()?);
        if !(1..=255).contains(&length) {
            return Err(MalformedWire);
        }
        joined = joined.checked_add(length).ok_or(MalformedWire)?;
        if joined > 4096 {
            return Err(MalformedWire);
        }
        let value = std::str::from_utf8(cursor.take(length)?).map_err(|_| MalformedWire)?;
        components.push(value.to_owned());
    }
    FilesystemRoot::new(identity, components).map_err(|_| InvalidOriginalData)
}
