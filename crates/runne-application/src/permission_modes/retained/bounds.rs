//! Borrowed size checks run before retained hashes, comparisons, or clones.

use crate::permission_modes::{
    composite::{CompositeEffectScope, FilesystemPosture},
    local_command_binding::LocalCommandPermissionBindingV1,
    retained::{
        RetainedAdmissionEvidenceV1, RetainedCurrentFactsInputV1, RetainedCurrentFactsV1,
        RetainedHumanEvidenceInputV1, RetainedHumanEvidenceV1, RetainedOriginalContextV1,
        RetainedOwnerCoordinatesV1, RetainedPolicyInputV1,
    },
};
use runne_domain::task_run::{
    MAX_LOCAL_COMMAND_ARGV, MAX_LOCAL_COMMAND_BYTES, MAX_LOCAL_COMMAND_ENV, TaskRunLocalCommand,
};

const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

fn add(total: &mut usize, amount: usize) -> bool {
    total.checked_add(amount).is_some_and(|next| {
        *total = next;
        next <= MAX_ENVELOPE_BYTES
    })
}

fn add_text(total: &mut usize, value: &str, max: usize) -> bool {
    value.len() <= max && add(total, value.len())
}

fn scope_size(scope: &CompositeEffectScope) -> Option<usize> {
    let mut total = 0;
    if !add_text(
        &mut total,
        &scope.permission_scope.runtime_authority_id.0,
        256,
    ) || !add_text(
        &mut total,
        scope.permission_scope.principal_id.as_str(),
        256,
    ) || !add(&mut total, 16 + 32 + 64)
    {
        return None;
    }
    if let FilesystemPosture::BoundedRoots(roots) = &scope.filesystem.posture {
        if roots.len() > 64 {
            return None;
        }
        for root in roots {
            if root.components.len() > 256 || root.root_identity.as_bytes().iter().all(|b| *b == 0)
            {
                return None;
            }
            let mut path_bytes = root.components.len().saturating_sub(1);
            if !add(&mut total, 32) {
                return None;
            }
            for component in &root.components {
                if component.is_empty()
                    || component == "."
                    || component == ".."
                    || component.contains('/')
                    || component.contains('\\')
                    || component.chars().any(char::is_control)
                    || component.len() > 255
                {
                    return None;
                }
                path_bytes = path_bytes.checked_add(component.len())?;
                if !add_text(&mut total, component, 255) {
                    return None;
                }
            }
            if path_bytes > 4096 {
                return None;
            }
        }
    }
    if !add(&mut total, scope.filesystem.permissions.len() + 128) {
        return None;
    }
    Some(total)
}

fn command_size(command: &TaskRunLocalCommand) -> Option<usize> {
    if command.argv().is_empty()
        || command.argv().len() > MAX_LOCAL_COMMAND_ARGV
        || command.env().len() > MAX_LOCAL_COMMAND_ENV
        || command.cwd().len() > 4096
        || command.executable().value().len() > 4096
    {
        return None;
    }
    let mut total = 0;
    if !add_text(&mut total, command.executable().value(), 4096)
        || !add_text(&mut total, command.cwd(), 4096)
    {
        return None;
    }
    for argument in command.argv() {
        if argument.len() > 16 * 1024 || argument.as_bytes().contains(&0) {
            return None;
        }
        if !add_text(&mut total, argument, 16 * 1024) {
            return None;
        }
    }
    for (key, value) in command.env() {
        let entry_len = key.len().checked_add(1)?.checked_add(value.len())?;
        if entry_len > 16 * 1024 || value.as_bytes().contains(&0) {
            return None;
        }
        if !add_text(&mut total, key, 16 * 1024) || !add_text(&mut total, value, 16 * 1024) {
            return None;
        }
    }
    (total <= MAX_LOCAL_COMMAND_BYTES).then_some(total)
}

fn coordinates_size(value: &RetainedOwnerCoordinatesV1) -> Option<usize> {
    let mut total = 0;
    if !add_text(&mut total, &value.runtime_authority_id, 256)
        || !add_text(&mut total, value.principal_id.as_str(), 256)
        || !add_text(&mut total, &value.assignment.node_id.0, 256)
        || !add_text(&mut total, &value.native_boundary_owner_id, 256)
        || !add(&mut total, 16 * 5 + 32 * 2 + 8 * 12)
    {
        return None;
    }
    Some(total)
}

fn binding_size(binding: &LocalCommandPermissionBindingV1) -> Option<usize> {
    let mut total = scope_size(binding.scope())?;
    if !add(&mut total, command_size(binding.command())?)
        || !add_text(&mut total, &binding.assignment().node_id.0, 256)
        || !add_text(&mut total, binding.approval().principal_id.as_str(), 256)
        || !add(&mut total, 512)
    {
        return None;
    }
    Some(total)
}

fn human_input_size(input: &RetainedHumanEvidenceInputV1) -> Option<usize> {
    let mut total = scope_size(&input.scope)?;
    if !add_text(&mut total, input.binding.principal_id.as_str(), 256)
        || !add_text(&mut total, input.accepted_by.as_str(), 256)
        || !add(&mut total, 512)
    {
        return None;
    }
    Some(total)
}

fn human_size(input: &RetainedHumanEvidenceV1) -> Option<usize> {
    let mut total = scope_size(input.scope())?;
    if !add_text(&mut total, input.binding().principal_id.as_str(), 256)
        || !add_text(&mut total, input.accepted_by().as_str(), 256)
        || !add(&mut total, 512)
    {
        return None;
    }
    Some(total)
}

fn current_parts_size(
    scope: &CompositeEffectScope,
    command: &TaskRunLocalCommand,
    coordinates: &RetainedOwnerCoordinatesV1,
    principal: &str,
    observation_owner: Option<&str>,
) -> Option<usize> {
    let mut total = scope_size(scope)?;
    if !add(&mut total, command_size(command)?)
        || !add(&mut total, coordinates_size(coordinates)?)
        || !add_text(&mut total, principal, 256)
        || !add(&mut total, 1024)
        || observation_owner.is_some_and(|owner| !add_text(&mut total, owner, 256))
    {
        return None;
    }
    Some(total)
}

pub(super) fn original_within_bounds(original: &LocalCommandPermissionBindingV1) -> bool {
    binding_size(original).is_some()
}

pub(super) fn original_context_within_bounds(context: &RetainedOriginalContextV1) -> bool {
    coordinates_size(&context.coordinates).is_some_and(|size| size + 128 <= MAX_ENVELOPE_BYTES)
}

pub(super) fn coordinates_within_bounds(coordinates: &RetainedOwnerCoordinatesV1) -> bool {
    coordinates_size(coordinates).is_some()
}

pub(super) fn current_input_within_bounds(input: &RetainedCurrentFactsInputV1) -> bool {
    current_parts_size(
        &input.scope,
        &input.command,
        &input.coordinates,
        input.candidate.principal_id.as_str(),
        input
            .observation_context
            .as_ref()
            .map(|observation| observation.native_boundary_owner_id.as_str()),
    )
    .is_some_and(|size| size <= MAX_ENVELOPE_BYTES)
}

pub(super) fn current_facts_within_bounds(input: &RetainedCurrentFactsV1) -> bool {
    current_parts_size(
        &input.scope,
        &input.command,
        &input.coordinates,
        input.candidate.principal_id.as_str(),
        input
            .observation_context
            .as_ref()
            .map(|observation| observation.native_boundary_owner_id.as_str()),
    )
    .is_some_and(|size| size <= MAX_ENVELOPE_BYTES)
}

pub(super) fn human_input_within_bounds(input: &RetainedHumanEvidenceInputV1) -> bool {
    human_input_size(input).is_some_and(|size| size <= MAX_ENVELOPE_BYTES)
}

pub(super) fn evaluate_input_within_bounds(
    input: &RetainedPolicyInputV1<'_>,
    resource_size: usize,
) -> bool {
    let mut total = 0;
    let Some(original_size) = binding_size(input.original) else {
        return false;
    };
    let Some(current_size) = current_parts_size(
        &input.current.scope,
        &input.current.command,
        &input.current.coordinates,
        input.current.candidate.principal_id.as_str(),
        input
            .current
            .observation_context
            .as_ref()
            .map(|observation| observation.native_boundary_owner_id.as_str()),
    ) else {
        return false;
    };
    if !add(&mut total, original_size)
        || !add(&mut total, current_size)
        || !add(&mut total, resource_size)
        || !add_text(
            &mut total,
            input.original_identity_candidate.principal_id.as_str(),
            256,
        )
    {
        return false;
    }
    if let Some(context) = input.original_context {
        let Some(size) = coordinates_size(&context.coordinates) else {
            return false;
        };
        if !add(&mut total, size + 128) {
            return false;
        }
    }
    if let RetainedAdmissionEvidenceV1::Human(proof) = input.admission {
        let Some(size) = human_size(proof) else {
            return false;
        };
        if !add(&mut total, size) {
            return false;
        }
    }
    if let Some(proof) = input.selected_human_candidate {
        let Some(size) = human_size(proof) else {
            return false;
        };
        if !add(&mut total, size) {
            return false;
        }
    }
    total <= MAX_ENVELOPE_BYTES
}
