use super::semantic_index::{Resolution, SemanticIndex};
use super::semantic_index_imports::ImportRecord;
use super::source_model::{ScopeId, TypeDefId, ValueDefId};
use super::symbols::{ModuleRecord, TypeKind, TypeRecord};

pub(super) fn resolve_type(
    index: &SemanticIndex,
    scope: ScopeId,
    path: &syn::Path,
) -> Resolution<TypeDefId> {
    let parts = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    super::semantic_index_imports::resolve_indexed_type_parts(index, scope, &parts)
}

pub(super) fn resolve_type_parts(
    modules: &[ModuleRecord],
    types: &[TypeRecord],
    imports: &[ImportRecord],
    scope: ScopeId,
    parts: &[String],
) -> Resolution<TypeDefId> {
    if parts.is_empty() {
        return Resolution::Missing;
    }
    if parts
        .first()
        .is_some_and(|part| part == "runne_macos_process_identity")
        && parts
            .last()
            .is_some_and(|part| part == "MacOsPendingCredentialServicePackageObservationV1")
    {
        let canonical = types
            .iter()
            .filter(|record| {
                matches!(record.kind, TypeKind::CanonicalTarget)
                    && record.source == super::source_model::SourceId(u32::MAX)
            })
            .map(|record| record.id)
            .collect();
        return resolution(canonical);
    }
    let mut candidates = direct_type_candidates(modules, types, scope, parts);
    if candidates.is_empty() && parts.len() == 1 {
        for import in imports.iter().filter(|import| import.scope == scope) {
            let named = import.alias.as_deref() == Some(parts[0].as_str());
            if named {
                if is_canonical_path(&import.path) {
                    candidates.extend(canonical_candidates(types));
                } else {
                    candidates.extend(direct_type_candidates(modules, types, scope, &import.path));
                }
            } else if import.glob {
                let mut imported = import.path.clone();
                imported.push(parts[0].clone());
                candidates.extend(direct_type_candidates(modules, types, scope, &imported));
            }
        }
    }
    if candidates.is_empty() && parts.len() > 1 {
        candidates.extend(qualified_import_candidates(
            modules, types, imports, scope, parts,
        ));
    }
    resolution(candidates)
}

fn qualified_import_candidates(
    modules: &[ModuleRecord],
    types: &[TypeRecord],
    imports: &[ImportRecord],
    scope: ScopeId,
    parts: &[String],
) -> Vec<TypeDefId> {
    let Some(current) = modules.iter().find(|module| module.scope == scope) else {
        return Vec::new();
    };
    let (module_path, name) = parts.split_at(parts.len() - 1);
    let mut candidates = Vec::new();
    for path in super::semantic_index_imports::candidate_module_paths(current, module_path) {
        let Some(module) = modules.iter().find(|module| {
            module.package == current.package
                && module.target == current.target
                && module.path == path
        }) else {
            continue;
        };
        for import in imports.iter().filter(|import| import.scope == module.scope) {
            if import.alias.as_deref() != Some(name[0].as_str()) {
                continue;
            }
            if is_canonical_path(&import.path) {
                candidates.extend(canonical_candidates(types));
            } else {
                candidates.extend(direct_type_candidates(
                    modules,
                    types,
                    module.scope,
                    &import.path,
                ));
            }
        }
    }
    candidates
}

pub(super) fn is_canonical_path(parts: &[String]) -> bool {
    parts
        .first()
        .is_some_and(|part| part == "runne_macos_process_identity")
        && parts
            .last()
            .is_some_and(|part| part == "MacOsPendingCredentialServicePackageObservationV1")
}

pub(super) fn canonical_candidates(types: &[TypeRecord]) -> Vec<TypeDefId> {
    types
        .iter()
        .filter(|record| {
            matches!(record.kind, TypeKind::CanonicalTarget)
                && record.source == super::source_model::SourceId(u32::MAX)
        })
        .map(|record| record.id)
        .collect()
}

fn direct_type_candidates(
    modules: &[ModuleRecord],
    types: &[TypeRecord],
    scope: ScopeId,
    parts: &[String],
) -> Vec<TypeDefId> {
    let Some(current) = modules.iter().find(|module| module.scope == scope) else {
        return Vec::new();
    };
    let (module_path, name) = parts.split_at(parts.len() - 1);
    let name = &name[0];
    let roots = super::semantic_index_imports::candidate_module_paths(current, module_path);
    let mut result = Vec::new();
    for root in roots {
        let Some(module) = modules.iter().find(|module| {
            module.package == current.package
                && module.target == current.target
                && module.path == root
        }) else {
            continue;
        };
        result.extend(
            types
                .iter()
                .filter(|record| record.scope == module.scope && record.name == *name)
                .map(|record| record.id),
        );
    }
    result.sort_unstable();
    result.dedup();
    result
}

pub(super) fn resolve_value(
    index: &SemanticIndex,
    scope: ScopeId,
    path: &syn::Path,
) -> Resolution<ValueDefId> {
    let parts = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        let owner_path = &parts[..parts.len() - 1];
        if let Resolution::Exact(owner) =
            super::semantic_index_imports::resolve_indexed_type_parts(index, scope, owner_path)
        {
            return resolution(
                index
                    .associated_value_ids(owner, &parts[parts.len() - 1])
                    .to_vec(),
            );
        }
    }
    let Some(current) = index.module(scope) else {
        return Resolution::Missing;
    };
    let (module_path, name) = parts.split_at(parts.len().saturating_sub(1));
    let Some(name) = name.first() else {
        return Resolution::Missing;
    };
    let mut candidates = Vec::new();
    for path in super::semantic_index_imports::candidate_module_paths(current, module_path) {
        if let Some(module) = index.module_at(current.package, current.target, &path) {
            candidates.extend(
                index
                    .value_ids(module.scope, name)
                    .iter()
                    .copied()
                    .filter(|id| {
                        index
                            .value_record(*id)
                            .is_some_and(|record| record.owner.is_none())
                    }),
            );
        }
    }
    resolution(candidates)
}

pub(super) fn canonical_type(
    index: &SemanticIndex,
    id: TypeDefId,
    stack: &mut Vec<TypeDefId>,
) -> Resolution<TypeDefId> {
    if stack.contains(&id) {
        return Resolution::Ambiguous(stack.clone());
    }
    let Some(record) = index.type_record(id) else {
        return Resolution::Missing;
    };
    match &record.kind {
        TypeKind::Alias(alias) if matches!(alias.as_ref(), syn::Type::Path(_)) => {
            let syn::Type::Path(path) = alias.as_ref() else {
                unreachable!("guarded alias path")
            };
            stack.push(id);
            let resolved = match index.resolve_type(record.scope, &path.path) {
                Resolution::Exact(target) => canonical_type(index, target, stack),
                Resolution::Ambiguous(values) => Resolution::Ambiguous(values),
                Resolution::Missing => Resolution::Missing,
            };
            stack.pop();
            resolved
        }
        TypeKind::CanonicalTarget => resolution(
            index
                .types
                .iter()
                .filter(|candidate| {
                    matches!(candidate.kind, TypeKind::CanonicalTarget)
                        && candidate.source == super::source_model::SourceId(u32::MAX)
                })
                .map(|candidate| candidate.id)
                .collect(),
        ),
        _ => Resolution::Exact(id),
    }
}

pub(super) fn resolution<T: Ord>(mut values: Vec<T>) -> Resolution<T> {
    values.sort();
    values.dedup();
    match values.len() {
        0 => Resolution::Missing,
        1 => Resolution::Exact(values.remove(0)),
        _ => Resolution::Ambiguous(values),
    }
}
