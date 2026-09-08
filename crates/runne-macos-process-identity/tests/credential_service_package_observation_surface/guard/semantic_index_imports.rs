use super::semantic_index::{Resolution, SemanticIndex};
use super::semantic_index_resolve::{canonical_candidates, is_canonical_path, resolution};
use super::source_model::{ScopeId, TypeDefId};
use super::symbols::ModuleRecord;

#[derive(Clone)]
pub(super) struct ImportRecord {
    pub(super) scope: ScopeId,
    pub(super) path: Vec<String>,
    pub(super) alias: Option<String>,
    pub(super) glob: bool,
}

pub(super) fn use_records(scope: ScopeId, tree: &syn::UseTree) -> Vec<ImportRecord> {
    let mut records = Vec::new();
    collect_use(scope, tree, &mut Vec::new(), &mut records);
    records
}

pub(super) fn extern_crate_record(
    scope: ScopeId,
    item: &syn::ItemExternCrate,
) -> Option<ImportRecord> {
    item.rename.as_ref().map(|(_, alias)| ImportRecord {
        scope,
        path: vec![item.ident.to_string()],
        alias: Some(alias.to_string()),
        glob: false,
    })
}

fn collect_use(
    scope: ScopeId,
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    records: &mut Vec<ImportRecord>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use(scope, &path.tree, prefix, records);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut path = prefix.clone();
            path.push(name.ident.to_string());
            records.push(ImportRecord {
                scope,
                path,
                alias: Some(name.ident.to_string()),
                glob: false,
            });
        }
        syn::UseTree::Rename(rename) => {
            let mut path = prefix.clone();
            path.push(rename.ident.to_string());
            records.push(ImportRecord {
                scope,
                path,
                alias: Some(rename.rename.to_string()),
                glob: false,
            });
        }
        syn::UseTree::Glob(_) => records.push(ImportRecord {
            scope,
            path: prefix.clone(),
            alias: None,
            glob: true,
        }),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use(scope, item, prefix, records);
            }
        }
    }
}

pub(super) fn resolve_indexed_type_parts(
    index: &SemanticIndex,
    scope: ScopeId,
    parts: &[String],
) -> Resolution<TypeDefId> {
    resolve_indexed_type_parts_inner(index, scope, parts, &mut Vec::new())
}

fn resolve_indexed_type_parts_inner(
    index: &SemanticIndex,
    scope: ScopeId,
    parts: &[String],
    stack: &mut Vec<Vec<String>>,
) -> Resolution<TypeDefId> {
    if parts.is_empty() {
        return Resolution::Missing;
    }
    if is_canonical_path(parts) {
        return resolution(canonical_candidates(&index.types));
    }
    if stack.iter().any(|seen| seen == parts) {
        return Resolution::Missing;
    }
    stack.push(parts.to_vec());
    let mut candidates = indexed_type_candidates(index, scope, parts);
    if candidates.is_empty() && parts.len() == 1 {
        for import in index.imports.iter().filter(|import| import.scope == scope) {
            if import.alias.as_deref() == Some(parts[0].as_str()) {
                if is_canonical_path(&import.path) {
                    candidates.extend(canonical_candidates(&index.types));
                } else {
                    match resolve_indexed_type_parts_inner(index, scope, &import.path, stack) {
                        Resolution::Exact(id) => candidates.push(id),
                        Resolution::Ambiguous(ids) => candidates.extend(ids),
                        Resolution::Missing => {}
                    }
                }
            } else if import.glob {
                let mut imported = import.path.clone();
                imported.push(parts[0].clone());
                if is_canonical_path(&imported) {
                    candidates.extend(canonical_candidates(&index.types));
                } else {
                    candidates.extend(indexed_type_candidates(index, scope, &imported));
                }
            }
        }
    }
    if candidates.is_empty() && parts.len() > 1 {
        for import in index.imports.iter().filter(|import| import.scope == scope) {
            if import.alias.as_deref() != Some(parts[0].as_str()) {
                continue;
            }
            let mut imported = import.path.clone();
            imported.extend_from_slice(&parts[1..]);
            if is_canonical_path(&imported) {
                candidates.extend(canonical_candidates(&index.types));
            } else {
                candidates.extend(indexed_type_candidates(index, scope, &imported));
            }
        }
        candidates.extend(indexed_qualified_imports(index, scope, parts));
    }
    stack.pop();
    resolution(candidates)
}

fn indexed_type_candidates(
    index: &SemanticIndex,
    scope: ScopeId,
    parts: &[String],
) -> Vec<TypeDefId> {
    let Some(current) = index.module(scope) else {
        return Vec::new();
    };
    let (module_path, name) = parts.split_at(parts.len() - 1);
    let mut result = Vec::new();
    for path in candidate_module_paths(current, module_path) {
        if let Some(module) = index.module_at(current.package, current.target, &path) {
            result.extend_from_slice(index.type_ids(module.scope, &name[0]));
        }
    }
    result
}

fn indexed_qualified_imports(
    index: &SemanticIndex,
    scope: ScopeId,
    parts: &[String],
) -> Vec<TypeDefId> {
    let Some(current) = index.module(scope) else {
        return Vec::new();
    };
    let (module_path, name) = parts.split_at(parts.len() - 1);
    let mut candidates = Vec::new();
    for path in candidate_module_paths(current, module_path) {
        let Some(module) = index.module_at(current.package, current.target, &path) else {
            continue;
        };
        for import in index
            .imports
            .iter()
            .filter(|import| import.scope == module.scope)
        {
            if import.alias.as_deref() != Some(name[0].as_str()) {
                continue;
            }
            if is_canonical_path(&import.path) {
                candidates.extend(canonical_candidates(&index.types));
            } else {
                candidates.extend(indexed_type_candidates(index, module.scope, &import.path));
            }
        }
    }
    candidates
}

pub(super) fn candidate_module_paths(current: &ModuleRecord, parts: &[String]) -> Vec<Vec<String>> {
    if parts.first().is_some_and(|part| {
        matches!(
            part.as_str(),
            "crate" | super::inventory_macro_semantic::DEFINITION_CRATE_MARKER
        )
    }) {
        return vec![parts[1..].to_vec()];
    }
    if parts.first().is_some_and(|part| part == "self") {
        let mut path = current.path.clone();
        path.extend_from_slice(&parts[1..]);
        return vec![path];
    }
    if parts.first().is_some_and(|part| part == "super") {
        let mut path = current.path.clone();
        let mut offset = 0;
        while parts.get(offset).is_some_and(|part| part == "super") {
            path.pop();
            offset += 1;
        }
        path.extend_from_slice(&parts[offset..]);
        return vec![path];
    }
    let mut roots = Vec::new();
    let mut lexical = current.path.clone();
    loop {
        let mut path = lexical.clone();
        path.extend_from_slice(parts);
        roots.push(path);
        if lexical.pop().is_none() {
            break;
        }
    }
    roots
}
