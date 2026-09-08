use std::collections::BTreeSet;

use super::metadata::{alias_has_local_provenance, is_known_target};
use super::source_parse::ParsedSource;

pub(super) fn local_implementer_names(
    source: &ParsedSource,
    implementers: &BTreeSet<String>,
    qualification_names: &BTreeSet<String>,
    implementer_modules: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut names = source
        .bindings
        .iter()
        .filter_map(|binding| {
            binding.local.as_ref().filter(|_| {
                is_known_target(&binding.target, implementers)
                    && target_module(&binding.target)
                        .is_none_or(|module| implementer_modules.contains(module))
            })
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    names.extend(source.impls.iter().filter_map(|item| {
        item.trait_name
            .as_ref()
            .filter(|name| qualification_names.contains(*name))
            .and_then(|_| item.self_name.clone())
    }));
    names
}

pub(super) fn implementer_modules(
    sources: &[ParsedSource],
    implementers: &BTreeSet<String>,
    qualification_names: &BTreeSet<String>,
) -> BTreeSet<String> {
    sources
        .iter()
        .filter(|source| {
            source.impls.iter().any(|item| {
                item.self_name
                    .as_ref()
                    .is_some_and(|name| implementers.contains(name))
                    && item
                        .trait_name
                        .as_ref()
                        .is_some_and(|name| qualification_names.contains(name))
            }) || source
                .aliases
                .iter()
                .any(|alias| implementers.contains(&alias.name))
        })
        .filter_map(|source| source.unit.path.file_stem()?.to_str().map(str::to_owned))
        .collect()
}

fn target_module(target: &str) -> Option<&str> {
    let mut parts = target.rsplit("::");
    parts.next()?;
    parts
        .next()
        .filter(|part| !matches!(*part, "crate" | "self" | "super"))
}

pub(super) fn qualification_implementers(
    sources: &[ParsedSource],
    qualification_names: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut modules = sources
        .iter()
        .filter(|source| {
            source
                .impls
                .iter()
                .any(|item| is_qualification(item, qualification_names))
        })
        .filter_map(|source| source.unit.path.file_stem()?.to_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let mut known = sources
        .iter()
        .flat_map(|source| &source.impls)
        .filter(|item| is_qualification(item, qualification_names))
        .filter_map(|item| item.self_name.clone())
        .collect::<BTreeSet<_>>();
    loop {
        let previous = known.len();
        for source in sources {
            for alias in &source.aliases {
                let local = alias_has_local_provenance(
                    alias,
                    &source.aliases,
                    &source.bindings,
                    &source.impls,
                    qualification_names,
                    &known,
                );
                let qualified = alias.has_qualified_path
                    && alias
                        .qualified_modules
                        .iter()
                        .any(|name| modules.contains(name));
                if alias.bases.iter().any(|base| known.contains(base)) && (local || qualified) {
                    known.insert(alias.name.clone());
                    if let Some(module) =
                        source.unit.path.file_stem().and_then(|name| name.to_str())
                    {
                        modules.insert(module.to_owned());
                    }
                }
            }
        }
        if known.len() == previous {
            return known;
        }
    }
}

fn is_qualification(item: &super::metadata::ImplRecord, names: &BTreeSet<String>) -> bool {
    item.trait_name
        .as_ref()
        .is_some_and(|name| names.contains(name))
}
