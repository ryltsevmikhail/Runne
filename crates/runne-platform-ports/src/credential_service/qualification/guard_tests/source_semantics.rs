use std::collections::BTreeSet;

use syn::ItemImpl;

use super::metadata::{is_known_target, last_path_segment};
use super::source_parse::ParsedSource;
use super::{QUALIFICATION_PORT, syntax};

pub(super) fn unrelated_type_names(
    sources: &[ParsedSource],
    qualification_names: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for source in sources {
        names.extend(
            source
                .aliases
                .iter()
                .filter(|alias| !qualification_names.contains(&alias.name))
                .map(|alias| alias.name.clone()),
        );
        names.extend(source.file.items.iter().filter_map(|item| match item {
            syn::Item::Trait(item) => {
                let name = syntax::normalized_ident(&item.ident);
                (!qualification_names.contains(&name)).then_some(name)
            }
            _ => None,
        }));
        for binding in &source.bindings {
            let Some(local) = &binding.local else {
                continue;
            };
            let targets_unrelated_module = sources.iter().any(|candidate| {
                let module = candidate
                    .unit
                    .path
                    .file_stem()
                    .and_then(|stem| stem.to_str());
                module.is_some_and(|module| binding.target.split("::").any(|part| part == module))
                    && !candidate.file.items.iter().any(|item| match item {
                        syn::Item::Impl(item) => impl_is_qualification(item, qualification_names),
                        _ => false,
                    })
            });
            if targets_unrelated_module {
                names.insert(local.clone());
            }
        }
    }
    names
}

pub(super) fn public_aliases(sources: &[ParsedSource]) -> BTreeSet<String> {
    let mut known = BTreeSet::from([QUALIFICATION_PORT.to_owned()]);
    loop {
        let previous = known.len();
        for source in sources {
            for binding in &source.bindings {
                if binding.public
                    && binding
                        .local
                        .as_ref()
                        .is_some_and(|_| is_known_target(&binding.target, &known))
                {
                    known.insert(binding.local.clone().unwrap());
                }
            }
        }
        if known.len() == previous {
            return known;
        }
    }
}

pub(super) fn qualification_names(sources: &[ParsedSource]) -> BTreeSet<String> {
    let mut known = BTreeSet::from([QUALIFICATION_PORT.to_owned()]);
    loop {
        let previous = known.len();
        for source in sources {
            for binding in &source.bindings {
                if binding
                    .local
                    .as_ref()
                    .is_some_and(|_| is_known_target(&binding.target, &known))
                {
                    known.insert(binding.local.clone().unwrap());
                }
            }
            for alias in &source.aliases {
                if alias.bases.iter().any(|base| known.contains(base)) {
                    known.insert(alias.name.clone());
                }
            }
            for supertrait in &source.supertraits {
                if supertrait.bases.iter().any(|base| known.contains(base)) {
                    known.insert(supertrait.name.clone());
                }
            }
        }
        if known.len() == previous {
            return known;
        }
    }
}

pub(super) fn public_reexport_modules(
    sources: &[ParsedSource],
    aliases: &BTreeSet<String>,
) -> BTreeSet<String> {
    sources
        .iter()
        .filter(|source| {
            source.bindings.iter().any(|binding| {
                binding.public
                    && binding.local.is_some()
                    && is_known_target(&binding.target, aliases)
            })
        })
        .filter_map(|source| source.unit.path.file_stem())
        .filter_map(|stem| stem.to_str())
        .map(str::to_owned)
        .collect()
}

pub(super) fn local_qualification_names(
    source: &ParsedSource,
    aliases: &BTreeSet<String>,
    reexport_modules: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut names = aliases.clone();
    names.insert(QUALIFICATION_PORT.to_owned());
    for binding in &source.bindings {
        if let Some(local) = &binding.local {
            if is_known_target(&binding.target, aliases) {
                names.insert(local.clone());
            }
        } else if binding.target.ends_with("::*")
            && binding
                .target
                .split("::")
                .any(|segment| reexport_modules.contains(segment))
        {
            names.extend(aliases.iter().cloned());
        }
    }
    names
}

pub(super) fn impl_is_qualification(item: &ItemImpl, names: &BTreeSet<String>) -> bool {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| last_path_segment(path))
        .is_some_and(|name| names.contains(&name))
}
