#[path = "bodies.rs"]
mod bodies;
#[path = "metadata.rs"]
mod metadata;
#[path = "syntax.rs"]
mod syntax;
#[path = "visitor.rs"]
mod visitor;

use std::collections::BTreeSet;
use std::path::PathBuf;

use syn::visit::Visit;
use syn::{File, Item, ItemImpl};

use metadata::{collect_metadata, is_known_target, last_path_segment};
pub(super) use syntax::{item_attrs, item_is_test_only};
use visitor::{Call, CallVisitor, macro_mentions_qualification};

const QUALIFICATION_PORT: &str = "CredentialServiceQualificationPort";

#[derive(Clone)]
pub(super) struct SourceUnit {
    pub(super) path: PathBuf,
    pub(super) source: String,
    pub(super) test_only: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Finding {
    pub(super) path: PathBuf,
    reason: &'static str,
}

struct ParsedSource {
    unit: SourceUnit,
    file: File,
    bindings: Vec<metadata::Binding>,
    impls: Vec<metadata::ImplRecord>,
    supertraits: Vec<metadata::SupertraitRecord>,
}

pub(super) fn find_production_callers(sources: &[SourceUnit]) -> Vec<Finding> {
    let mut parsed = Vec::new();
    let mut findings = Vec::new();
    for unit in sources.iter().filter(|unit| !unit.test_only) {
        let Ok(file) = syn::parse_file(&unit.source) else {
            if unit.source.contains("qualify") || unit.source.contains(QUALIFICATION_PORT) {
                findings.push(Finding {
                    path: unit.path.clone(),
                    reason: "production source with qualification syntax is not parseable",
                });
            }
            continue;
        };
        let mut bindings = Vec::new();
        let mut impls = Vec::new();
        let mut supertraits = Vec::new();
        collect_metadata(&file.items, &mut bindings, &mut impls, &mut supertraits);
        parsed.push(ParsedSource {
            unit: unit.clone(),
            file,
            bindings,
            impls,
            supertraits,
        });
    }

    let public_aliases = public_aliases(&parsed);
    let direct_qualification_names = qualification_names(&parsed);
    let qualification_names = metadata::qualification_names_with_supertraits(
        &direct_qualification_names,
        parsed.iter().flat_map(|source| source.supertraits.iter()),
    );
    let reexport_modules = public_reexport_modules(&parsed, &public_aliases);
    let implementers = qualification_implementers(&parsed, &qualification_names);
    for source in &parsed {
        let local_names =
            local_qualification_names(source, &qualification_names, &reexport_modules);
        let concrete_names = local_implementer_names(source, &implementers);
        let evidence = source.bindings.iter().any(|binding| {
            binding.local.is_some()
                && (is_known_target(&binding.target, &public_aliases)
                    || is_known_target(&binding.target, &implementers))
        }) || !concrete_names.is_empty()
            || source
                .unit
                .path
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("inc");
        let mut calls = Vec::new();
        collect_calls(&source.file.items, &local_names, &mut calls);
        let has_qualification_bound = calls.iter().any(|call| match call {
            Call::TraitBound { name } => qualification_names.contains(name),
            _ => false,
        });
        for call in calls {
            let relevant = match call {
                Call::Path {
                    qualifier,
                    subject,
                    qself,
                } => {
                    source
                        .unit
                        .path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        == Some("inc")
                        || qualifier.is_some_and(|name| local_names.contains(&name))
                        || (qself && subject.is_some_and(|name| implementers.contains(&name)))
                }
                Call::Method {
                    from_qualification_body,
                } => evidence || has_qualification_bound || from_qualification_body,
                Call::TraitBound { .. } => false,
                Call::Macro => true,
            };
            if relevant {
                findings.push(Finding {
                    path: source.unit.path.clone(),
                    reason: "production qualification port invocation",
                });
            }
        }
    }
    findings
}

fn collect_calls(items: &[Item], local_names: &BTreeSet<String>, calls: &mut Vec<Call>) {
    for item in items {
        if item_is_test_only(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Trait(item) if item.ident == QUALIFICATION_PORT => {
                bodies::collect_trait_bodies(item, calls);
            }
            Item::Trait(item) => {
                let mut visitor = CallVisitor::new();
                visitor.visit_item_trait(item);
                calls.extend(visitor.calls);
            }
            Item::Impl(item) if impl_is_qualification(item, local_names) => {
                bodies::collect_impl_bodies(item, calls);
            }
            Item::Macro(item) if macro_mentions_qualification(&item.mac) => calls.push(Call::Macro),
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_calls(nested, local_names, calls);
                }
            }
            _ => {
                let mut visitor = CallVisitor::new();
                visitor.visit_item(item);
                calls.extend(visitor.calls);
            }
        }
    }
}

fn public_aliases(sources: &[ParsedSource]) -> BTreeSet<String> {
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

fn qualification_implementers(
    sources: &[ParsedSource],
    aliases: &BTreeSet<String>,
) -> BTreeSet<String> {
    sources
        .iter()
        .flat_map(|source| source.impls.iter())
        .filter(|item| {
            item.trait_name
                .as_ref()
                .is_some_and(|name| aliases.contains(name))
        })
        .filter_map(|item| item.self_name.clone())
        .collect()
}

fn qualification_names(sources: &[ParsedSource]) -> BTreeSet<String> {
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
        }
        if known.len() == previous {
            return known;
        }
    }
}

fn public_reexport_modules(
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

fn local_qualification_names(
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

fn local_implementer_names(
    source: &ParsedSource,
    implementers: &BTreeSet<String>,
) -> BTreeSet<String> {
    source
        .bindings
        .iter()
        .filter_map(|binding| binding.local.as_ref())
        .filter(|local| implementers.contains(*local))
        .cloned()
        .collect()
}

fn impl_is_qualification(item: &ItemImpl, names: &BTreeSet<String>) -> bool {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| last_path_segment(path))
        .is_some_and(|name| names.contains(&name))
}
