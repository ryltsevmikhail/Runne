#[path = "bodies.rs"]
mod bodies;
#[path = "calls.rs"]
mod calls;
#[path = "implementer_names.rs"]
mod implementer_names;
#[path = "macro_definitions.rs"]
mod macro_definitions;
#[path = "macro_scope.rs"]
mod macro_scope;
#[path = "metadata.rs"]
mod metadata;
#[path = "source_parse.rs"]
mod source_parse;
#[path = "syntax.rs"]
mod syntax;
#[path = "visitor.rs"]
mod visitor;
#[path = "visitor_types.rs"]
mod visitor_types;

use std::collections::BTreeSet;
use std::path::PathBuf;

use syn::ItemImpl;

use implementer_names::{implementer_modules, local_implementer_names, qualification_implementers};
use metadata::{is_known_target, last_path_segment};
use source_parse::{ParsedSource, parse_source};
pub(super) use syntax::{item_attrs, item_is_test_only};
use visitor::Call;

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

pub(super) fn find_production_callers(sources: &[SourceUnit]) -> Vec<Finding> {
    let mut parsed = Vec::new();
    let mut findings = Vec::new();
    for unit in sources.iter().filter(|unit| !unit.test_only) {
        let Some(source) = parse_source(unit) else {
            if unit.source.contains("qualify") || unit.source.contains(QUALIFICATION_PORT) {
                findings.push(Finding {
                    path: unit.path.clone(),
                    reason: "production source with qualification syntax is not parseable",
                });
            }
            continue;
        };
        parsed.push(source);
    }

    let public_aliases = public_aliases(&parsed);
    let qualification_names = qualification_names(&parsed);
    let reexport_modules = public_reexport_modules(&parsed, &public_aliases);
    let implementers = qualification_implementers(&parsed, &qualification_names);
    let implementer_modules = implementer_modules(&parsed, &implementers, &qualification_names);
    for source in &parsed {
        let local_names =
            local_qualification_names(source, &qualification_names, &reexport_modules);
        let concrete_names = local_implementer_names(
            source,
            &implementers,
            &qualification_names,
            &implementer_modules,
        );
        let (calls, macro_definitions) =
            calls::collect(&source.file.items, &local_names, &concrete_names);
        for call in calls {
            let relevant = match call {
                Call::Path {
                    qualifier,
                    subject,
                    qself,
                    qualification_context,
                } => {
                    source
                        .unit
                        .path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        == Some("inc")
                        || qualifier
                            .as_ref()
                            .is_some_and(|name| local_names.contains(name))
                        || qualifier
                            .as_ref()
                            .is_some_and(|name| implementers.contains(name))
                        || qualification_context
                        || (qself && subject.is_some_and(|name| implementers.contains(&name)))
                }
                Call::Method {
                    from_qualification_body,
                    qualification_context,
                } => {
                    from_qualification_body
                        || qualification_context
                        || source
                            .unit
                            .path
                            .extension()
                            .and_then(|extension| extension.to_str())
                            == Some("inc")
                }
                Call::Macro {
                    name,
                    unqualified,
                    qualification_context,
                    selects_qualification,
                    scope,
                    position,
                } => macro_definitions::is_relevant(
                    &macro_definitions,
                    &name,
                    unqualified,
                    qualification_context,
                    selects_qualification,
                    &scope,
                    position,
                ),
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

pub(super) fn impl_is_qualification(item: &ItemImpl, names: &BTreeSet<String>) -> bool {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| last_path_segment(path))
        .is_some_and(|name| names.contains(&name))
}
