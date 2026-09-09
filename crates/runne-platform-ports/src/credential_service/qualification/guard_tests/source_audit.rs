#[path = "attributes.rs"]
mod attributes;
#[path = "bodies.rs"]
mod bodies;
#[path = "call_provenance.rs"]
mod call_provenance;
#[path = "calls.rs"]
mod calls;
#[path = "implementer_names.rs"]
mod implementer_names;
#[path = "macro_definitions.rs"]
mod macro_definitions;
#[path = "macro_scope.rs"]
mod macro_scope;
#[path = "macro_tokens.rs"]
mod macro_tokens;
#[path = "macro_trust.rs"]
mod macro_trust;
#[path = "metadata.rs"]
mod metadata;
#[path = "source_parse.rs"]
mod source_parse;
#[path = "source_semantics.rs"]
mod source_semantics;
#[path = "syntax.rs"]
mod syntax;
#[path = "visitor.rs"]
mod visitor;
#[path = "visitor_state.rs"]
mod visitor_state;
#[path = "visitor_types.rs"]
mod visitor_types;

pub(super) use macro_trust::source_shadows_root;

use std::collections::BTreeSet;
use std::path::PathBuf;

use implementer_names::{implementer_modules, local_implementer_names, qualification_implementers};
use source_parse::{ParsedSource, parse_source};
use source_semantics::{
    local_qualification_names, public_aliases, public_reexport_modules, qualification_names,
    unrelated_type_names,
};
pub(super) use syntax::{item_attrs, item_is_test_only};
use visitor::Call;

const QUALIFICATION_PORT: &str = "CredentialServiceQualificationPort";

#[derive(Clone)]
pub(super) struct SourceUnit {
    pub(super) path: PathBuf,
    pub(super) source: String,
    pub(super) test_only: bool,
    pub(super) trusted_external_roots: BTreeSet<String>,
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
            findings.push(Finding {
                path: unit.path.clone(),
                reason: "production source is not parseable as a complete Rust file",
            });
            continue;
        };
        parsed.push(source);
    }

    let public_aliases = public_aliases(&parsed);
    let qualification_names = qualification_names(&parsed);
    let unrelated_type_names = unrelated_type_names(&parsed, &qualification_names);
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
        let (calls, macro_definitions) = calls::collect(
            &source.file.items,
            &local_names,
            &concrete_names,
            &unrelated_type_names,
            &source.unit.trusted_external_roots,
        );
        for call in calls {
            let relevant = match call {
                Call::Path {
                    qualifier,
                    subject,
                    qself,
                    qualification_context,
                } => {
                    source_is_fragment(source)
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
                            .is_some_and(|value| value == "inc")
                }
                Call::Macro {
                    name,
                    trusted_path,
                    disposition,
                    scope,
                    position,
                    payload,
                } => {
                    let disposition = resolved_macro_disposition(
                        source,
                        &parsed,
                        &macro_definitions,
                        &name,
                        trusted_path.as_deref(),
                        disposition,
                        &scope,
                    );
                    macro_definitions::is_relevant(
                        &macro_definitions,
                        &name,
                        disposition,
                        &scope,
                        position,
                        payload.as_ref(),
                    )
                }
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

fn source_is_fragment(source: &ParsedSource) -> bool {
    source
        .unit
        .path
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("inc")
}

fn resolved_macro_disposition(
    source: &ParsedSource,
    parsed: &[ParsedSource],
    definitions: &macro_definitions::Index,
    name: &str,
    trusted_path: Option<&str>,
    disposition: visitor::MacroDisposition,
    scope: &[String],
) -> visitor::MacroDisposition {
    let unresolved = matches!(
        disposition,
        visitor::MacroDisposition::ResolveLocal | visitor::MacroDisposition::ResolveContext
    );
    let trusted_fallback = definitions.allows_trusted_fallback(name, scope)
        && !macro_trust::has_macro_use(&source.file);
    if unresolved
        && (macro_trust::trusted_local_macro_import(&source.file, name)
            || (trusted_fallback && macro_definitions::is_compiler_builtin_macro(name))
            || (trusted_fallback
                && macro_trust::trusted_bare_root(name)
                    .is_some_and(|root| source.unit.trusted_external_roots.contains(root))))
    {
        return visitor::MacroDisposition::ResolveTrusted;
    }
    if unresolved && macro_trust::has_macro_use(&source.file) {
        return visitor::MacroDisposition::OpaqueExternal;
    }
    if trusted_path.is_some_and(|path| {
        let mut segments = path.split("::");
        let root = segments.next().unwrap_or_default();
        let symbol = segments.next();
        (!matches!(root, "core" | "std") && !source.unit.trusted_external_roots.contains(root))
            || source_or_glob_shadows_root(source, parsed, root)
            || symbol.is_some_and(|symbol| {
                macro_trust::source_shadows_symbol(&source.file, symbol, root)
            })
    }) {
        return visitor::MacroDisposition::OpaqueExternal;
    }
    disposition
}

fn source_or_glob_shadows_root(
    source: &ParsedSource,
    sources: &[ParsedSource],
    root: &str,
) -> bool {
    if macro_trust::source_shadows_root(&source.file, root) {
        return true;
    }
    let modules = macro_trust::local_glob_modules(&source.file);
    !modules.is_empty()
        && sources
            .iter()
            .any(|candidate| macro_trust::source_shadows_root(&candidate.file, root))
}
