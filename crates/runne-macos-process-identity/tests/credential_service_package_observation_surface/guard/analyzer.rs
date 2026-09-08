use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::bodies::{
    BodyEngine, CallEvidence, EvaluationMode, FunctionSummary, UnresolvedEvidence,
};
use super::bodies_types::{FactResolver, TypeFactCache};
use super::provenance::{CallableFact, UnresolvedReason, ValueFact};
use super::semantic_index::{IndexError, SemanticIndex};
use super::source_model::{SourceId, SyntaxId, ValueDefId};
use super::symbols::{BodySyntax, ValueKind};

#[path = "attributes.rs"]
pub(super) mod attributes;

const SUMMARY_LIMIT: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum GuardVerdict {
    Clean,
    Calls(Vec<CallSite>),
    Inconclusive(Vec<UnresolvedSite>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallSite {
    pub(super) source: SourceId,
    pub(super) syntax: SyntaxId,
    pub(super) method: super::provenance::TargetMethod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UnresolvedSite {
    pub(super) source: Option<SourceId>,
    pub(super) syntax: Option<SyntaxId>,
    pub(super) reason: UnresolvedReason,
    pub(super) detail: String,
}

pub(super) fn analyze_source(source: &str) -> GuardVerdict {
    match SemanticIndex::from_source(source) {
        Ok(index) => analyze(&index),
        Err(error) => index_error(error),
    }
}

pub(super) fn analyze(index: &SemanticIndex) -> GuardVerdict {
    let type_facts = TypeFactCache::default();
    let summaries = match build_summaries(index, &type_facts) {
        Ok(summaries) => summaries,
        Err(site) => return GuardVerdict::Inconclusive(vec![site]),
    };
    let mut calls = Vec::new();
    let mut unresolved = index
        .opaque_source_macros
        .iter()
        .map(|site| UnresolvedSite {
            source: Some(site.source),
            syntax: None,
            reason: UnresolvedReason::OpaqueSourceMacro,
            detail: format!(
                "opaque production source macro expansion: {}",
                site.macro_path
            ),
        })
        .collect::<Vec<_>>();
    unresolved.extend(attributes::analyze(index));
    for body in index.bodies() {
        let evaluation = BodyEngine::evaluate(
            index,
            body,
            &summaries.values,
            &summaries.functions,
            &type_facts,
            EvaluationMode::Analyze,
        );
        calls.extend(evaluation.calls.iter().map(call_site));
        unresolved.extend(evaluation.unresolved.into_iter().map(unresolved_site));
    }
    for item in &index.items {
        let syn::Item::Macro(item_macro) = &item.item else {
            continue;
        };
        if item_macro.ident.is_some() {
            continue;
        }
        let evaluation = super::macro_semantics::analyze_item_macro(
            index,
            super::macro_semantics::ItemMacroContext {
                source: item.source,
                syntax: item.syntax,
                scope: item.scope,
            },
            &item_macro.mac,
            super::macro_semantics::MacroFacts {
                values: &summaries.values,
                functions: &summaries.functions,
                type_facts: &type_facts,
            },
        );
        calls.extend(evaluation.calls.iter().map(call_site));
        unresolved.extend(evaluation.unresolved.into_iter().map(unresolved_site));
    }
    calls.sort_by_key(|site| (site.source, site.syntax));
    calls.dedup();
    unresolved.sort_by_key(|site| (site.source, site.syntax));
    unresolved.dedup();
    if !calls.is_empty() {
        GuardVerdict::Calls(calls)
    } else if !unresolved.is_empty() {
        GuardVerdict::Inconclusive(unresolved)
    } else {
        GuardVerdict::Clean
    }
}

struct Summaries {
    values: HashMap<ValueDefId, ValueFact>,
    functions: HashMap<ValueDefId, FunctionSummary>,
}

fn build_summaries(
    index: &SemanticIndex,
    type_facts: &TypeFactCache,
) -> Result<Summaries, UnresolvedSite> {
    let mut values = initial_values(index, type_facts);
    let mut functions = HashMap::new();
    for _ in 0..SUMMARY_LIMIT {
        let mut next_values = values.clone();
        let mut next_functions = functions.clone();
        for body in index.bodies() {
            let evaluation = BodyEngine::evaluate(
                index,
                body,
                &values,
                &functions,
                type_facts,
                EvaluationMode::Summary,
            );
            let Some(record) = index.value_record(body.owner) else {
                continue;
            };
            match &record.kind {
                ValueKind::Function { .. } => {
                    let summary = FunctionSummary {
                        output: evaluation.output,
                        invoked_parameters: evaluation.invoked_parameters,
                        parameter_effects: evaluation.parameter_effects,
                    };
                    next_values.insert(
                        record.id,
                        ValueFact::Callable(CallableFact {
                            output: Box::new(summary.output.clone()),
                            invoked_parameters: summary.invoked_parameters.clone(),
                            parameter_effects: summary.parameter_effects.clone(),
                        }),
                    );
                    next_functions.insert(record.id, summary);
                }
                ValueKind::Const { .. } | ValueKind::Static { .. } => {
                    next_values.insert(record.id, evaluation.output);
                }
            }
        }
        if next_values == values && next_functions == functions {
            return Ok(Summaries { values, functions });
        }
        values = next_values;
        functions = next_functions;
    }
    let first = index.bodies().next();
    Err(UnresolvedSite {
        source: first.map(|body| body.source),
        syntax: first.map(|body| body.syntax),
        reason: UnresolvedReason::FixedPointLimit,
        detail: "semantic item summaries did not converge".into(),
    })
}

fn initial_values(
    index: &SemanticIndex,
    type_facts: &TypeFactCache,
) -> HashMap<ValueDefId, ValueFact> {
    let empty = HashMap::new();
    let resolver = FactResolver::new(index, &empty, type_facts);
    index
        .values()
        .map(|record| {
            let fact = if record.canonical_method.is_some() {
                resolver.value_fact(record.id)
            } else {
                match &record.kind {
                    ValueKind::Function { body: Some(body) } => index
                        .body_record(*body)
                        .and_then(|body| match body.syntax_tree.as_ref() {
                            BodySyntax::Function { signature, .. } => {
                                Some(ValueFact::Callable(CallableFact {
                                    output: Box::new(
                                        resolver.return_fact(record.scope, &signature.output),
                                    ),
                                    invoked_parameters: BTreeSet::default(),
                                    parameter_effects: BTreeMap::default(),
                                }))
                            }
                            BodySyntax::Initializer { .. } => None,
                        })
                        .unwrap_or(ValueFact::NonTarget),
                    ValueKind::Function { body: None } => ValueFact::NonTarget,
                    ValueKind::Const { ty, .. } | ValueKind::Static { ty, .. } => {
                        resolver.type_fact(record.scope, ty)
                    }
                }
            };
            (record.id, fact)
        })
        .collect()
}

const fn call_site(evidence: &CallEvidence) -> CallSite {
    CallSite {
        source: evidence.source,
        syntax: evidence.syntax,
        method: evidence.method,
    }
}

fn unresolved_site(evidence: UnresolvedEvidence) -> UnresolvedSite {
    UnresolvedSite {
        source: Some(evidence.source),
        syntax: Some(evidence.syntax),
        reason: evidence.reason,
        detail: "target-relevant invocation could not be proven".into(),
    }
}

fn index_error(error: IndexError) -> GuardVerdict {
    GuardVerdict::Inconclusive(vec![UnresolvedSite {
        source: error.source,
        syntax: None,
        reason: UnresolvedReason::AmbiguousResolution,
        detail: error.reason,
    }])
}
