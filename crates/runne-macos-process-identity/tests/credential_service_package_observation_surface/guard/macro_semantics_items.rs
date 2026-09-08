use std::collections::HashMap;

use super::super::bodies::{CallEvidence, FunctionSummary, UnresolvedEvidence};
use super::super::bodies_types::TypeFactCache;
use super::super::provenance::{UnresolvedReason, ValueFact};
use super::super::semantic_index::SemanticIndex;
use super::super::source_edge_macros::MacroResolution;
use super::super::source_model::{ScopeId, SourceId, SyntaxId, ValueDefId};

#[path = "macro_semantics_item_attrs.rs"]
mod attributes;
use attributes::item_attrs;
#[path = "macro_semantics_item_body.rs"]
mod body;
use body::{evaluate_function, evaluate_initializer};
#[path = "macro_semantics_item_members.rs"]
mod members;

const MAX_ITEM_MACRO_DEPTH: u8 = 16;

pub struct MacroItemEvaluation {
    pub calls: Vec<CallEvidence>,
    pub unresolved: Vec<UnresolvedEvidence>,
}

#[derive(Clone, Copy)]
pub struct ItemMacroContext {
    pub source: SourceId,
    pub syntax: SyntaxId,
    pub scope: ScopeId,
}

#[derive(Clone, Copy)]
pub struct MacroFacts<'a> {
    pub values: &'a HashMap<ValueDefId, ValueFact>,
    pub functions: &'a HashMap<ValueDefId, FunctionSummary>,
    pub type_facts: &'a TypeFactCache,
}

pub fn analyze_item_macro(
    index: &SemanticIndex,
    context: ItemMacroContext,
    invocation: &syn::Macro,
    facts: MacroFacts<'_>,
) -> MacroItemEvaluation {
    analyze_item_macro_depth(index, context, invocation, facts, 0)
}

fn analyze_item_macro_depth(
    index: &SemanticIndex,
    context: ItemMacroContext,
    invocation: &syn::Macro,
    facts: MacroFacts<'_>,
    depth: u8,
) -> MacroItemEvaluation {
    if depth >= MAX_ITEM_MACRO_DEPTH {
        return unresolved_result(context, UnresolvedReason::MacroRecursionLimit);
    }
    let resolved = match index.resolve_macro(context.scope, invocation) {
        MacroResolution::Workspace(resolved) => resolved,
        MacroResolution::Builtin(_) | MacroResolution::External => {
            return unresolved_result(context, UnresolvedReason::UnsupportedMacro);
        }
        MacroResolution::Unresolved(reason) => {
            return unresolved_result(context, super::resolution_reason(&reason));
        }
    };
    analyze_resolved_item_macro(index, context, &resolved, facts, depth, None)
}

fn analyze_resolved_item_macro(
    index: &SemanticIndex,
    context: ItemMacroContext,
    resolved: &super::super::source_edge_macros::ResolvedMacroInvocation,
    facts: MacroFacts<'_>,
    depth: u8,
    inherited_self_type: Option<&syn::Type>,
) -> MacroItemEvaluation {
    if depth >= MAX_ITEM_MACRO_DEPTH {
        return unresolved_result(context, UnresolvedReason::MacroRecursionLimit);
    }
    let expansion_scope = resolved.analysis_scope.unwrap_or(context.scope);
    let mut result = empty_result();
    for arm in &resolved.selected_arms {
        let Some(bindings) = super::validated_bindings(&arm.matcher, arm.bindings.clone()) else {
            merge(
                &mut result,
                unresolved_result(context, UnresolvedReason::UnsupportedMacro),
            );
            continue;
        };
        let expansion = super::substitute(arm.expansion.clone(), &bindings);
        let Ok(file) = syn::parse2::<syn::File>(expansion) else {
            merge(
                &mut result,
                unresolved_result(context, UnresolvedReason::UnsupportedMacro),
            );
            continue;
        };
        let expanded_context = ItemMacroContext {
            scope: expansion_scope,
            ..context
        };
        for item in &file.items {
            analyze_generated_item(
                index,
                expanded_context,
                item,
                resolved,
                &file.items,
                facts,
                depth + 1,
                inherited_self_type,
                &mut result,
            );
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn analyze_generated_item(
    index: &SemanticIndex,
    context: ItemMacroContext,
    item: &syn::Item,
    parent: &super::super::source_edge_macros::ResolvedMacroInvocation,
    generated_items: &[syn::Item],
    facts: MacroFacts<'_>,
    depth: u8,
    inherited_self_type: Option<&syn::Type>,
    result: &mut MacroItemEvaluation,
) {
    if !super::super::cfg_projection::is_production(item_attrs(item)) {
        return;
    }
    if super::super::analyzer::attributes::item_has_opaque_attribute(index, context.scope, item) {
        merge(
            result,
            unresolved_result(context, UnresolvedReason::UnsupportedMacro),
        );
    }
    match item {
        syn::Item::Fn(function) => evaluate_function(
            index,
            context,
            &function.sig,
            &function.block,
            inherited_self_type.cloned(),
            facts,
            result,
        ),
        syn::Item::Impl(item_impl) => members::analyze_impl(
            index,
            context,
            item_impl,
            parent,
            generated_items,
            facts,
            depth,
            result,
        ),
        syn::Item::Trait(item_trait) => members::analyze_trait(
            index,
            context,
            item_trait,
            parent,
            generated_items,
            facts,
            depth,
            result,
        ),
        syn::Item::Mod(module) => {
            if let Some((_, items)) = &module.content {
                for item in items {
                    analyze_generated_item(
                        index,
                        context,
                        item,
                        parent,
                        generated_items,
                        facts,
                        depth,
                        None,
                        result,
                    );
                }
            }
        }
        syn::Item::Const(item_const) => {
            evaluate_initializer(index, context, &item_const.expr, facts, result);
        }
        syn::Item::Static(item_static) => {
            evaluate_initializer(index, context, &item_static.expr, facts, result);
        }
        syn::Item::Macro(item_macro) if item_macro.ident.is_none() => {
            let nested = analyze_nested_macro(
                index,
                context,
                &item_macro.mac,
                parent,
                generated_items,
                facts,
                depth,
                inherited_self_type,
            );
            merge(result, nested);
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_nested_macro(
    index: &SemanticIndex,
    context: ItemMacroContext,
    invocation: &syn::Macro,
    parent: &super::super::source_edge_macros::ResolvedMacroInvocation,
    generated_items: &[syn::Item],
    facts: MacroFacts<'_>,
    depth: u8,
    inherited_self_type: Option<&syn::Type>,
) -> MacroItemEvaluation {
    match index.resolve_generated_macro(parent, generated_items, invocation) {
        MacroResolution::Workspace(resolved) => analyze_resolved_item_macro(
            index,
            context,
            &resolved,
            facts,
            depth,
            inherited_self_type,
        ),
        MacroResolution::Builtin(_) | MacroResolution::External => {
            unresolved_result(context, UnresolvedReason::UnsupportedMacro)
        }
        MacroResolution::Unresolved(reason) => {
            unresolved_result(context, super::resolution_reason(&reason))
        }
    }
}

const fn empty_result() -> MacroItemEvaluation {
    MacroItemEvaluation {
        calls: Vec::new(),
        unresolved: Vec::new(),
    }
}

fn unresolved_result(context: ItemMacroContext, reason: UnresolvedReason) -> MacroItemEvaluation {
    MacroItemEvaluation {
        calls: Vec::new(),
        unresolved: vec![UnresolvedEvidence {
            source: context.source,
            syntax: context.syntax,
            reason,
        }],
    }
}

fn merge(target: &mut MacroItemEvaluation, source: MacroItemEvaluation) {
    target.calls.extend(source.calls);
    target.unresolved.extend(source.unresolved);
}
