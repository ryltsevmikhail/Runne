use super::super::super::cfg_projection;
use super::super::super::semantic_index::SemanticIndex;
use super::super::super::source_edge_macros::ResolvedMacroInvocation;
use super::attributes::{impl_item_attrs, trait_item_attrs};
use super::{
    ItemMacroContext, MacroFacts, MacroItemEvaluation, analyze_nested_macro, evaluate_function,
    evaluate_initializer, merge,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn analyze_impl(
    index: &SemanticIndex,
    context: ItemMacroContext,
    item_impl: &syn::ItemImpl,
    parent: &ResolvedMacroInvocation,
    generated_items: &[syn::Item],
    facts: MacroFacts<'_>,
    depth: u8,
    result: &mut MacroItemEvaluation,
) {
    for member in &item_impl.items {
        if !cfg_projection::is_production(impl_item_attrs(member)) {
            continue;
        }
        match member {
            syn::ImplItem::Const(item) => {
                evaluate_initializer(index, context, &item.expr, facts, result);
            }
            syn::ImplItem::Fn(function) => evaluate_function(
                index,
                context,
                &function.sig,
                &function.block,
                Some((*item_impl.self_ty).clone()),
                facts,
                result,
            ),
            syn::ImplItem::Macro(item_macro) => merge(
                result,
                analyze_nested_macro(
                    index,
                    context,
                    &item_macro.mac,
                    parent,
                    generated_items,
                    facts,
                    depth,
                    Some(&item_impl.self_ty),
                ),
            ),
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn analyze_trait(
    index: &SemanticIndex,
    context: ItemMacroContext,
    item: &syn::ItemTrait,
    parent: &ResolvedMacroInvocation,
    generated_items: &[syn::Item],
    facts: MacroFacts<'_>,
    depth: u8,
    result: &mut MacroItemEvaluation,
) {
    for member in &item.items {
        if !cfg_projection::is_production(trait_item_attrs(member)) {
            continue;
        }
        match member {
            syn::TraitItem::Const(item) => {
                if let Some((_, expression)) = &item.default {
                    evaluate_initializer(index, context, expression, facts, result);
                }
            }
            syn::TraitItem::Fn(function) => {
                if let Some(block) = &function.default {
                    evaluate_function(index, context, &function.sig, block, None, facts, result);
                }
            }
            syn::TraitItem::Macro(item) => merge(
                result,
                analyze_nested_macro(
                    index,
                    context,
                    &item.mac,
                    parent,
                    generated_items,
                    facts,
                    depth,
                    None,
                ),
            ),
            _ => {}
        }
    }
}
