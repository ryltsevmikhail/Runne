use std::collections::HashMap;

use super::bodies_types::FactResolver;
use super::provenance::{ShapeFact, UnresolvedReason, ValueFact};
use super::semantic_index::{PathOrigin, Resolution};
use super::source_edge_macros::MacroResolution;
use super::source_model::{ScopeId, TypeDefId};
use super::symbols::TypeKind;

#[path = "bodies_type_cycles.rs"]
mod cycles;
pub(super) use cycles::recursive_back_edge_fact;

impl FactResolver<'_> {
    pub(super) fn root_type_id(&self, scope: ScopeId, ty: &syn::Type) -> Option<TypeDefId> {
        let syn::Type::Path(path) = ty else {
            return None;
        };
        if path
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
        {
            return None;
        }
        let Resolution::Exact(id) = self.index.resolve_type(scope, &path.path) else {
            return None;
        };
        let Resolution::Exact(canonical) = self.index.canonical_type(id) else {
            return None;
        };
        Some(canonical)
    }

    pub(super) fn canonical_target(&self) -> Option<TypeDefId> {
        self.index
            .types()
            .find(|record| matches!(record.kind, TypeKind::CanonicalTarget))
            .map(|record| record.id)
    }

    pub(super) fn is_callable_type(&self, scope: ScopeId, ty: &syn::Type) -> bool {
        self.is_callable_type_inner(scope, ty, &mut Vec::new())
    }

    fn is_callable_type_inner(
        &self,
        scope: ScopeId,
        ty: &syn::Type,
        stack: &mut Vec<TypeDefId>,
    ) -> bool {
        match ty {
            syn::Type::BareFn(_) => true,
            syn::Type::Paren(ty) => self.is_callable_type_inner(scope, &ty.elem, stack),
            syn::Type::Group(ty) => self.is_callable_type_inner(scope, &ty.elem, stack),
            syn::Type::Path(path) => self.resolved_alias_is_callable(scope, path, stack),
            _ => false,
        }
    }

    fn resolved_alias_is_callable(
        &self,
        scope: ScopeId,
        path: &syn::TypePath,
        stack: &mut Vec<TypeDefId>,
    ) -> bool {
        let Resolution::Exact(id) = self.index.resolve_type(scope, &path.path) else {
            return false;
        };
        if stack.contains(&id) {
            return false;
        }
        let Some(record) = self.index.type_record(id) else {
            return false;
        };
        let TypeKind::Alias(target) = &record.kind else {
            return false;
        };
        stack.push(id);
        let callable = self.is_callable_type_inner(record.scope, target, stack);
        stack.pop();
        callable
    }
}

pub(super) fn apply_generic_arguments(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    path: &syn::Path,
    stack: &mut Vec<TypeDefId>,
    memo: &mut HashMap<TypeDefId, ValueFact>,
    mut base: ValueFact,
) -> ValueFact {
    if generic_argument_facts(resolver, scope, path, stack, memo).is_empty() {
        return base;
    }
    let uncertain = ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
    match &mut base {
        ValueFact::Aggregate(ShapeFact::Record { fields, .. }) => {
            for fact in fields.values_mut() {
                if !fact.may_carry_target() {
                    *fact = uncertain.clone();
                }
            }
            base
        }
        ValueFact::Aggregate(ShapeFact::Tuple { items, .. }) => {
            for fact in items {
                if !fact.may_carry_target() {
                    *fact = uncertain.clone();
                }
            }
            base
        }
        ValueFact::NonTarget => uncertain,
        _ => base,
    }
}

pub(super) fn generic_path_fact(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    path: &syn::Path,
    stack: &mut Vec<TypeDefId>,
    memo: &mut HashMap<TypeDefId, ValueFact>,
) -> ValueFact {
    let facts = generic_argument_facts(resolver, scope, path, stack, memo);
    if !facts.is_empty() {
        let wrapper = path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        if matches!(
            wrapper.as_str(),
            "Box" | "Rc" | "Arc" | "Pin" | "Cell" | "RefCell"
        ) {
            return ValueFact::Aggregate(ShapeFact::Reference(Box::new(join_facts(facts))));
        }
        return ValueFact::Aggregate(ShapeFact::Tuple {
            owner: None,
            items: facts,
        });
    }
    match resolver.index.path_origin(scope, path) {
        PathOrigin::ExternalOpaque => ValueFact::OpaqueExternal,
        PathOrigin::Local
            if path.segments.len() == 1 || has_local_glob_import(resolver, scope, path) =>
        {
            ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
        }
        PathOrigin::Unknown if has_local_glob_import(resolver, scope, path) => {
            ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
        }
        _ => ValueFact::NonTarget,
    }
}

fn has_local_glob_import(resolver: &FactResolver<'_>, scope: ScopeId, path: &syn::Path) -> bool {
    if path.segments.len() != 1 {
        return false;
    }
    let Some(current) = resolver.index.module(scope) else {
        return false;
    };
    resolver
        .index
        .imports
        .iter()
        .filter(|import| import.scope == scope && import.glob)
        .flat_map(|import| {
            super::semantic_index_imports::candidate_module_paths(current, &import.path)
        })
        .any(|module_path| {
            resolver
                .index
                .module_at(current.package, current.target, &module_path)
                .is_some()
        })
}

pub(super) fn type_macro_fact(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    invocation: &syn::Macro,
    stack: &mut Vec<TypeDefId>,
    memo: &mut HashMap<TypeDefId, ValueFact>,
) -> ValueFact {
    let expansion = match resolver.index.resolve_macro(scope, invocation) {
        MacroResolution::Workspace(expansion) => expansion,
        MacroResolution::Builtin(_)
        | MacroResolution::External
        | MacroResolution::Unresolved(_) => {
            return ValueFact::MaybeTarget(UnresolvedReason::UnsupportedMacro);
        }
    };
    let expansion_scope = expansion.analysis_scope.unwrap_or(scope);
    let mut output: Option<ValueFact> = None;
    for arm in expansion.selected_arms {
        let Some(bindings) = super::macro_semantics::validated_bindings(&arm.matcher, arm.bindings)
        else {
            return ValueFact::MaybeTarget(UnresolvedReason::UnsupportedMacro);
        };
        let expansion = super::macro_semantics::substitute(arm.expansion, &bindings);
        let Ok(ty) = syn::parse2::<syn::Type>(expansion) else {
            return ValueFact::MaybeTarget(UnresolvedReason::UnsupportedMacro);
        };
        if matches!(ty, syn::Type::Macro(_)) {
            return ValueFact::MaybeTarget(UnresolvedReason::MacroRecursionLimit);
        }
        let fact = resolver.type_fact_inner(expansion_scope, &ty, stack, memo);
        output = Some(output.map_or_else(|| fact.clone(), |current| current.join(&fact)));
    }
    output.unwrap_or(ValueFact::NonTarget)
}

fn generic_argument_facts(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    path: &syn::Path,
    stack: &mut Vec<TypeDefId>,
    memo: &mut HashMap<TypeDefId, ValueFact>,
) -> Vec<ValueFact> {
    path.segments
        .iter()
        .filter_map(|segment| match &segment.arguments {
            syn::PathArguments::AngleBracketed(arguments) => Some(&arguments.args),
            _ => None,
        })
        .flatten()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(ty) => {
                Some(resolver.type_fact_inner(scope, ty, stack, memo))
            }
            _ => None,
        })
        .filter(ValueFact::may_carry_target)
        .collect()
}

fn join_facts(facts: Vec<ValueFact>) -> ValueFact {
    facts
        .into_iter()
        .reduce(|left, right| left.join(&right))
        .unwrap_or(ValueFact::NonTarget)
}
