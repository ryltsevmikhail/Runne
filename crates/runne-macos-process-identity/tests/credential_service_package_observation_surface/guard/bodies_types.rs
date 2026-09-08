use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::provenance::{CallableFact, ShapeFact, TargetMethod, UnresolvedReason, ValueFact};
use super::semantic_index::{Resolution, SemanticIndex};
use super::source_model::{ScopeId, TypeDefId, ValueDefId};
use super::symbols::{CanonicalMethod, TypeKind, ValueKind};

pub(super) struct FactResolver<'a> {
    pub(super) index: &'a SemanticIndex,
    values: &'a HashMap<ValueDefId, ValueFact>,
    pub(super) type_facts: &'a TypeFactCache,
}

#[derive(Default)]
pub(super) struct TypeFactCache {
    pub(super) facts: RefCell<HashMap<TypeDefId, ValueFact>>,
    pub(super) reaches_target: RefCell<HashMap<TypeDefId, bool>>,
}

impl<'a> FactResolver<'a> {
    pub(super) const fn new(
        index: &'a SemanticIndex,
        values: &'a HashMap<ValueDefId, ValueFact>,
        type_facts: &'a TypeFactCache,
    ) -> Self {
        Self {
            index,
            values,
            type_facts,
        }
    }

    pub(super) fn type_fact(&self, scope: ScopeId, ty: &syn::Type) -> ValueFact {
        let root = self.root_type_id(scope, ty);
        if let Some(fact) = root.and_then(|id| self.type_facts.facts.borrow().get(&id).cloned()) {
            return fact;
        }
        let fact = self.type_fact_inner(scope, ty, &mut Vec::new(), &mut HashMap::new());
        if let Some(id) = root {
            self.type_facts.facts.borrow_mut().insert(id, fact.clone());
        }
        fact
    }

    pub(super) fn value_fact(&self, id: ValueDefId) -> ValueFact {
        if let Some(fact) = self.values.get(&id) {
            return fact.clone();
        }
        let Some(record) = self.index.value_record(id) else {
            return ValueFact::NonTarget;
        };
        if let Some(method) = record.canonical_method {
            return ValueFact::TargetCallable(match method {
                CanonicalMethod::Capture => TargetMethod::Capture,
                CanonicalMethod::Verify => TargetMethod::Verify,
            });
        }
        match &record.kind {
            ValueKind::Function { body: Some(body) } => {
                let Some(body) = self.index.body_record(*body) else {
                    return ValueFact::NonTarget;
                };
                let super::symbols::BodySyntax::Function { signature, .. } =
                    body.syntax_tree.as_ref()
                else {
                    return ValueFact::NonTarget;
                };
                ValueFact::Callable(CallableFact {
                    output: Box::new(self.return_fact(record.scope, &signature.output)),
                    invoked_parameters: BTreeSet::default(),
                    parameter_effects: BTreeMap::default(),
                })
            }
            ValueKind::Function { body: None } => ValueFact::NonTarget,
            ValueKind::Const { ty, .. } | ValueKind::Static { ty, .. } => {
                self.type_fact(record.scope, ty)
            }
        }
    }

    pub(super) fn value_candidates_fact(&self, ids: &[ValueDefId]) -> ValueFact {
        if ids.iter().any(|id| self.value_fact(*id).may_carry_target()) {
            ValueFact::MaybeTarget(UnresolvedReason::AmbiguousResolution)
        } else {
            ValueFact::NonTarget
        }
    }

    pub(super) fn type_candidates_fact(&self, ids: &[TypeDefId]) -> ValueFact {
        let mut stack = Vec::new();
        let mut memo = HashMap::new();
        if ids.iter().any(|id| {
            self.type_id_fact(*id, &mut stack, &mut memo)
                .may_carry_target()
        }) {
            ValueFact::MaybeTarget(UnresolvedReason::AmbiguousResolution)
        } else {
            ValueFact::NonTarget
        }
    }

    pub(super) fn return_fact(&self, scope: ScopeId, output: &syn::ReturnType) -> ValueFact {
        match output {
            syn::ReturnType::Default => ValueFact::NonTarget,
            syn::ReturnType::Type(_, ty) => self.type_fact(scope, ty),
        }
    }

    pub(super) fn type_fact_inner(
        &self,
        scope: ScopeId,
        ty: &syn::Type,
        stack: &mut Vec<TypeDefId>,
        memo: &mut HashMap<TypeDefId, ValueFact>,
    ) -> ValueFact {
        match ty {
            syn::Type::Path(path) => match self.index.resolve_type(scope, &path.path) {
                Resolution::Exact(id) => {
                    let base = self.type_id_fact(id, stack, memo);
                    super::bodies_type_paths::apply_generic_arguments(
                        self, scope, &path.path, stack, memo, base,
                    )
                }
                Resolution::Ambiguous(ids) => self.type_candidates_fact(&ids),
                Resolution::Missing => super::bodies_type_paths::generic_path_fact(
                    self, scope, &path.path, stack, memo,
                ),
            },
            syn::Type::Reference(reference) => ValueFact::Aggregate(ShapeFact::Reference(
                Box::new(self.type_fact_inner(scope, &reference.elem, stack, memo)),
            )),
            syn::Type::Paren(paren) => self.type_fact_inner(scope, &paren.elem, stack, memo),
            syn::Type::Group(group) => self.type_fact_inner(scope, &group.elem, stack, memo),
            syn::Type::Tuple(tuple) => ValueFact::Aggregate(ShapeFact::Tuple {
                owner: None,
                items: tuple
                    .elems
                    .iter()
                    .map(|item| self.type_fact_inner(scope, item, stack, memo))
                    .collect(),
            }),
            syn::Type::Array(array) => ValueFact::Aggregate(ShapeFact::Sequence {
                items: vec![self.type_fact_inner(scope, &array.elem, stack, memo)],
            }),
            syn::Type::Slice(slice) => ValueFact::Aggregate(ShapeFact::Sequence {
                items: vec![self.type_fact_inner(scope, &slice.elem, stack, memo)],
            }),
            syn::Type::BareFn(function) => {
                let output = match &function.output {
                    syn::ReturnType::Default => ValueFact::NonTarget,
                    syn::ReturnType::Type(_, ty) => self.type_fact_inner(scope, ty, stack, memo),
                };
                if output.may_carry_target()
                    || function.inputs.iter().any(|input| {
                        self.type_fact_inner(scope, &input.ty, stack, memo)
                            .may_carry_target()
                    })
                {
                    ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
                } else {
                    ValueFact::NonTarget
                }
            }
            syn::Type::ImplTrait(bounds) => {
                callable_bound_fact(self, scope, &bounds.bounds, stack, memo)
            }
            syn::Type::TraitObject(bounds) => {
                callable_bound_fact(self, scope, &bounds.bounds, stack, memo)
            }
            syn::Type::Ptr(pointer) => self.type_fact_inner(scope, &pointer.elem, stack, memo),
            syn::Type::Macro(type_macro) => {
                super::bodies_type_paths::type_macro_fact(self, scope, &type_macro.mac, stack, memo)
            }
            _ => ValueFact::NonTarget,
        }
    }

    fn type_id_fact(
        &self,
        id: TypeDefId,
        stack: &mut Vec<TypeDefId>,
        memo: &mut HashMap<TypeDefId, ValueFact>,
    ) -> ValueFact {
        let canonical = match self.index.canonical_type(id) {
            Resolution::Exact(id) => id,
            Resolution::Ambiguous(ids) => {
                let target = self.canonical_target();
                if ids.iter().any(|id| {
                    target == Some(*id)
                        || matches!(self.index.canonical_type(*id), Resolution::Exact(found) if Some(found) == target)
                }) {
                    return ValueFact::MaybeTarget(UnresolvedReason::AmbiguousResolution);
                }
                return ValueFact::NonTarget;
            }
            Resolution::Missing => {
                return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
            }
        };
        if let Some(fact) = memo.get(&canonical) {
            return fact.clone();
        }
        if stack.contains(&canonical) {
            return super::bodies_type_paths::recursive_back_edge_fact(self, canonical);
        }
        let Some(record) = self.index.type_record(canonical) else {
            return ValueFact::NonTarget;
        };
        stack.push(canonical);
        let fact = match &record.kind {
            TypeKind::CanonicalTarget => ValueFact::TargetObject(canonical),
            TypeKind::Alias(ty) => self.type_fact_inner(record.scope, ty, stack, memo),
            TypeKind::Struct(fields)
                if fields
                    .iter()
                    .all(|field| matches!(field.member, super::symbols::MemberKey::Unnamed(_))) =>
            {
                ValueFact::Aggregate(ShapeFact::Tuple {
                    owner: Some(canonical),
                    items: fields
                        .iter()
                        .map(|field| self.type_fact_inner(record.scope, &field.ty, stack, memo))
                        .collect(),
                })
            }
            TypeKind::Struct(fields) | TypeKind::Union(fields) => {
                ValueFact::Aggregate(ShapeFact::Record {
                    owner: Some(canonical),
                    fields: fields
                        .iter()
                        .map(|field| {
                            (
                                field.member.clone(),
                                self.type_fact_inner(record.scope, &field.ty, stack, memo),
                            )
                        })
                        .collect(),
                })
            }
            TypeKind::Enum(variants) => ValueFact::Aggregate(ShapeFact::Record {
                owner: Some(canonical),
                fields: variants.iter().flat_map(|variant| &variant.fields).fold(
                    BTreeMap::new(),
                    |mut fields, field| {
                        let fact = self.type_fact_inner(record.scope, &field.ty, stack, memo);
                        fields
                            .entry(field.member.clone())
                            .and_modify(|current: &mut ValueFact| *current = current.join(&fact))
                            .or_insert(fact);
                        fields
                    },
                ),
            }),
        };
        stack.pop();
        memo.insert(canonical, fact.clone());
        fact
    }
}

fn callable_bound_fact(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    stack: &mut Vec<TypeDefId>,
    memo: &mut HashMap<TypeDefId, ValueFact>,
) -> ValueFact {
    for bound in bounds {
        let syn::TypeParamBound::Trait(bound) = bound else {
            continue;
        };
        let Some(segment) = bound.path.segments.last() else {
            continue;
        };
        if matches!(
            segment.ident.to_string().as_str(),
            "Fn" | "FnMut" | "FnOnce"
        ) && let syn::PathArguments::Parenthesized(arguments) = &segment.arguments
        {
            let output = match &arguments.output {
                syn::ReturnType::Default => ValueFact::NonTarget,
                syn::ReturnType::Type(_, ty) => resolver.type_fact_inner(scope, ty, stack, memo),
            };
            if output.may_carry_target() {
                return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
            }
        }
    }
    ValueFact::NonTarget
}
