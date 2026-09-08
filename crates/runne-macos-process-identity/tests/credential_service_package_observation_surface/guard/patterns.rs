use std::collections::BTreeMap;

use super::assignments::{Projection, assign_projected};
use super::provenance::ValueFact;
use super::source_model::{BindingId, BodyId, ScopeId};
use super::symbols::MemberKey;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    id: BindingId,
    fact: ValueFact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopeFrame {
    id: ScopeId,
    next_ordinal: u32,
    bindings: BTreeMap<String, Binding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BindingEnvironment {
    body: BodyId,
    frames: Vec<ScopeFrame>,
}

impl BindingEnvironment {
    pub(super) fn new(body: BodyId, scope: ScopeId) -> Self {
        Self {
            body,
            frames: vec![ScopeFrame {
                id: scope,
                next_ordinal: 0,
                bindings: BTreeMap::new(),
            }],
        }
    }

    pub(super) fn push_scope(&mut self, scope: ScopeId) {
        self.frames.push(ScopeFrame {
            id: scope,
            next_ordinal: 0,
            bindings: BTreeMap::new(),
        });
    }

    pub(super) fn current_scope(&self) -> ScopeId {
        self.frames.last().expect("body scope exists").id
    }

    pub(super) fn pop_scope(&mut self) {
        assert!(self.frames.len() > 1, "cannot pop the body root scope");
        self.frames.pop();
    }

    pub(super) fn bind_self(&mut self, fact: ValueFact) -> BindingId {
        self.bind_name("self".into(), fact)
    }

    pub(super) fn bind_hygienic_unknown(&mut self, name: String) -> BindingId {
        self.bind_name(
            name,
            ValueFact::MaybeTarget(super::provenance::UnresolvedReason::MissingTargetProvenance),
        )
    }

    pub(super) fn bind_pattern(&mut self, pattern: &syn::Pat, fact: &ValueFact) {
        let mut projected = BTreeMap::new();
        project_pattern(pattern, fact, &mut projected);
        for (name, fact) in projected {
            self.bind_name(name, fact);
        }
    }

    pub(super) fn lookup(&self, name: &str) -> Option<&ValueFact> {
        self.frames
            .iter()
            .rev()
            .find_map(|frame| frame.bindings.get(name).map(|binding| &binding.fact))
    }

    pub(super) fn binding(&self, name: &str) -> Option<BindingId> {
        self.frames
            .iter()
            .rev()
            .find_map(|frame| frame.bindings.get(name).map(|binding| binding.id))
    }

    pub(super) fn assign_projection(
        &mut self,
        name: &str,
        projection: &[Projection],
        fact: ValueFact,
    ) -> bool {
        for frame in self.frames.iter_mut().rev() {
            if let Some(binding) = frame.bindings.get_mut(name) {
                binding.fact = assign_projected(&binding.fact, projection, fact);
                return true;
            }
        }
        false
    }

    pub(super) fn join_from(&mut self, other: &Self) {
        for frame in &mut self.frames {
            let Some(other_frame) = other
                .frames
                .iter()
                .find(|candidate| candidate.id == frame.id)
            else {
                continue;
            };
            for binding in frame.bindings.values_mut() {
                let Some(other_binding) = other_frame
                    .bindings
                    .values()
                    .find(|candidate| candidate.id == binding.id)
                else {
                    continue;
                };
                binding.fact = binding.fact.join(&other_binding.fact);
            }
        }
    }

    fn bind_name(&mut self, name: String, fact: ValueFact) -> BindingId {
        let frame = self.frames.last_mut().expect("body scope exists");
        let id = BindingId {
            body: self.body,
            scope: frame.id,
            ordinal: frame.next_ordinal,
        };
        frame.next_ordinal += 1;
        frame.bindings.insert(name, Binding { id, fact });
        id
    }
}

fn project_pattern(
    pattern: &syn::Pat,
    fact: &ValueFact,
    projected: &mut BTreeMap<String, ValueFact>,
) {
    match pattern {
        syn::Pat::Ident(binding) => {
            merge_projection(projected, binding.ident.to_string(), fact.clone());
            if let Some((_, subpattern)) = &binding.subpat {
                project_pattern(subpattern, fact, projected);
            }
        }
        syn::Pat::Paren(pattern) => project_pattern(&pattern.pat, fact, projected),
        syn::Pat::Reference(pattern) => {
            project_pattern(&pattern.pat, fact.transparent(), projected);
        }
        syn::Pat::Type(pattern) => project_pattern(&pattern.pat, fact, projected),
        syn::Pat::Struct(pattern) => {
            for field in &pattern.fields {
                let member = match &field.member {
                    syn::Member::Named(name) => MemberKey::Named(name.to_string()),
                    syn::Member::Unnamed(index) => MemberKey::Unnamed(index.index),
                };
                project_pattern(&field.pat, &fact.project_member(&member), projected);
            }
        }
        syn::Pat::TupleStruct(pattern) => project_tuple(&pattern.elems, fact, projected),
        syn::Pat::Tuple(pattern) => project_tuple(&pattern.elems, fact, projected),
        syn::Pat::Slice(pattern) => project_slice(&pattern.elems, fact, projected),
        syn::Pat::Or(pattern) => {
            for alternative in &pattern.cases {
                let mut branch = BTreeMap::new();
                project_pattern(alternative, fact, &mut branch);
                for (name, fact) in branch {
                    merge_projection(projected, name, fact);
                }
            }
        }
        _ => {}
    }
}

fn project_tuple(
    patterns: &syn::punctuated::Punctuated<syn::Pat, syn::Token![,]>,
    fact: &ValueFact,
    projected: &mut BTreeMap<String, ValueFact>,
) {
    project_positional(patterns, fact, projected);
}

fn project_slice(
    patterns: &syn::punctuated::Punctuated<syn::Pat, syn::Token![,]>,
    fact: &ValueFact,
    projected: &mut BTreeMap<String, ValueFact>,
) {
    project_positional(patterns, fact, projected);
}

fn project_positional(
    patterns: &syn::punctuated::Punctuated<syn::Pat, syn::Token![,]>,
    fact: &ValueFact,
    projected: &mut BTreeMap<String, ValueFact>,
) {
    let rest = patterns
        .iter()
        .position(|item| matches!(item, syn::Pat::Rest(_)));
    let source_len = fact.positional_len();
    for (index, pattern) in patterns.iter().enumerate() {
        if matches!(pattern, syn::Pat::Rest(_)) {
            continue;
        }
        let source_index = rest.map_or(Some(index), |rest| {
            if index < rest {
                Some(index)
            } else {
                source_len.map(|len| len.saturating_sub(patterns.len() - index))
            }
        });
        project_pattern(pattern, &fact.project_index(source_index), projected);
    }
}

fn merge_projection(projected: &mut BTreeMap<String, ValueFact>, name: String, fact: ValueFact) {
    projected
        .entry(name)
        .and_modify(|current| *current = current.join(&fact))
        .or_insert(fact);
}
