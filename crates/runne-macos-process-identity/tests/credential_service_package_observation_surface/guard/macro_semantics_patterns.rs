use super::super::bodies::BodyEngine;
use super::super::provenance::{UnresolvedReason, ValueFact};
use super::super::source_edge_macros::MacroResolution;
use super::super::source_model::ScopeId;
use super::{MAX_MACRO_DEPTH, substitute, validated_bindings};

impl BodyEngine<'_> {
    pub(in crate::guard) fn bind_pattern(&mut self, pattern: &syn::Pat, fact: &ValueFact) {
        self.bind_pattern_in_scope(self.environment.current_scope(), pattern, fact);
    }

    pub(in crate::guard) fn bind_pattern_in_scope(
        &mut self,
        scope: ScopeId,
        pattern: &syn::Pat,
        fact: &ValueFact,
    ) {
        for pattern in self.expand_pattern(scope, None, pattern, fact) {
            self.environment.bind_pattern(&pattern, fact);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn expand_pattern(
        &mut self,
        scope: ScopeId,
        parent: Option<&super::super::source_edge_macros::ResolvedMacroInvocation>,
        pattern: &syn::Pat,
        fact: &ValueFact,
    ) -> Vec<syn::Pat> {
        match pattern {
            syn::Pat::Ident(value) => {
                let Some((at, subpattern)) = &value.subpat else {
                    return vec![pattern.clone()];
                };
                return self
                    .expand_pattern(scope, parent, subpattern, fact)
                    .into_iter()
                    .map(|pat| {
                        syn::Pat::Ident(syn::PatIdent {
                            subpat: Some((*at, Box::new(pat))),
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::TupleStruct(value) => {
                return self
                    .expand_elements(scope, parent, &value.elems, fact)
                    .into_iter()
                    .map(|elems| {
                        syn::Pat::TupleStruct(syn::PatTupleStruct {
                            elems,
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::Tuple(value) => {
                return self
                    .expand_elements(scope, parent, &value.elems, fact)
                    .into_iter()
                    .map(|elems| {
                        syn::Pat::Tuple(syn::PatTuple {
                            elems,
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::Slice(value) => {
                return self
                    .expand_elements(scope, parent, &value.elems, fact)
                    .into_iter()
                    .map(|elems| {
                        syn::Pat::Slice(syn::PatSlice {
                            elems,
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::Paren(value) => {
                return self
                    .expand_pattern(scope, parent, &value.pat, fact)
                    .into_iter()
                    .map(|pat| {
                        syn::Pat::Paren(syn::PatParen {
                            pat: Box::new(pat),
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::Reference(value) => {
                return self
                    .expand_pattern(scope, parent, &value.pat, fact.transparent())
                    .into_iter()
                    .map(|pat| {
                        syn::Pat::Reference(syn::PatReference {
                            pat: Box::new(pat),
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::Type(value) => {
                return self
                    .expand_pattern(scope, parent, &value.pat, fact)
                    .into_iter()
                    .map(|pat| {
                        syn::Pat::Type(syn::PatType {
                            pat: Box::new(pat),
                            ..value.clone()
                        })
                    })
                    .collect();
            }
            syn::Pat::Struct(value) => return self.expand_struct(scope, parent, value, fact),
            syn::Pat::Or(value) => return self.expand_or(scope, parent, value, fact),
            _ => {}
        }
        let syn::Pat::Macro(value) = pattern else {
            return vec![pattern.clone()];
        };
        if self.macro_depth >= MAX_MACRO_DEPTH {
            return self.unresolved_pattern(fact, UnresolvedReason::MacroRecursionLimit);
        }
        let resolution = parent.map_or_else(
            || self.index.resolve_macro(scope, &value.mac),
            |parent| self.index.resolve_pattern_macro(parent, &value.mac),
        );
        let MacroResolution::Workspace(resolved) = resolution else {
            return self.unresolved_pattern(fact, UnresolvedReason::UnsupportedMacro);
        };
        if self.macro_stack.contains(&resolved.definition) {
            return self.unresolved_pattern(fact, UnresolvedReason::MacroRecursionLimit);
        }
        self.macro_depth += 1;
        self.macro_stack.push(resolved.definition);
        let expansion_scope = resolved.analysis_scope.unwrap_or(scope);
        let nested_parent = resolved.clone();
        let mut patterns = Vec::new();
        for arm in resolved.selected_arms {
            let Some(bindings) = validated_bindings(&arm.matcher, arm.bindings) else {
                patterns.extend(self.unresolved_pattern(fact, UnresolvedReason::UnsupportedMacro));
                continue;
            };
            let expansion = substitute(arm.expansion, &bindings);
            let parsed =
                syn::parse::Parser::parse2(syn::Pat::parse_multi_with_leading_vert, expansion);
            match parsed {
                Ok(pattern) => patterns.extend(self.expand_pattern(
                    expansion_scope,
                    Some(&nested_parent),
                    &pattern,
                    fact,
                )),
                Err(_) => patterns
                    .extend(self.unresolved_pattern(fact, UnresolvedReason::UnsupportedMacro)),
            }
        }
        self.macro_depth -= 1;
        self.macro_stack.pop();
        patterns
    }

    fn expand_elements(
        &mut self,
        scope: ScopeId,
        parent: Option<&super::super::source_edge_macros::ResolvedMacroInvocation>,
        elements: &syn::punctuated::Punctuated<syn::Pat, syn::Token![,]>,
        fact: &ValueFact,
    ) -> Vec<syn::punctuated::Punctuated<syn::Pat, syn::Token![,]>> {
        let mut variants = vec![syn::punctuated::Punctuated::new()];
        for (index, element) in elements.iter().enumerate() {
            let patterns =
                self.expand_pattern(scope, parent, element, &fact.project_index(Some(index)));
            variants = variants
                .into_iter()
                .flat_map(|base| {
                    patterns.iter().map(move |pattern| {
                        let mut next = base.clone();
                        if !next.is_empty() {
                            next.push_punct(syn::token::Comma::default());
                        }
                        next.push_value(pattern.clone());
                        next
                    })
                })
                .collect();
        }
        variants
    }

    fn expand_struct(
        &mut self,
        scope: ScopeId,
        parent: Option<&super::super::source_edge_macros::ResolvedMacroInvocation>,
        value: &syn::PatStruct,
        fact: &ValueFact,
    ) -> Vec<syn::Pat> {
        let mut variants = vec![value.clone()];
        for (index, field) in value.fields.iter().enumerate() {
            let member = match &field.member {
                syn::Member::Named(name) => {
                    super::super::symbols::MemberKey::Named(name.to_string())
                }
                syn::Member::Unnamed(index) => {
                    super::super::symbols::MemberKey::Unnamed(index.index)
                }
            };
            let patterns =
                self.expand_pattern(scope, parent, &field.pat, &fact.project_member(&member));
            variants = variants
                .into_iter()
                .flat_map(|base| {
                    patterns.iter().map(move |pattern| {
                        let mut next = base.clone();
                        *next
                            .fields
                            .iter_mut()
                            .nth(index)
                            .expect("struct field exists")
                            .pat = pattern.clone();
                        next
                    })
                })
                .collect();
        }
        variants.into_iter().map(syn::Pat::Struct).collect()
    }

    fn expand_or(
        &mut self,
        scope: ScopeId,
        parent: Option<&super::super::source_edge_macros::ResolvedMacroInvocation>,
        value: &syn::PatOr,
        fact: &ValueFact,
    ) -> Vec<syn::Pat> {
        let mut cases = syn::punctuated::Punctuated::new();
        for case in &value.cases {
            for pattern in self.expand_pattern(scope, parent, case, fact) {
                if !cases.is_empty() {
                    cases.push_punct(syn::token::Or::default());
                }
                cases.push_value(pattern);
            }
        }
        vec![syn::Pat::Or(syn::PatOr {
            cases,
            ..value.clone()
        })]
    }

    fn unresolved_pattern(&mut self, fact: &ValueFact, reason: UnresolvedReason) -> Vec<syn::Pat> {
        if fact.may_carry_target() {
            self.unresolved_macro(reason);
        }
        Vec::new()
    }
}
