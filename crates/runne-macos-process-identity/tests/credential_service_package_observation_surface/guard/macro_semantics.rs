use std::collections::HashMap;

use proc_macro2::{Group, TokenStream, TokenTree};

use super::bodies::BodyEngine;
use super::provenance::{UnresolvedReason, ValueFact};
use super::source_edge_macros::{
    BuiltinMacro, MacroResolution, UnresolvedReason as MacroUnresolvedReason,
};

#[path = "macro_semantics_hygiene.rs"]
mod hygiene;
#[path = "macro_semantics_items.rs"]
mod items;
#[path = "macro_semantics_patterns.rs"]
mod patterns;
use hygiene::template_call_site_collisions;
pub(super) use items::{ItemMacroContext, MacroFacts, analyze_item_macro};

pub(super) const MAX_MACRO_DEPTH: u8 = 16;

impl BodyEngine<'_> {
    pub(super) fn eval_macro(&mut self, invocation: &syn::Macro) -> ValueFact {
        if self.macro_depth >= MAX_MACRO_DEPTH {
            return self.unresolved_macro(UnresolvedReason::MacroRecursionLimit);
        }
        match self
            .index
            .resolve_macro(self.environment.current_scope(), invocation)
        {
            MacroResolution::Workspace(resolved) => {
                if self.macro_stack.contains(&resolved.definition) {
                    return self.unresolved_macro(UnresolvedReason::MacroRecursionLimit);
                }
                self.macro_depth += 1;
                self.macro_stack.push(resolved.definition);
                let mut output: Option<ValueFact> = None;
                let expansion_scope = resolved
                    .analysis_scope
                    .unwrap_or_else(|| self.environment.current_scope());
                for arm in resolved.selected_arms {
                    let collisions =
                        template_call_site_collisions(&arm.expansion, &self.environment);
                    let Some(bindings) = validated_bindings(&arm.matcher, arm.bindings) else {
                        output = Some(self.unresolved_macro(UnresolvedReason::UnsupportedMacro));
                        continue;
                    };
                    let expansion = substitute(arm.expansion, &bindings);
                    let parsed = syn::parse2::<syn::Block>(quote_block(expansion));
                    let fact = match parsed {
                        Ok(block) => {
                            self.environment.push_scope(expansion_scope);
                            for name in collisions {
                                self.environment.bind_hygienic_unknown(name);
                            }
                            let fact = self.eval_block(&block, false);
                            self.environment.pop_scope();
                            fact
                        }
                        Err(_) => self.unresolved_macro(UnresolvedReason::UnsupportedMacro),
                    };
                    output =
                        Some(output.map_or_else(|| fact.clone(), |current| current.join(&fact)));
                }
                self.macro_depth -= 1;
                self.macro_stack.pop();
                output.unwrap_or(ValueFact::NonTarget)
            }
            MacroResolution::Builtin(BuiltinMacro::Matches) => {
                self.eval_matches_macro(invocation.tokens.clone())
            }
            MacroResolution::Builtin(
                BuiltinMacro::Panic
                | BuiltinMacro::Todo
                | BuiltinMacro::Unimplemented
                | BuiltinMacro::Unreachable,
            ) => self.eval_diverging_macro(invocation.tokens.clone()),
            MacroResolution::External => self.unresolved_macro(UnresolvedReason::UnsupportedMacro),
            MacroResolution::Unresolved(reason) => {
                self.unresolved_macro(resolution_reason(&reason))
            }
        }
    }

    fn eval_matches_macro(&mut self, tokens: TokenStream) -> ValueFact {
        let Ok(input) = syn::parse2::<MatchesInput>(tokens) else {
            return self.unresolved_macro(UnresolvedReason::UnsupportedMacro);
        };
        let fact = self.eval_expr(&input.expression);
        let saved_environment = self.environment.clone();
        self.bind_pattern(&input.pattern, &fact);
        if let Some(guard) = input.guard {
            self.eval_expr(&guard);
        }
        self.environment = saved_environment;
        ValueFact::NonTarget
    }

    fn eval_diverging_macro(&mut self, tokens: TokenStream) -> ValueFact {
        let Ok(arguments) = syn::parse::Parser::parse2(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
            tokens,
        ) else {
            return self.unresolved_macro(UnresolvedReason::UnsupportedMacro);
        };
        for argument in arguments {
            self.eval_expr(&argument);
        }
        self.terminated = true;
        ValueFact::NonTarget
    }

    pub(super) fn unresolved_macro(&mut self, reason: UnresolvedReason) -> ValueFact {
        if self.mode == super::bodies::EvaluationMode::Analyze {
            self.unresolved.push(super::bodies::UnresolvedEvidence {
                source: self.body.source,
                syntax: self.body.syntax,
                reason: reason.clone(),
            });
        }
        ValueFact::MaybeTarget(reason)
    }
}

pub(super) const fn resolution_reason(reason: &MacroUnresolvedReason) -> UnresolvedReason {
    match reason {
        MacroUnresolvedReason::MissingScope | MacroUnresolvedReason::MissingDefinition => {
            UnresolvedReason::MissingTargetProvenance
        }
        MacroUnresolvedReason::AmbiguousDefinition => UnresolvedReason::AmbiguousResolution,
        MacroUnresolvedReason::UnsupportedArm => UnresolvedReason::UnsupportedMacro,
        MacroUnresolvedReason::RecursiveExpansion => UnresolvedReason::MacroRecursionLimit,
    }
}

pub(super) fn substitute(
    tokens: TokenStream,
    bindings: &HashMap<String, TokenStream>,
) -> TokenStream {
    let values = tokens.into_iter().collect::<Vec<_>>();
    let mut output = TokenStream::new();
    let mut index = 0;
    while index < values.len() {
        if matches!(values.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == '$')
            && let Some(TokenTree::Group(group)) = values.get(index + 1)
            && matches!(values.get(index + 2), Some(TokenTree::Punct(punct)) if matches!(punct.as_char(), '*' | '+'))
            && let Some(replacement) = repeated_binding(group, bindings)
        {
            output.extend(replacement);
            index += 3;
            continue;
        }
        if matches!(values.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == '$')
            && let Some(TokenTree::Ident(name)) = values.get(index + 1)
        {
            if let Some(replacement) = bindings.get(&name.to_string()) {
                output.extend(replacement.clone());
                index += 2;
                continue;
            }
            if name == "crate" {
                output.extend([TokenTree::Ident(name.clone())]);
                index += 2;
                continue;
            }
        }
        match &values[index] {
            TokenTree::Group(group) => {
                let mut replaced =
                    Group::new(group.delimiter(), substitute(group.stream(), bindings));
                replaced.set_span(group.span());
                output.extend([TokenTree::Group(replaced)]);
            }
            token => output.extend([token.clone()]),
        }
        index += 1;
    }
    output
}

fn repeated_binding(group: &Group, bindings: &HashMap<String, TokenStream>) -> Option<TokenStream> {
    let tokens = group.stream().into_iter().collect::<Vec<_>>();
    let [TokenTree::Punct(dollar), TokenTree::Ident(name)] = tokens.as_slice() else {
        return None;
    };
    (dollar.as_char() == '$')
        .then(|| bindings.get(&name.to_string()).cloned())
        .flatten()
}

pub(super) fn validated_bindings(
    matcher: &TokenStream,
    bindings: Vec<super::inventory_macro_bindings::MacroArgumentBinding>,
) -> Option<HashMap<String, TokenStream>> {
    let names = matcher_metavariables(matcher.clone());
    bindings
        .iter()
        .all(|binding| binding.name == "crate" || names.contains(&binding.name))
        .then(|| {
            bindings
                .into_iter()
                .map(|binding| (binding.name, binding.tokens))
                .collect()
        })
}

fn matcher_metavariables(tokens: TokenStream) -> Vec<String> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    let mut names = tokens
        .windows(2)
        .filter_map(|pair| match pair {
            [TokenTree::Punct(dollar), TokenTree::Ident(name)] if dollar.as_char() == '$' => {
                Some(name.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for token in tokens {
        if let TokenTree::Group(group) = token {
            names.extend(matcher_metavariables(group.stream()));
        }
    }
    names
}

fn quote_block(tokens: TokenStream) -> TokenStream {
    TokenStream::from(TokenTree::Group(Group::new(
        proc_macro2::Delimiter::Brace,
        tokens,
    )))
}

struct MatchesInput {
    expression: syn::Expr,
    pattern: syn::Pat,
    guard: Option<syn::Expr>,
}

impl syn::parse::Parse for MatchesInput {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let expression = input.parse()?;
        input.parse::<syn::Token![,]>()?;
        let pattern = syn::Pat::parse_multi_with_leading_vert(input)?;
        let guard = if input.peek(syn::Token![if]) {
            input.parse::<syn::Token![if]>()?;
            Some(input.parse()?)
        } else {
            None
        };
        if input.peek(syn::Token![,]) {
            input.parse::<syn::Token![,]>()?;
        }
        if input.is_empty() {
            Ok(Self {
                expression,
                pattern,
                guard,
            })
        } else {
            Err(input.error("unexpected tokens after matches! pattern"))
        }
    }
}
