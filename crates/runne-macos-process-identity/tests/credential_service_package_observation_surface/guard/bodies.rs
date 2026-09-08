use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::bodies_types::{FactResolver, TypeFactCache};
use super::patterns::BindingEnvironment;
use super::provenance::{TargetMethod, UnresolvedReason, ValueFact};
use super::semantic_index::SemanticIndex;
use super::source_model::{MacroDefId, SourceId, SourceOrigin, SyntaxId, ValueDefId};
use super::symbols::{BodyRecord, BodySyntax};

#[path = "bodies_arguments.rs"]
mod arguments;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FunctionSummary {
    pub(super) output: ValueFact,
    pub(super) invoked_parameters: BTreeSet<u16>,
    pub(super) parameter_effects: BTreeMap<u16, TargetMethod>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EvaluationMode {
    Summary,
    Analyze,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallEvidence {
    pub(super) source: SourceId,
    pub(super) syntax: SyntaxId,
    pub(super) method: TargetMethod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UnresolvedEvidence {
    pub(super) source: SourceId,
    pub(super) syntax: SyntaxId,
    pub(super) reason: UnresolvedReason,
}

#[derive(Clone, Debug)]
pub(super) struct BodyEvaluation {
    pub(super) output: ValueFact,
    pub(super) invoked_parameters: BTreeSet<u16>,
    pub(super) parameter_effects: BTreeMap<u16, TargetMethod>,
    pub(super) calls: Vec<CallEvidence>,
    pub(super) unresolved: Vec<UnresolvedEvidence>,
}

pub(super) struct BodyEngine<'a> {
    pub(super) index: &'a SemanticIndex,
    pub(super) body: &'a BodyRecord,
    pub(super) values: &'a HashMap<ValueDefId, ValueFact>,
    pub(super) functions: &'a HashMap<ValueDefId, FunctionSummary>,
    pub(super) type_facts: &'a TypeFactCache,
    pub(super) environment: BindingEnvironment,
    pub(super) mode: EvaluationMode,
    pub(super) invoked_parameters: BTreeSet<u16>,
    pub(super) parameter_effects: BTreeMap<u16, TargetMethod>,
    pub(super) calls: Vec<CallEvidence>,
    pub(super) unresolved: Vec<UnresolvedEvidence>,
    pub(super) macro_depth: u8,
    pub(super) macro_stack: Vec<MacroDefId>,
    pub(super) loop_breaks: Vec<(Option<String>, Vec<ValueFact>)>,
    pub(super) returned: Option<ValueFact>,
    pub(super) terminated: bool,
}

impl<'a> BodyEngine<'a> {
    pub(super) fn evaluate(
        index: &'a SemanticIndex,
        body: &'a BodyRecord,
        values: &'a HashMap<ValueDefId, ValueFact>,
        functions: &'a HashMap<ValueDefId, FunctionSummary>,
        type_facts: &'a TypeFactCache,
        mode: EvaluationMode,
    ) -> BodyEvaluation {
        let mut engine = Self {
            index,
            body,
            values,
            functions,
            type_facts,
            environment: BindingEnvironment::new(body.id, body.scope),
            mode,
            invoked_parameters: BTreeSet::new(),
            parameter_effects: BTreeMap::new(),
            calls: Vec::new(),
            unresolved: Vec::new(),
            macro_depth: 0,
            macro_stack: Vec::new(),
            loop_breaks: Vec::new(),
            returned: None,
            terminated: false,
        };
        let normal_output = match body.syntax_tree.as_ref() {
            BodySyntax::Function {
                signature,
                block,
                self_type,
            } => {
                engine.bind_arguments(signature, self_type.as_ref());
                engine.eval_block(block, true)
            }
            BodySyntax::Initializer { expression, .. } => engine.eval_expr(expression),
        };
        let output = engine.returned.take().map_or_else(
            || normal_output.clone(),
            |returned| {
                if normal_output.may_carry_target() {
                    returned.join(&normal_output)
                } else {
                    returned
                }
            },
        );
        BodyEvaluation {
            output,
            invoked_parameters: engine.invoked_parameters,
            parameter_effects: engine.parameter_effects,
            calls: engine.calls,
            unresolved: engine.unresolved,
        }
    }

    pub(super) const fn resolver(&self) -> FactResolver<'_> {
        FactResolver::new(self.index, self.values, self.type_facts)
    }

    pub(super) fn record_call(&mut self, expression: &syn::Expr, method: TargetMethod) {
        if self.mode == EvaluationMode::Analyze {
            let syntax = self
                .index
                .expr_context(expression)
                .map_or(self.body.syntax, |context| context.syntax);
            if self.index.source_origin(self.body.source) == SourceOrigin::OpaqueMacroInclude {
                self.unresolved.push(UnresolvedEvidence {
                    source: self.body.source,
                    syntax,
                    reason: UnresolvedReason::UnsupportedMacro,
                });
                return;
            }
            self.calls.push(CallEvidence {
                source: self.body.source,
                syntax,
                method,
            });
        }
    }

    pub(super) fn record_unresolved(&mut self, expression: &syn::Expr, reason: UnresolvedReason) {
        if self.mode == EvaluationMode::Analyze {
            let syntax = self
                .index
                .expr_context(expression)
                .map_or(self.body.syntax, |context| context.syntax);
            self.unresolved.push(UnresolvedEvidence {
                source: self.body.source,
                syntax,
                reason,
            });
        }
    }

    pub(super) fn begin_loop(&mut self, label: Option<String>) {
        self.loop_breaks.push((label, Vec::new()));
    }

    pub(super) fn finish_loop(&mut self) -> ValueFact {
        self.loop_breaks
            .pop()
            .expect("loop break frame exists")
            .1
            .into_iter()
            .reduce(|left, right| left.join(&right))
            .unwrap_or(ValueFact::NonTarget)
    }

    pub(super) fn record_break(&mut self, label: Option<&syn::Lifetime>, fact: ValueFact) -> bool {
        let label = label.map(|label| label.ident.to_string());
        let Some((_, breaks)) = self
            .loop_breaks
            .iter_mut()
            .rev()
            .find(|(candidate, _)| label.is_none() || candidate.as_ref() == label.as_ref())
        else {
            return false;
        };
        breaks.push(fact);
        true
    }

    pub(super) fn eval_block(&mut self, block: &syn::Block, nested: bool) -> ValueFact {
        if nested {
            let scope = self
                .index
                .block_context(block)
                .map_or_else(|| self.environment.current_scope(), |context| context.scope);
            self.environment.push_scope(scope);
        }
        let mut output = ValueFact::NonTarget;
        for statement in &block.stmts {
            output = self.eval_statement(statement);
            if self.terminated {
                break;
            }
        }
        if nested {
            self.environment.pop_scope();
        }
        output
    }

    fn eval_statement(&mut self, statement: &syn::Stmt) -> ValueFact {
        match statement {
            syn::Stmt::Local(local) if super::cfg_projection::is_production(&local.attrs) => {
                let inferred = local
                    .init
                    .as_ref()
                    .map_or(ValueFact::NonTarget, |init| self.eval_expr(&init.expr));
                let fact = if matches!(inferred, ValueFact::NonTarget) {
                    declared_pattern_fact(self, &local.pat)
                        .filter(ValueFact::may_carry_target)
                        .unwrap_or(ValueFact::NonTarget)
                } else {
                    inferred
                };
                self.bind_pattern(&local.pat, &fact);
                if let Some(diverge) = local.init.as_ref().and_then(|init| init.diverge.as_ref()) {
                    let saved = self.environment.clone();
                    let saved_terminated = self.terminated;
                    self.eval_expr(&diverge.1);
                    self.environment = saved;
                    self.terminated = saved_terminated;
                }
                ValueFact::NonTarget
            }
            syn::Stmt::Expr(expression, semicolon) => {
                let fact = self.eval_expr(expression);
                if semicolon.is_some() {
                    ValueFact::NonTarget
                } else {
                    fact
                }
            }
            syn::Stmt::Macro(statement)
                if super::cfg_projection::is_production(&statement.attrs) =>
            {
                self.eval_macro(&statement.mac)
            }
            syn::Stmt::Item(_) | syn::Stmt::Local(_) | syn::Stmt::Macro(_) => ValueFact::NonTarget,
        }
    }
}

fn declared_pattern_fact(engine: &BodyEngine<'_>, pattern: &syn::Pat) -> Option<ValueFact> {
    let syn::Pat::Type(pattern) = pattern else {
        return None;
    };
    Some(
        engine
            .resolver()
            .type_fact(engine.environment.current_scope(), &pattern.ty),
    )
}
