use super::bodies::BodyEngine;
use super::bodies_support::member_key;
use super::provenance::{CallableFact, ShapeFact, ValueFact};
use super::semantic_index::Resolution;

impl BodyEngine<'_> {
    pub(super) fn eval_closure(&mut self, value: &syn::ExprClosure) -> ValueFact {
        let saved_environment = self.environment.clone();
        let saved_invoked = std::mem::take(&mut self.invoked_parameters);
        let saved_effects = std::mem::take(&mut self.parameter_effects);
        let saved_returned = self.returned.take();
        let saved_terminated = self.terminated;
        self.terminated = false;
        let scope = self
            .index
            .expr_context(&value.body)
            .map_or_else(|| self.environment.current_scope(), |context| context.scope);
        self.environment.push_scope(scope);
        for (position, pattern) in value.inputs.iter().enumerate() {
            let parameter = u16::try_from(position).expect("closure parameter count exceeds u16");
            self.environment
                .bind_pattern(pattern, &ValueFact::CallableParameter(parameter));
        }
        let normal_output = self.eval_expr(&value.body);
        let output = self.returned.take().map_or_else(
            || normal_output.clone(),
            |returned| {
                if normal_output.may_carry_target() {
                    returned.join(&normal_output)
                } else {
                    returned
                }
            },
        );
        let invoked_parameters = std::mem::replace(&mut self.invoked_parameters, saved_invoked);
        let parameter_effects = std::mem::replace(&mut self.parameter_effects, saved_effects);
        self.returned = saved_returned;
        self.terminated = saved_terminated;
        self.environment = saved_environment;
        ValueFact::Callable(CallableFact {
            output: Box::new(output),
            invoked_parameters,
            parameter_effects,
        })
    }

    pub(super) fn eval_loop(&mut self, value: &syn::ExprLoop) -> ValueFact {
        let saved_terminated = self.terminated;
        self.begin_loop(
            value
                .label
                .as_ref()
                .map(|label| label.name.ident.to_string()),
        );
        self.terminated = false;
        self.eval_block(&value.body, true);
        let output = self.finish_loop();
        self.terminated = saved_terminated;
        output
    }

    pub(super) fn eval_while(&mut self, value: &syn::ExprWhile) -> ValueFact {
        let saved = self.environment.clone();
        let bindings = self.condition_bindings(&value.cond);
        self.environment = saved.clone();
        let scope = self
            .index
            .block_context(&value.body)
            .map_or_else(|| self.environment.current_scope(), |context| context.scope);
        self.environment.push_scope(scope);
        for (scope, pattern, fact) in bindings {
            self.bind_pattern_in_scope(scope, pattern, &fact);
        }
        let saved_terminated = self.terminated;
        self.begin_loop(
            value
                .label
                .as_ref()
                .map(|label| label.name.ident.to_string()),
        );
        self.eval_block(&value.body, false);
        self.finish_loop();
        self.terminated = saved_terminated;
        self.environment.pop_scope();
        let body_environment = self.environment.clone();
        self.environment = saved;
        self.environment.join_from(&body_environment);
        ValueFact::NonTarget
    }

    pub(super) fn eval_for_loop(&mut self, value: &syn::ExprForLoop) -> ValueFact {
        let source = self.eval_expr(&value.expr).project_index(None);
        let saved = self.environment.clone();
        let pattern_scope = self.environment.current_scope();
        let scope = self
            .index
            .block_context(&value.body)
            .map_or_else(|| self.environment.current_scope(), |context| context.scope);
        self.environment.push_scope(scope);
        self.bind_pattern_in_scope(pattern_scope, &value.pat, &source);
        let saved_terminated = self.terminated;
        self.begin_loop(
            value
                .label
                .as_ref()
                .map(|label| label.name.ident.to_string()),
        );
        self.eval_block(&value.body, false);
        self.finish_loop();
        self.terminated = saved_terminated;
        self.environment.pop_scope();
        self.environment.join_from(&saved);
        ValueFact::NonTarget
    }

    pub(super) fn eval_struct(&mut self, value: &syn::ExprStruct) -> ValueFact {
        let resolution = self
            .index
            .resolve_type(self.environment.current_scope(), &value.path);
        let mut fact = match &resolution {
            Resolution::Exact(_) => self.resolver().type_fact(
                self.environment.current_scope(),
                &syn::Type::Path(syn::TypePath {
                    qself: None,
                    path: value.path.clone(),
                }),
            ),
            Resolution::Ambiguous(ids) => self.resolver().type_candidates_fact(ids),
            Resolution::Missing => ValueFact::NonTarget,
        };
        let explicit = value
            .fields
            .iter()
            .map(|field| (member_key(&field.member), self.eval_expr(&field.expr)))
            .collect::<std::collections::BTreeMap<_, _>>();
        if let ValueFact::Aggregate(ShapeFact::Record { fields, .. }) = &mut fact {
            fields.extend(explicit);
        } else if !explicit.is_empty() {
            let owner = match resolution {
                Resolution::Exact(id) => Some(id),
                Resolution::Ambiguous(_) | Resolution::Missing => None,
            };
            fact = ValueFact::Aggregate(ShapeFact::Record {
                owner,
                fields: explicit,
            });
        }
        if let Some(rest) = &value.rest {
            self.eval_expr(rest);
        }
        fact
    }

    pub(super) fn eval_assign(&mut self, value: &syn::ExprAssign) -> ValueFact {
        let fact = self.eval_expr(&value.right);
        if let Some((name, projection)) = super::assignments::assignment_projection(&value.left) {
            if !self
                .environment
                .assign_projection(&name, &projection, fact.clone())
                && fact.may_carry_target()
            {
                self.record_unresolved(
                    &syn::Expr::Assign(value.clone()),
                    super::provenance::UnresolvedReason::MissingTargetProvenance,
                );
            }
        } else if fact.may_carry_target() {
            self.record_unresolved(
                &syn::Expr::Assign(value.clone()),
                super::provenance::UnresolvedReason::MissingTargetProvenance,
            );
        }
        ValueFact::NonTarget
    }

    pub(super) fn eval_if(&mut self, value: &syn::ExprIf) -> ValueFact {
        let saved = self.environment.clone();
        let bindings = self.condition_bindings(&value.cond);
        self.environment = saved.clone();
        let scope = self
            .index
            .block_context(&value.then_branch)
            .map_or_else(|| self.environment.current_scope(), |context| context.scope);
        self.environment.push_scope(scope);
        for (scope, pattern, fact) in bindings {
            self.bind_pattern_in_scope(scope, pattern, &fact);
        }
        self.terminated = false;
        let left = self.eval_block(&value.then_branch, false);
        let left_terminated = self.terminated;
        self.environment.pop_scope();
        let left_environment = self.environment.clone();
        self.environment = saved.clone();
        self.terminated = false;
        let right = value
            .else_branch
            .as_ref()
            .map_or(ValueFact::NonTarget, |(_, branch)| self.eval_expr(branch));
        let right_terminated = value.else_branch.is_some() && self.terminated;
        let right_environment = self.environment.clone();
        self.environment = saved;
        self.environment.join_from(&left_environment);
        self.environment.join_from(&right_environment);
        self.terminated = left_terminated && right_terminated;
        left.join(&right)
    }

    fn condition_bindings<'a>(
        &mut self,
        condition: &'a syn::Expr,
    ) -> Vec<(super::source_model::ScopeId, &'a syn::Pat, ValueFact)> {
        let mut bindings = Vec::new();
        self.collect_condition_bindings(self.body.scope, condition, &mut bindings);
        bindings
    }

    fn collect_condition_bindings<'a>(
        &mut self,
        scope: super::source_model::ScopeId,
        condition: &'a syn::Expr,
        bindings: &mut Vec<(super::source_model::ScopeId, &'a syn::Pat, ValueFact)>,
    ) {
        match condition {
            syn::Expr::Let(value) => {
                let fact = self.eval_expr(&value.expr);
                self.bind_pattern_in_scope(scope, &value.pat, &fact);
                bindings.push((scope, &value.pat, fact));
            }
            syn::Expr::Binary(value) if matches!(value.op, syn::BinOp::And(_)) => {
                self.collect_condition_bindings(scope, &value.left, bindings);
                self.collect_condition_bindings(scope, &value.right, bindings);
            }
            syn::Expr::Paren(value) => {
                self.collect_condition_bindings(scope, &value.expr, bindings);
            }
            syn::Expr::Group(value) => {
                self.collect_condition_bindings(scope, &value.expr, bindings);
            }
            _ => {
                self.eval_expr(condition);
            }
        }
    }

    pub(super) fn eval_match(&mut self, value: &syn::ExprMatch) -> ValueFact {
        let input = self.eval_expr(&value.expr);
        let saved = self.environment.clone();
        let mut output: Option<ValueFact> = None;
        let mut joined = saved.clone();
        let mut all_terminated = !value.arms.is_empty();
        for arm in &value.arms {
            if !super::cfg_projection::is_production(&arm.attrs) {
                continue;
            }
            self.environment = saved.clone();
            self.terminated = false;
            self.bind_pattern(&arm.pat, &input);
            if let Some((_, guard)) = &arm.guard {
                self.eval_expr(guard);
            }
            let fact = self.eval_expr(&arm.body);
            all_terminated &= self.terminated;
            output = Some(output.map_or_else(|| fact.clone(), |current| current.join(&fact)));
            joined.join_from(&self.environment);
        }
        self.environment = joined;
        self.terminated = all_terminated;
        output.unwrap_or(ValueFact::NonTarget)
    }
}
