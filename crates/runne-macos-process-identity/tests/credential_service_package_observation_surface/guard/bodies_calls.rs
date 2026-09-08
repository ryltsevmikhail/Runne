use super::bodies::BodyEngine;
use super::bodies_support::{qualifier, target_method_name};
use super::provenance::{ShapeFact, TargetMethod, UnresolvedReason, ValueFact};
use super::semantic_index::{PathOrigin, Resolution};
use super::source_model::SourceOrigin;

#[path = "bodies_call_resolution.rs"]
mod resolution;
use resolution::is_container_constructor;
#[path = "bodies_call_missing_paths.rs"]
mod missing_paths;

impl BodyEngine<'_> {
    pub(super) fn eval_path(&self, expression: &syn::ExprPath) -> ValueFact {
        if let Some(qself) = &expression.qself
            && let Some(method) = target_method_name(self, &expression.path)
        {
            return match self
                .resolver()
                .type_fact(self.environment.current_scope(), &qself.ty)
                .transparent()
            {
                ValueFact::TargetObject(id) if self.resolver().canonical_target() == Some(*id) => {
                    ValueFact::TargetCallable(method)
                }
                ValueFact::MaybeTarget(reason) => ValueFact::MaybeTarget(reason.clone()),
                ValueFact::OpaqueExternal => {
                    ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
                }
                _ => ValueFact::NonTarget,
            };
        }
        if expression.qself.is_none() && expression.path.segments.len() == 1 {
            let name = expression.path.segments[0].ident.to_string();
            if let Some(fact) = self.environment.lookup(&name) {
                return fact.clone();
            }
        }
        match self
            .index
            .resolve_value(self.environment.current_scope(), &expression.path)
        {
            Resolution::Exact(id) => self.resolver().value_fact(id),
            Resolution::Ambiguous(ids) => self.resolver().value_candidates_fact(&ids),
            Resolution::Missing => {
                let missing = self.missing_path_fact(expression);
                if matches!(missing, ValueFact::NonTarget)
                    && let Resolution::Exact(_) = self
                        .index
                        .resolve_type(self.environment.current_scope(), &expression.path)
                {
                    self.resolver().type_fact(
                        self.environment.current_scope(),
                        &syn::Type::Path(syn::TypePath {
                            qself: None,
                            path: expression.path.clone(),
                        }),
                    )
                } else {
                    missing
                }
            }
        }
    }

    fn missing_path_fact(&self, expression: &syn::ExprPath) -> ValueFact {
        if matches!(
            self.index.source_origin(self.body.source),
            SourceOrigin::ContextDependentInclude | SourceOrigin::OpaqueMacroInclude
        ) {
            return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
        }
        let target_method = target_method_name(self, &expression.path).is_some();
        let origin_path = if target_method {
            qualifier(&expression.path)
        } else {
            expression.path.clone()
        };
        let origin = self
            .index
            .path_origin(self.environment.current_scope(), &origin_path);
        if target_method && matches!(origin, PathOrigin::ExternalOpaque | PathOrigin::Unknown) {
            return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
        }
        match origin {
            PathOrigin::ExternalOpaque => ValueFact::OpaqueExternal,
            _ => ValueFact::NonTarget,
        }
    }

    pub(super) fn eval_call(&mut self, expression: &syn::Expr, call: &syn::ExprCall) -> ValueFact {
        let callee = self.eval_expr(&call.func);
        let arguments = call
            .args
            .iter()
            .map(|argument| self.eval_expr(argument))
            .collect::<Vec<_>>();
        if let Some(summary) = self.resolved_function_summary(&call.func).cloned() {
            self.apply_summary(expression, &summary, &arguments);
            return summary.output.substitute_parameters(&arguments);
        }
        if let Some(owner) = self.tuple_constructor_owner(&call.func)
            && (arguments.iter().any(ValueFact::may_carry_target)
                || (call.args.is_empty() && self.source_has_item_macro()))
        {
            return ValueFact::Aggregate(ShapeFact::Tuple {
                owner: Some(owner),
                items: arguments,
            });
        }
        if is_container_constructor(&call.func) && arguments.iter().any(ValueFact::may_carry_target)
        {
            return ValueFact::Aggregate(ShapeFact::Tuple {
                owner: None,
                items: arguments,
            });
        }
        if matches!(callee.transparent(), ValueFact::OpaqueExternal)
            && arguments.iter().any(ValueFact::may_carry_target)
        {
            self.record_unresolved(expression, UnresolvedReason::MissingTargetProvenance);
            return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
        }
        if matches!(callee.transparent(), ValueFact::NonTarget)
            && self.is_unresolved_local_path(&call.func)
            && (arguments.iter().any(ValueFact::may_carry_target)
                || (call.args.is_empty() && self.source_has_item_macro()))
        {
            self.record_unresolved(expression, UnresolvedReason::MissingTargetProvenance);
            return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
        }
        self.invoke_fact(expression, &callee, &arguments)
    }

    pub(super) fn eval_method_call(
        &mut self,
        expression: &syn::Expr,
        call: &syn::ExprMethodCall,
    ) -> ValueFact {
        let receiver = self.eval_expr(&call.receiver);
        let arguments = call
            .args
            .iter()
            .map(|argument| self.eval_expr(argument))
            .collect::<Vec<_>>();
        if call.method == self.index.target.verify_method.as_str() {
            match receiver.transparent() {
                ValueFact::TargetObject(id) if self.resolver().canonical_target() == Some(*id) => {
                    self.record_call(expression, TargetMethod::Verify);
                }
                ValueFact::MaybeTarget(reason) => {
                    self.record_unresolved(expression, reason.clone());
                }
                ValueFact::OpaqueExternal => {
                    self.record_unresolved(expression, UnresolvedReason::MissingTargetProvenance);
                }
                ValueFact::CallableParameter(parameter) => {
                    self.parameter_effects
                        .insert(*parameter, TargetMethod::Verify);
                }
                _ => {}
            }
            return ValueFact::NonTarget;
        }
        if let Some(summary) = self
            .resolved_method_summary(&call.method, &receiver)
            .cloned()
        {
            self.apply_summary(expression, &summary, &arguments);
            let output = summary.output.substitute_parameters(&arguments);
            if call.method == "unwrap_or"
                && receiver.may_carry_target()
                && !output.may_carry_target()
            {
                self.record_unresolved(expression, UnresolvedReason::MissingTargetProvenance);
                return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
            }
            return output;
        }
        if call.method == "unwrap_or" {
            let fallback = arguments.first().unwrap_or(&ValueFact::NonTarget);
            if super::bodies_call_fallbacks::is_none_constructor(&call.receiver) {
                fallback.clone()
            } else {
                receiver.contained_or_self().join(fallback)
            }
        } else if matches!(
            call.method.to_string().as_str(),
            "unwrap" | "expect" | "as_ref" | "as_mut"
        ) {
            receiver.contained_or_self()
        } else if receiver.may_carry_target() || arguments.iter().any(ValueFact::may_carry_target) {
            self.record_unresolved(expression, UnresolvedReason::MissingTargetProvenance);
            ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
        } else {
            receiver
        }
    }

    fn invoke_fact(
        &mut self,
        expression: &syn::Expr,
        fact: &ValueFact,
        arguments: &[ValueFact],
    ) -> ValueFact {
        match fact.transparent() {
            ValueFact::TargetCallable(method) => {
                let method = *method;
                self.record_call(expression, method);
                self.target_output(method)
            }
            ValueFact::Callable(callable) => {
                let callable = callable.clone();
                self.apply_callable(expression, &callable, arguments);
                callable.output.substitute_parameters(arguments)
            }
            ValueFact::CallableParameter(parameter) => {
                self.invoked_parameters.insert(*parameter);
                ValueFact::NonTarget
            }
            ValueFact::MaybeTarget(reason) => {
                let reason = reason.clone();
                self.record_unresolved(expression, reason.clone());
                ValueFact::MaybeTarget(reason)
            }
            _ => ValueFact::NonTarget,
        }
    }

    fn apply_argument_effect(&mut self, expression: &syn::Expr, argument: &ValueFact) {
        match argument.transparent() {
            ValueFact::TargetCallable(method) => self.record_call(expression, *method),
            ValueFact::Callable(callable) => {
                self.apply_callable(expression, callable, &[]);
            }
            ValueFact::MaybeTarget(reason) => self.record_unresolved(expression, reason.clone()),
            ValueFact::CallableParameter(parameter) => {
                self.invoked_parameters.insert(*parameter);
            }
            _ => {}
        }
    }

    fn apply_summary(
        &mut self,
        expression: &syn::Expr,
        summary: &super::bodies::FunctionSummary,
        arguments: &[ValueFact],
    ) {
        for parameter in &summary.invoked_parameters {
            if let Some(argument) = arguments.get(*parameter as usize) {
                self.apply_argument_effect(expression, argument);
            }
        }
        for (parameter, method) in &summary.parameter_effects {
            if let Some(argument) = arguments.get(*parameter as usize) {
                self.apply_parameter_effect(expression, argument, *method);
            }
        }
    }

    fn apply_callable(
        &mut self,
        expression: &syn::Expr,
        callable: &super::provenance::CallableFact,
        arguments: &[ValueFact],
    ) {
        let summary = super::bodies::FunctionSummary {
            output: (*callable.output).clone(),
            invoked_parameters: callable.invoked_parameters.clone(),
            parameter_effects: callable.parameter_effects.clone(),
        };
        self.apply_summary(expression, &summary, arguments);
    }

    fn apply_parameter_effect(
        &mut self,
        expression: &syn::Expr,
        argument: &ValueFact,
        method: TargetMethod,
    ) {
        match argument.transparent() {
            ValueFact::TargetObject(id) if self.resolver().canonical_target() == Some(*id) => {
                self.record_call(expression, method);
            }
            ValueFact::MaybeTarget(reason) => self.record_unresolved(expression, reason.clone()),
            ValueFact::OpaqueExternal => {
                self.record_unresolved(expression, UnresolvedReason::MissingTargetProvenance);
            }
            _ => {}
        }
    }
}
