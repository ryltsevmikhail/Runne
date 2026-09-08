use super::bodies::BodyEngine;
use super::bodies_support::{expr_attributes, integer_index, member_key};
use super::provenance::{ShapeFact, ValueFact};

impl BodyEngine<'_> {
    #[allow(clippy::too_many_lines)]
    pub(super) fn eval_expr(&mut self, expression: &syn::Expr) -> ValueFact {
        if !super::cfg_projection::is_production(expr_attributes(expression)) {
            return ValueFact::NonTarget;
        }
        match expression {
            syn::Expr::Path(path) => self.eval_path(path),
            syn::Expr::Call(call) => self.eval_call(expression, call),
            syn::Expr::MethodCall(call) => self.eval_method_call(expression, call),
            syn::Expr::Struct(value) => self.eval_struct(value),
            syn::Expr::Tuple(tuple) => ValueFact::Aggregate(ShapeFact::Tuple {
                owner: None,
                items: tuple
                    .elems
                    .iter()
                    .map(|item| self.eval_expr(item))
                    .collect(),
            }),
            syn::Expr::Array(array) => ValueFact::Aggregate(ShapeFact::Sequence {
                items: array
                    .elems
                    .iter()
                    .map(|item| self.eval_expr(item))
                    .collect(),
            }),
            syn::Expr::Field(field) => {
                let base = self.eval_expr(&field.base);
                base.project_member(&member_key(&field.member))
            }
            syn::Expr::Index(index) => {
                let fact = self.eval_expr(&index.expr);
                self.eval_expr(&index.index);
                fact.project_index(integer_index(&index.index))
            }
            syn::Expr::Reference(reference) => ValueFact::Aggregate(ShapeFact::Reference(
                Box::new(self.eval_expr(&reference.expr)),
            )),
            syn::Expr::Paren(paren) => self.eval_expr(&paren.expr),
            syn::Expr::Group(group) => self.eval_expr(&group.expr),
            syn::Expr::Try(value) => self.eval_expr(&value.expr).contained_or_self(),
            syn::Expr::Cast(cast) => self.eval_expr(&cast.expr),
            syn::Expr::Unary(unary) => self.eval_expr(&unary.expr).transparent().clone(),
            syn::Expr::Block(block) => self.eval_block(&block.block, true),
            syn::Expr::If(value) => self.eval_if(value),
            syn::Expr::Match(value) => self.eval_match(value),
            syn::Expr::Let(value) => {
                self.eval_expr(&value.expr);
                ValueFact::NonTarget
            }
            syn::Expr::Assign(assign) => self.eval_assign(assign),
            syn::Expr::Return(value) => {
                let fact = value
                    .expr
                    .as_ref()
                    .map_or(ValueFact::NonTarget, |value| self.eval_expr(value));
                self.returned = Some(
                    self.returned
                        .take()
                        .map_or_else(|| fact.clone(), |current| current.join(&fact)),
                );
                self.terminated = true;
                ValueFact::NonTarget
            }
            syn::Expr::Closure(closure) => self.eval_closure(closure),
            syn::Expr::Macro(value) => self.eval_macro(&value.mac),
            syn::Expr::Await(value) => self.eval_expr(&value.base),
            syn::Expr::Async(value) => {
                let saved_environment = self.environment.clone();
                let saved_returned = self.returned.take();
                let saved_terminated = self.terminated;
                self.terminated = false;
                let normal_output = self.eval_block(&value.block, true);
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
                self.environment = saved_environment;
                self.returned = saved_returned;
                self.terminated = saved_terminated;
                output
            }
            syn::Expr::Binary(value) => {
                self.eval_expr(&value.left);
                self.eval_expr(&value.right)
            }
            syn::Expr::Range(value) => {
                value.start.as_ref().map(|item| self.eval_expr(item));
                value.end.as_ref().map(|item| self.eval_expr(item));
                ValueFact::NonTarget
            }
            syn::Expr::Repeat(value) => {
                let fact = self.eval_expr(&value.expr);
                ValueFact::Aggregate(ShapeFact::Sequence { items: vec![fact] })
            }
            syn::Expr::Loop(value) => self.eval_loop(value),
            syn::Expr::While(value) => self.eval_while(value),
            syn::Expr::ForLoop(value) => self.eval_for_loop(value),
            syn::Expr::Break(value) => {
                let fact = value
                    .expr
                    .as_ref()
                    .map_or(ValueFact::NonTarget, |item| self.eval_expr(item));
                if !self.record_break(value.label.as_ref(), fact.clone()) && fact.may_carry_target()
                {
                    self.record_unresolved(
                        expression,
                        super::provenance::UnresolvedReason::MissingTargetProvenance,
                    );
                }
                self.terminated = true;
                fact
            }
            syn::Expr::Yield(value) => value
                .expr
                .as_ref()
                .map_or(ValueFact::NonTarget, |item| self.eval_expr(item)),
            syn::Expr::Unsafe(value) => self.eval_block(&value.block, true),
            syn::Expr::Const(value) => self.eval_block(&value.block, true),
            syn::Expr::TryBlock(value) => self.eval_block(&value.block, true),
            syn::Expr::RawAddr(value) => self.eval_expr(&value.expr),
            syn::Expr::Continue(_) | syn::Expr::Infer(_) | syn::Expr::Lit(_) => {
                ValueFact::NonTarget
            }
            syn::Expr::Verbatim(_) => {
                self.record_unresolved(
                    expression,
                    super::provenance::UnresolvedReason::UnsupportedMacro,
                );
                ValueFact::MaybeTarget(super::provenance::UnresolvedReason::UnsupportedMacro)
            }
            _ => {
                self.record_unresolved(
                    expression,
                    super::provenance::UnresolvedReason::MissingTargetProvenance,
                );
                ValueFact::MaybeTarget(super::provenance::UnresolvedReason::MissingTargetProvenance)
            }
        }
    }
}
