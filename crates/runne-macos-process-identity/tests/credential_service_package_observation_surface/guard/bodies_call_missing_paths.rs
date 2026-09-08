use super::super::bodies::BodyEngine;
use super::super::provenance::{TargetMethod, UnresolvedReason, ValueFact};
use super::super::semantic_index::Resolution;

impl BodyEngine<'_> {
    pub(super) fn is_unresolved_local_path(&self, expression: &syn::Expr) -> bool {
        match expression {
            syn::Expr::Paren(paren) => self.is_unresolved_local_path(&paren.expr),
            syn::Expr::Group(group) => self.is_unresolved_local_path(&group.expr),
            syn::Expr::Reference(reference) => self.is_unresolved_local_path(&reference.expr),
            syn::Expr::Unary(unary) => self.is_unresolved_local_path(&unary.expr),
            syn::Expr::Cast(cast) => self.is_unresolved_local_path(&cast.expr),
            syn::Expr::Block(block) => single_tail_expression(&block.block)
                .is_some_and(|tail| self.is_unresolved_local_path(tail)),
            syn::Expr::Path(path) => self.is_unresolved_path(path),
            _ => false,
        }
    }

    fn is_unresolved_path(&self, path: &syn::ExprPath) -> bool {
        if path.qself.is_some() || path.path.segments.len() != 1 || path.path.is_ident("drop") {
            return false;
        }
        matches!(
            self.index
                .resolve_value(self.environment.current_scope(), &path.path),
            Resolution::Missing
        ) && matches!(
            self.index
                .resolve_type(self.environment.current_scope(), &path.path),
            Resolution::Missing
        )
    }

    pub(super) fn source_has_item_macro(&self) -> bool {
        self.index.items.iter().any(|item| {
            item.source == self.body.source
                && matches!(&item.item, syn::Item::Macro(value) if value.ident.is_none())
        })
    }

    pub(super) fn target_output(&self, method: TargetMethod) -> ValueFact {
        match method {
            TargetMethod::Capture => self.resolver().canonical_target().map_or(
                ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance),
                ValueFact::TargetObject,
            ),
            TargetMethod::Verify => ValueFact::NonTarget,
        }
    }
}

fn single_tail_expression(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(expression, None)] => Some(expression),
        _ => None,
    }
}
