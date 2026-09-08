use super::super::bodies::{BodyEngine, FunctionSummary};
use super::super::provenance::{ShapeFact, ValueFact};
use super::super::semantic_index::Resolution;

impl BodyEngine<'_> {
    pub(super) fn tuple_constructor_owner(
        &self,
        expression: &syn::Expr,
    ) -> Option<super::super::source_model::TypeDefId> {
        let syn::Expr::Path(path) = expression else {
            return None;
        };
        let Resolution::Exact(owner) = self
            .index
            .resolve_type(self.environment.current_scope(), &path.path)
        else {
            return None;
        };
        Some(owner)
    }

    pub(super) fn resolved_function_summary(
        &self,
        expression: &syn::Expr,
    ) -> Option<&FunctionSummary> {
        let syn::Expr::Path(path) = expression else {
            return None;
        };
        let Resolution::Exact(id) = self
            .index
            .resolve_value(self.environment.current_scope(), &path.path)
        else {
            return None;
        };
        self.functions.get(&id)
    }

    pub(super) fn resolved_method_summary(
        &self,
        method: &syn::Ident,
        receiver: &ValueFact,
    ) -> Option<&FunctionSummary> {
        let owner = match receiver.transparent() {
            ValueFact::Aggregate(
                ShapeFact::Record { owner, .. } | ShapeFact::Tuple { owner, .. },
            ) => *owner,
            ValueFact::TargetObject(owner) => Some(*owner),
            _ => None,
        }?;
        let mut candidates = self.index.values().filter(|record| {
            record.owner == Some(owner)
                && *method == record.name
                && self.functions.contains_key(&record.id)
        });
        let first = candidates.next()?;
        candidates
            .next()
            .is_none()
            .then(|| &self.functions[&first.id])
    }
}

pub(super) fn is_container_constructor(expression: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.path.segments.last().is_some_and(|segment| {
        matches!(
            segment.ident.to_string().as_str(),
            "Some" | "Ok" | "Box" | "new"
        )
    })
}
