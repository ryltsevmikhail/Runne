use super::super::bodies::BodyEngine;
use super::super::provenance::ValueFact;

impl BodyEngine<'_> {
    pub(super) fn bind_arguments(
        &mut self,
        signature: &syn::Signature,
        self_type: Option<&syn::Type>,
    ) {
        let mut positional = 0_u16;
        for argument in &signature.inputs {
            match argument {
                syn::FnArg::Receiver(_) => {
                    let fact = self_type.map_or(ValueFact::NonTarget, |ty| {
                        self.resolver().type_fact(self.body.scope, ty)
                    });
                    self.environment.bind_self(fact);
                }
                syn::FnArg::Typed(argument) => {
                    let symbolic_parameter = generic_parameter_name(&argument.ty)
                        .is_some_and(|name| generic_is_declared(signature, &name))
                        || self
                            .resolver()
                            .is_callable_type(self.body.scope, &argument.ty)
                        || generic_parameter_name(&argument.ty)
                            .as_ref()
                            .is_some_and(|name| generic_is_callable(signature, name));
                    let fact = if symbolic_parameter {
                        ValueFact::CallableParameter(positional)
                    } else {
                        self.resolver().type_fact(self.body.scope, &argument.ty)
                    };
                    self.bind_pattern(&argument.pat, &fact);
                    positional += 1;
                }
            }
        }
    }
}

fn generic_parameter_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    (path.qself.is_none() && path.path.segments.len() == 1)
        .then(|| path.path.segments[0].ident.to_string())
}

fn generic_is_callable(signature: &syn::Signature, name: &str) -> bool {
    let direct = signature.generics.params.iter().any(|parameter| {
        matches!(parameter, syn::GenericParam::Type(parameter) if parameter.ident == name && parameter.bounds.iter().any(callable_bound))
    });
    direct
        || signature
            .generics
            .where_clause
            .iter()
            .flat_map(|clause| &clause.predicates)
            .any(|predicate| {
                matches!(predicate, syn::WherePredicate::Type(predicate)
                    if generic_parameter_name(&predicate.bounded_ty).as_deref() == Some(name)
                        && predicate.bounds.iter().any(callable_bound))
            })
}

fn generic_is_declared(signature: &syn::Signature, name: &str) -> bool {
    signature
        .generics
        .params
        .iter()
        .any(|parameter| matches!(parameter, syn::GenericParam::Type(ty) if ty.ident == name))
}

fn callable_bound(bound: &syn::TypeParamBound) -> bool {
    matches!(bound, syn::TypeParamBound::Trait(bound)
        if bound.path.segments.last().is_some_and(|segment|
            matches!(segment.ident.to_string().as_str(), "Fn" | "FnMut" | "FnOnce")))
}
