use std::collections::HashSet;

use super::super::bodies_types::FactResolver;
use super::super::provenance::{UnresolvedReason, ValueFact};
use super::super::semantic_index::{PathOrigin, Resolution};
use super::super::source_model::{ScopeId, TypeDefId};
use super::super::symbols::TypeKind;

pub(in super::super) fn recursive_back_edge_fact(
    resolver: &FactResolver<'_>,
    id: TypeDefId,
) -> ValueFact {
    if let Some(reaches) = resolver.type_facts.reaches_target.borrow().get(&id) {
        return if *reaches {
            ValueFact::MaybeTarget(UnresolvedReason::FixedPointLimit)
        } else {
            ValueFact::NonTarget
        };
    }
    let reaches = type_id_reaches_target(resolver, id, &mut HashSet::new());
    resolver
        .type_facts
        .reaches_target
        .borrow_mut()
        .insert(id, reaches);
    if reaches {
        ValueFact::MaybeTarget(UnresolvedReason::FixedPointLimit)
    } else {
        ValueFact::NonTarget
    }
}

fn type_id_reaches_target(
    resolver: &FactResolver<'_>,
    id: TypeDefId,
    visited: &mut HashSet<TypeDefId>,
) -> bool {
    let Resolution::Exact(canonical) = resolver.index.canonical_type(id) else {
        return true;
    };
    if !visited.insert(canonical) {
        return false;
    }
    let Some(record) = resolver.index.type_record(canonical) else {
        return false;
    };
    let reaches = match &record.kind {
        TypeKind::CanonicalTarget => true,
        TypeKind::Alias(ty) => type_reaches_target(resolver, record.scope, ty, visited),
        TypeKind::Struct(fields) | TypeKind::Union(fields) => fields
            .iter()
            .any(|field| type_reaches_target(resolver, record.scope, &field.ty, visited)),
        TypeKind::Enum(variants) => variants
            .iter()
            .flat_map(|variant| &variant.fields)
            .any(|field| type_reaches_target(resolver, record.scope, &field.ty, visited)),
    };
    visited.remove(&canonical);
    reaches
}

fn type_reaches_target(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    ty: &syn::Type,
    visited: &mut HashSet<TypeDefId>,
) -> bool {
    match ty {
        syn::Type::Path(path) => match resolver.index.resolve_type(scope, &path.path) {
            Resolution::Exact(id) => type_id_reaches_target(resolver, id, visited),
            Resolution::Ambiguous(ids) => ids
                .into_iter()
                .any(|id| type_id_reaches_target(resolver, id, visited)),
            Resolution::Missing => {
                missing_path_reaches_target(resolver, scope, &path.path, visited)
            }
        },
        syn::Type::Reference(ty) => type_reaches_target(resolver, scope, &ty.elem, visited),
        syn::Type::Paren(ty) => type_reaches_target(resolver, scope, &ty.elem, visited),
        syn::Type::Group(ty) => type_reaches_target(resolver, scope, &ty.elem, visited),
        syn::Type::Ptr(ty) => type_reaches_target(resolver, scope, &ty.elem, visited),
        syn::Type::Slice(ty) => type_reaches_target(resolver, scope, &ty.elem, visited),
        syn::Type::Array(ty) => type_reaches_target(resolver, scope, &ty.elem, visited),
        syn::Type::Tuple(ty) => ty
            .elems
            .iter()
            .any(|ty| type_reaches_target(resolver, scope, ty, visited)),
        syn::Type::BareFn(function) => {
            function
                .inputs
                .iter()
                .any(|input| type_reaches_target(resolver, scope, &input.ty, visited))
                || matches!(&function.output, syn::ReturnType::Type(_, ty)
                    if type_reaches_target(resolver, scope, ty, visited))
        }
        syn::Type::Macro(_) | syn::Type::ImplTrait(_) | syn::Type::TraitObject(_) => true,
        _ => false,
    }
}

fn missing_path_reaches_target(
    resolver: &FactResolver<'_>,
    scope: ScopeId,
    path: &syn::Path,
    visited: &mut HashSet<TypeDefId>,
) -> bool {
    let generic = path.segments.iter().any(|segment| {
        let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return false;
        };
        arguments.args.iter().any(|argument| {
            matches!(argument, syn::GenericArgument::Type(ty)
                if type_reaches_target(resolver, scope, ty, visited))
        })
    });
    generic
        || (resolver.index.path_origin(scope, path) == PathOrigin::ExternalOpaque
            && !is_modeled_container(path))
}

fn is_modeled_container(path: &syn::Path) -> bool {
    path.segments.last().is_some_and(|segment| {
        matches!(
            segment.ident.to_string().as_str(),
            "Option" | "Result" | "Box" | "Vec" | "Rc" | "Arc" | "Pin" | "Cell" | "RefCell"
        )
    })
}
