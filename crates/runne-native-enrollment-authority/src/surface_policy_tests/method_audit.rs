#![cfg(test)]

use syn::{FnArg, GenericArgument, ItemImpl, PathArguments, ReturnType, Type};

use super::platform_method_audit::{is_exact_macos_claim_parts, is_exact_macos_effect_parts};
use super::{CLAIM, EFFECT, HANDOFF, PINNED, SESSION, attribute_audit, type_opaque_name};

pub(super) fn exact_public_method(
    item: &ItemImpl,
    method: &syn::ImplItemFn,
) -> Option<&'static str> {
    if is_exact_consuming_split(item, method) {
        Some("split")
    } else if is_exact_stdin_receiver(item, method) {
        Some("receive_from_stdin")
    } else if is_exact_pinned_observer(item, method) {
        Some("observe_current_pinned_writer_session")
    } else if is_exact_current_writer_authenticator(item, method) {
        Some("authenticate_current_writer")
    } else if is_exact_macos_claim_parts(item, method) {
        Some("into_macos_claim_parts")
    } else if is_exact_macos_effect_parts(item, method) {
        Some("into_macos_effect_parts")
    } else {
        None
    }
}

fn is_exact_current_writer_authenticator(item: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    type_opaque_name(&item.self_ty) == Some(PINNED)
        && item.trait_.is_none()
        && method.defaultness.is_none()
        && method.sig.ident == "authenticate_current_writer"
        && method.sig.constness.is_none()
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.variadic.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && !attribute_audit::has_cfg_or_path_substitution(&method.attrs)
        && method.sig.inputs.len() == 1
        && matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
            if receiver.reference.is_none()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none())
        && returns_exact_authenticated_result(&method.sig.output)
}

fn is_exact_pinned_observer(item: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    type_opaque_name(&item.self_ty) == Some(HANDOFF)
        && item.trait_.is_none()
        && method.defaultness.is_none()
        && method.sig.ident == "observe_current_pinned_writer_session"
        && method.sig.constness.is_none()
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.variadic.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && !attribute_audit::has_cfg_or_path_substitution(&method.attrs)
        && method.sig.inputs.len() == 1
        && matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
            if receiver.reference.is_none()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none())
        && returns_exact_pinned_result(&method.sig.output)
}

fn is_exact_consuming_split(item: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    type_opaque_name(&item.self_ty) == Some(SESSION)
        && item.trait_.is_none()
        && method.defaultness.is_none()
        && method.sig.ident == "split"
        && method.sig.constness.is_none()
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.variadic.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && !attribute_audit::has_cfg_or_path_substitution(&method.attrs)
        && method.sig.inputs.len() == 1
        && matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
            if receiver.reference.is_none()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none())
        && returns_exact_split_pair(&method.sig.output)
}

fn is_exact_stdin_receiver(item: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    type_opaque_name(&item.self_ty) == Some(HANDOFF)
        && item.trait_.is_none()
        && method.defaultness.is_none()
        && method.sig.ident == "receive_from_stdin"
        && method.sig.constness.is_none()
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.variadic.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && method.sig.inputs.is_empty()
        && !attribute_audit::has_cfg_or_path_substitution(&method.attrs)
        && returns_std_io_result_self(&method.sig.output)
}

fn returns_exact_split_pair(output: &ReturnType) -> bool {
    let ReturnType::Type(_, value) = output else {
        return false;
    };
    let Type::Tuple(tuple) = value.as_ref() else {
        return false;
    };
    tuple.elems.len() == 2
        && type_opaque_name(&tuple.elems[0]) == Some(CLAIM)
        && type_opaque_name(&tuple.elems[1]) == Some(EFFECT)
}

fn returns_std_io_result_self(output: &ReturnType) -> bool {
    let ReturnType::Type(_, value) = output else {
        return false;
    };
    let Type::Path(result) = value.as_ref() else {
        return false;
    };
    if result.qself.is_some() || result.path.leading_colon.is_some() {
        return false;
    }
    let names: Vec<_> = result
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if names != ["std", "io", "Result"] {
        return false;
    }
    let PathArguments::AngleBracketed(arguments) = &result.path.segments[2].arguments else {
        return false;
    };
    arguments.args.len() == 1
        && matches!(arguments.args.first(), Some(GenericArgument::Type(Type::Path(value)))
            if value.qself.is_none()
                && value.path.segments.len() == 1
                && value.path.segments[0].ident == "Self"
                && matches!(value.path.segments[0].arguments, PathArguments::None))
}

fn returns_exact_pinned_result(output: &ReturnType) -> bool {
    let ReturnType::Type(_, value) = output else {
        return false;
    };
    let Type::Path(result) = value.as_ref() else {
        return false;
    };
    let Some(segment) = result.path.segments.first() else {
        return false;
    };
    if result.qself.is_some()
        || result.path.leading_colon.is_some()
        || result.path.segments.len() != 1
        || segment.ident != "Result"
    {
        return false;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let mut arguments = arguments.args.iter();
    let Some(GenericArgument::Type(ok)) = arguments.next() else {
        return false;
    };
    let Some(GenericArgument::Type(Type::Path(error))) = arguments.next() else {
        return false;
    };
    arguments.next().is_none()
        && type_opaque_name(ok) == Some(PINNED)
        && error.qself.is_none()
        && error.path.leading_colon.is_none()
        && error.path.segments.len() == 2
        && error.path.segments[0].ident == "runne_macos_process_identity"
        && error.path.segments[1].ident == "MacOsPackagedWriterObservationError"
        && error
            .path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}

fn returns_exact_authenticated_result(output: &ReturnType) -> bool {
    let ReturnType::Type(_, value) = output else {
        return false;
    };
    let Type::Path(result) = value.as_ref() else {
        return false;
    };
    let Some(segment) = result.path.segments.first() else {
        return false;
    };
    if result.qself.is_some()
        || result.path.leading_colon.is_some()
        || result.path.segments.len() != 1
        || segment.ident != "Result"
    {
        return false;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let mut arguments = arguments.args.iter();
    let Some(GenericArgument::Type(ok)) = arguments.next() else {
        return false;
    };
    let Some(GenericArgument::Type(Type::Path(error))) = arguments.next() else {
        return false;
    };
    arguments.next().is_none()
        && type_opaque_name(ok) == Some(SESSION)
        && error.qself.is_none()
        && error.path.leading_colon.is_none()
        && error.path.segments.len() == 2
        && error.path.segments[0].ident == "runne_macos_process_identity"
        && error.path.segments[1].ident == "MacOsPackagedWriterObservationError"
        && error
            .path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}
