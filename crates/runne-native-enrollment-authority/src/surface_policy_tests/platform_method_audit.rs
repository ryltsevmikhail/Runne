#![cfg(test)]

use syn::{FnArg, GenericArgument, ItemImpl, PathArguments, ReturnType, Type};

use super::{CLAIM, EFFECT, attribute_audit, type_opaque_name};

pub(super) fn is_exact_macos_claim_parts(item: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    exact_consuming_method(item, method, CLAIM, "into_macos_claim_parts")
        && returns_exact_result(
            &method.sig.output,
            &[
                &["CredentialWriterClaimIssuer"],
                &["std", "os", "unix", "net", "UnixStream"],
                &["runne_provider", "BrokerChannelBinding"],
                &["runne_provider", "PendingCredentialIssueTicketV1"],
            ],
        )
}

pub(super) fn is_exact_macos_effect_parts(item: &ItemImpl, method: &syn::ImplItemFn) -> bool {
    exact_consuming_method(item, method, EFFECT, "into_macos_effect_parts")
        && returns_exact_result(
            &method.sig.output,
            &[
                &["CredentialWriterEffectAuthority"],
                &["std", "path", "PathBuf"],
                &["std", "path", "PathBuf"],
            ],
        )
}

fn exact_consuming_method(
    item: &ItemImpl,
    method: &syn::ImplItemFn,
    owner: &str,
    name: &str,
) -> bool {
    type_opaque_name(&item.self_ty) == Some(owner)
        && item.trait_.is_none()
        && attribute_audit::has_exact_macos_cfg(&item.attrs)
        && method.defaultness.is_none()
        && method.sig.ident == name
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
}

fn returns_exact_result(output: &ReturnType, expected: &[&[&str]]) -> bool {
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
    let Some(GenericArgument::Type(Type::Tuple(tuple))) = arguments.next() else {
        return false;
    };
    let Some(GenericArgument::Type(error)) = arguments.next() else {
        return false;
    };
    arguments.next().is_none()
        && tuple.elems.len() == expected.len()
        && tuple
            .elems
            .iter()
            .zip(expected)
            .all(|(actual, expected)| type_path_is(actual, expected))
        && type_path_is(
            error,
            &[
                "runne_macos_process_identity",
                "MacOsPackagedWriterObservationError",
            ],
        )
}

fn type_path_is(value: &Type, expected: &[&str]) -> bool {
    let Type::Path(path) = value else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path.path.segments.iter().zip(expected).all(|(part, name)| {
            part.ident == *name && matches!(part.arguments, PathArguments::None)
        })
}
