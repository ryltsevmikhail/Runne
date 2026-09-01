use syn::{Expr, ExprMethodCall};

pub fn path_is(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected && segment.arguments.is_empty())
}

pub fn pinned_observe_is_reviewed(relative: &str, call: &ExprMethodCall, broker: &str) -> bool {
    let Expr::Path(receiver) = call.receiver.as_ref() else {
        return false;
    };
    relative == broker
        && call.attrs.is_empty()
        && call.method == "observe_current_pinned_writer_session"
        && call.turbofish.is_none()
        && call.args.is_empty()
        && receiver.attrs.is_empty()
        && receiver.qself.is_none()
        && path_is(&receiver.path, &["handoff"])
}

pub fn macro_identifiers(tokens: proc_macro2::TokenStream) -> Vec<String> {
    let mut identifiers = Vec::new();
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Ident(identifier) => {
                identifiers.push(identifier.to_string());
            }
            proc_macro2::TokenTree::Group(group) => {
                identifiers.extend(macro_identifiers(group.stream()));
            }
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
    identifiers
}
