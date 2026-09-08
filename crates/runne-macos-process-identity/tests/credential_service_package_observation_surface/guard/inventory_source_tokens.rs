use std::path::Path;

pub(super) fn is_source_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "rs" || extension == "inc")
}

pub(super) fn source_literal_present(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Literal(literal) => {
            syn::parse_str::<syn::LitStr>(&literal.to_string())
                .is_ok_and(|path| is_source_path(&path.value()))
        }
        proc_macro2::TokenTree::Group(group) => source_literal_present(group.stream()),
        proc_macro2::TokenTree::Ident(_) | proc_macro2::TokenTree::Punct(_) => false,
    })
}
