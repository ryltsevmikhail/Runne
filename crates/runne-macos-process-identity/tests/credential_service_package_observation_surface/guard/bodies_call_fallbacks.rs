pub(super) fn is_none_constructor(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Path(path) => is_none_path(path),
        _ => false,
    }
}

fn is_none_path(path: &syn::ExprPath) -> bool {
    path.qself.is_none()
        && path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "None")
}
