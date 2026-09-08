use syn::{Attribute, Expr};

pub(super) fn is_test_only(attributes: &[Attribute]) -> bool {
    !super::cfg_projection::is_production(attributes)
}

pub(super) fn expr_is_test_only(expression: &Expr) -> bool {
    let attributes = match expression {
        Expr::Array(node) => &node.attrs,
        Expr::Assign(node) => &node.attrs,
        Expr::Async(node) => &node.attrs,
        Expr::Await(node) => &node.attrs,
        Expr::Binary(node) => &node.attrs,
        Expr::Block(node) => &node.attrs,
        Expr::Break(node) => &node.attrs,
        Expr::Call(node) => &node.attrs,
        Expr::Cast(node) => &node.attrs,
        Expr::Closure(node) => &node.attrs,
        Expr::Const(node) => &node.attrs,
        Expr::Continue(node) => &node.attrs,
        Expr::Field(node) => &node.attrs,
        Expr::ForLoop(node) => &node.attrs,
        Expr::Group(node) => &node.attrs,
        Expr::If(node) => &node.attrs,
        Expr::Index(node) => &node.attrs,
        Expr::Infer(node) => &node.attrs,
        Expr::Let(node) => &node.attrs,
        Expr::Lit(node) => &node.attrs,
        Expr::Loop(node) => &node.attrs,
        Expr::Macro(node) => &node.attrs,
        Expr::Match(node) => &node.attrs,
        Expr::MethodCall(node) => &node.attrs,
        Expr::Paren(node) => &node.attrs,
        Expr::Path(node) => &node.attrs,
        Expr::Range(node) => &node.attrs,
        Expr::RawAddr(node) => &node.attrs,
        Expr::Reference(node) => &node.attrs,
        Expr::Repeat(node) => &node.attrs,
        Expr::Return(node) => &node.attrs,
        Expr::Struct(node) => &node.attrs,
        Expr::Try(node) => &node.attrs,
        Expr::TryBlock(node) => &node.attrs,
        Expr::Tuple(node) => &node.attrs,
        Expr::Unary(node) => &node.attrs,
        Expr::Unsafe(node) => &node.attrs,
        Expr::While(node) => &node.attrs,
        Expr::Yield(node) => &node.attrs,
        Expr::Verbatim(_) | _ => return false,
    };
    is_test_only(attributes)
}

pub(super) fn parse_source(source: &str) -> syn::File {
    if let Ok(file) = syn::parse_file(source) {
        return file;
    }
    for wrapped in [
        format!("fn __runne_guard_wrapper() {{\n{source}\n}}"),
        format!("mod __runne_guard_wrapper {{\n{source}\n}}"),
    ] {
        if let Ok(file) = syn::parse_file(&wrapped) {
            return file;
        }
    }
    panic!("production source must parse")
}
