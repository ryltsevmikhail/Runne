use super::bodies::BodyEngine;
use super::provenance::TargetMethod;
use super::symbols::MemberKey;

pub(super) fn target_method_name(
    engine: &BodyEngine<'_>,
    path: &syn::Path,
) -> Option<TargetMethod> {
    let name = path.segments.last()?.ident.to_string();
    if name == engine.index.target.capture_method {
        Some(TargetMethod::Capture)
    } else if name == engine.index.target.verify_method {
        Some(TargetMethod::Verify)
    } else {
        None
    }
}

pub(super) fn qualifier(path: &syn::Path) -> syn::Path {
    let mut path = path.clone();
    path.segments.pop();
    path
}

pub(super) fn member_key(member: &syn::Member) -> MemberKey {
    match member {
        syn::Member::Named(name) => MemberKey::Named(name.to_string()),
        syn::Member::Unnamed(index) => MemberKey::Unnamed(index.index),
    }
}

pub(super) fn integer_index(expression: &syn::Expr) -> Option<usize> {
    let syn::Expr::Lit(value) = expression else {
        return None;
    };
    let syn::Lit::Int(value) = &value.lit else {
        return None;
    };
    value.base10_parse().ok()
}

pub(super) fn expr_attributes(expression: &syn::Expr) -> &[syn::Attribute] {
    match expression {
        syn::Expr::Array(value) => &value.attrs,
        syn::Expr::Assign(value) => &value.attrs,
        syn::Expr::Await(value) => &value.attrs,
        syn::Expr::Binary(value) => &value.attrs,
        syn::Expr::Block(value) => &value.attrs,
        syn::Expr::Break(value) => &value.attrs,
        syn::Expr::Call(value) => &value.attrs,
        syn::Expr::Cast(value) => &value.attrs,
        syn::Expr::Closure(value) => &value.attrs,
        syn::Expr::Const(value) => &value.attrs,
        syn::Expr::Field(value) => &value.attrs,
        syn::Expr::ForLoop(value) => &value.attrs,
        syn::Expr::Group(value) => &value.attrs,
        syn::Expr::If(value) => &value.attrs,
        syn::Expr::Index(value) => &value.attrs,
        syn::Expr::Let(value) => &value.attrs,
        syn::Expr::Lit(value) => &value.attrs,
        syn::Expr::Loop(value) => &value.attrs,
        syn::Expr::Macro(value) => &value.attrs,
        syn::Expr::Match(value) => &value.attrs,
        syn::Expr::MethodCall(value) => &value.attrs,
        syn::Expr::Paren(value) => &value.attrs,
        syn::Expr::Path(value) => &value.attrs,
        syn::Expr::Range(value) => &value.attrs,
        syn::Expr::Reference(value) => &value.attrs,
        syn::Expr::Repeat(value) => &value.attrs,
        syn::Expr::Return(value) => &value.attrs,
        syn::Expr::Struct(value) => &value.attrs,
        syn::Expr::Try(value) => &value.attrs,
        syn::Expr::Tuple(value) => &value.attrs,
        syn::Expr::Unary(value) => &value.attrs,
        syn::Expr::Unsafe(value) => &value.attrs,
        syn::Expr::While(value) => &value.attrs,
        syn::Expr::Yield(value) => &value.attrs,
        _ => &[],
    }
}
