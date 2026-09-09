use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Arm, Attribute, Expr, ImplItem, Item, Meta, Stmt, Token, TraitItem};

pub(super) fn normalized_ident(ident: &proc_macro2::Ident) -> String {
    let ident = ident.to_string();
    ident.strip_prefix("r#").unwrap_or(&ident).to_owned()
}

pub fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

pub fn item_is_test_only(attrs: &[Attribute]) -> bool {
    attrs_are_test_only(attrs)
}

pub fn stmt_is_test_only(statement: &Stmt) -> bool {
    match statement {
        Stmt::Local(local) => attrs_are_test_only(&local.attrs),
        Stmt::Item(item) => item_is_test_only(item_attrs(item)),
        Stmt::Expr(expression, _) => expr_is_test_only(expression),
        Stmt::Macro(statement) => attrs_are_test_only(&statement.attrs),
    }
}

pub fn expr_is_test_only(expression: &Expr) -> bool {
    attrs_are_test_only(expr_attrs(expression))
}

pub fn arm_is_test_only(arm: &Arm) -> bool {
    attrs_are_test_only(&arm.attrs)
}

pub fn trait_item_is_test_only(item: &TraitItem) -> bool {
    attrs_are_test_only(trait_item_attrs(item))
}

pub fn impl_item_is_test_only(item: &ImplItem) -> bool {
    attrs_are_test_only(impl_item_attrs(item))
}

fn attrs_are_test_only(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("test") || attr_excludes_production(attribute))
}

fn attr_excludes_production(attribute: &Attribute) -> bool {
    let Meta::List(list) = &attribute.meta else {
        return false;
    };
    if attribute.path().is_ident("cfg") {
        return cfg_truth(&list.tokens) == Truth::False;
    }
    if !attribute.path().is_ident("cfg_attr") {
        return false;
    }
    let Ok(arguments) = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
    else {
        return false;
    };
    let mut arguments = arguments.into_iter();
    if arguments
        .next()
        .is_none_or(|condition| cfg_meta_truth(&condition) != Truth::True)
    {
        return false;
    }
    arguments.any(|attribute| {
        matches!(attribute, Meta::List(list) if list.path.is_ident("cfg") && cfg_truth(&list.tokens) == Truth::False)
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Unknown,
}

pub(super) fn cfg_meta_is_false(meta: &Meta) -> bool {
    cfg_meta_truth(meta) == Truth::False
}

fn cfg_truth(tokens: &proc_macro2::TokenStream) -> Truth {
    syn::parse2::<Meta>(tokens.clone()).map_or(Truth::Unknown, |meta| cfg_meta_truth(&meta))
}

fn cfg_meta_truth(meta: &Meta) -> Truth {
    if meta.path().is_ident("test") {
        return Truth::False;
    }
    let Meta::List(list) = meta else {
        return Truth::Unknown;
    };
    let Ok(arguments) = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
    else {
        return Truth::Unknown;
    };
    match list.path.get_ident().map(ToString::to_string).as_deref() {
        Some("not") if arguments.len() == 1 => negate(cfg_meta_truth(arguments.first().unwrap())),
        Some("all") => arguments
            .into_iter()
            .fold(Truth::True, |truth, argument| and(truth, &argument)),
        Some("any") => arguments
            .into_iter()
            .fold(Truth::False, |truth, argument| or(truth, &argument)),
        _ => Truth::Unknown,
    }
}

fn negate(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

fn and(left: Truth, right: &Meta) -> Truth {
    match (left, cfg_meta_truth(right)) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn or(left: Truth, right: &Meta) -> Truth {
    match (left, cfg_meta_truth(right)) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

fn expr_attrs(expression: &Expr) -> &[Attribute] {
    macro_rules! attrs {
        ($($variant:ident),*) => { match expression { $(Expr::$variant(expression) => &expression.attrs,)* Expr::Verbatim(_) | _ => &[] } };
    }
    attrs!(
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall, Paren,
        Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple, Unary,
        Unsafe, While, Yield
    )
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(item) => &item.attrs,
        TraitItem::Fn(item) => &item.attrs,
        TraitItem::Macro(item) => &item.attrs,
        TraitItem::Type(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(item) => &item.attrs,
        ImplItem::Fn(item) => &item.attrs,
        ImplItem::Macro(item) => &item.attrs,
        ImplItem::Type(item) => &item.attrs,
        _ => &[],
    }
}
