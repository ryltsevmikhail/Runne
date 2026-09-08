use syn::punctuated::Punctuated;
use syn::{Meta, Token};

pub(super) fn condition_may_apply(meta: &Meta) -> bool {
    condition(meta) != Truth::False
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Symbolic,
}

fn condition(meta: &Meta) -> Truth {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Truth::False,
        Meta::List(list) if list.path.is_ident("not") => syn::parse2::<Meta>(list.tokens.clone())
            .map_or(Truth::Symbolic, |item| not(condition(&item))),
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_or(Truth::Symbolic, |items| {
                items
                    .iter()
                    .fold(Truth::True, |truth, item| and(truth, condition(item)))
            }),
        Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_or(Truth::Symbolic, |items| {
                items
                    .iter()
                    .fold(Truth::False, |truth, item| or(truth, condition(item)))
            }),
        _ => Truth::Symbolic,
    }
}

const fn and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Symbolic,
    }
}

const fn or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Symbolic,
    }
}

const fn not(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Symbolic => Truth::Symbolic,
    }
}
