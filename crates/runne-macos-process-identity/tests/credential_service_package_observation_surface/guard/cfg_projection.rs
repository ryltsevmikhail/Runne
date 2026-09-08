use syn::punctuated::Punctuated;
use syn::{Attribute, Meta, Token};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Symbolic,
}

pub(super) fn is_production(attributes: &[Attribute]) -> bool {
    let mut result = Truth::True;
    for attribute in attributes {
        if attribute.path().is_ident("test") {
            return false;
        }
        if attribute.path().is_ident("cfg") {
            result = and(result, cfg_attribute(&attribute.meta));
        } else if attribute.path().is_ident("cfg_attr") {
            result = and(result, cfg_attr(attribute));
        }
        if result == Truth::False {
            return false;
        }
    }
    true
}

fn cfg_attribute(meta: &Meta) -> Truth {
    let Meta::List(list) = meta else {
        return Truth::Symbolic;
    };
    predicate_tokens(list.tokens.clone())
}

fn cfg_attr(attribute: &Attribute) -> Truth {
    let Meta::List(list) = &attribute.meta else {
        return Truth::Symbolic;
    };
    let Ok(parts) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        return Truth::Symbolic;
    };
    let Some(condition) = parts.first() else {
        return Truth::Symbolic;
    };
    match predicate(condition) {
        Truth::False => Truth::True,
        Truth::True => parts
            .iter()
            .skip(1)
            .fold(Truth::True, |value, meta| and(value, applied_meta(meta))),
        Truth::Symbolic => Truth::Symbolic,
    }
}

fn applied_meta(meta: &Meta) -> Truth {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Truth::False,
        Meta::List(list) if list.path.is_ident("cfg") => predicate_tokens(list.tokens.clone()),
        Meta::List(list) if list.path.is_ident("cfg_attr") => nested_cfg_attr(list),
        _ => Truth::True,
    }
}

fn nested_cfg_attr(list: &syn::MetaList) -> Truth {
    let Ok(parts) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        return Truth::Symbolic;
    };
    let Some(condition) = parts.first() else {
        return Truth::Symbolic;
    };
    match predicate(condition) {
        Truth::False => Truth::True,
        Truth::True => parts
            .iter()
            .skip(1)
            .fold(Truth::True, |value, meta| and(value, applied_meta(meta))),
        Truth::Symbolic => Truth::Symbolic,
    }
}

fn predicate_tokens(tokens: proc_macro2::TokenStream) -> Truth {
    syn::parse2::<Meta>(tokens).map_or(Truth::Symbolic, |meta| predicate(&meta))
}

fn predicate(meta: &Meta) -> Truth {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Truth::False,
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_or(Truth::Symbolic, |items| {
                items
                    .iter()
                    .fold(Truth::True, |value, item| and(value, predicate(item)))
            }),
        Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_or(Truth::Symbolic, |items| {
                items
                    .iter()
                    .fold(Truth::False, |value, item| or(value, predicate(item)))
            }),
        Meta::List(list) if list.path.is_ident("not") => {
            let Ok(item) = syn::parse2::<Meta>(list.tokens.clone()) else {
                return Truth::Symbolic;
            };
            not(predicate(&item))
        }
        Meta::Path(_) | Meta::NameValue(_) | Meta::List(_) => Truth::Symbolic,
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

#[cfg(test)]
mod tests {
    use super::is_production;

    fn attributes(source: &str) -> Vec<syn::Attribute> {
        let item = syn::parse_str::<syn::ItemFn>(&format!("{source} fn sample() {{}}"))
            .expect("valid attributed function");
        item.attrs
    }

    #[test]
    fn projects_test_false_and_keeps_symbolic_cfg() {
        for source in ["#[cfg(test)]", "#[cfg(not(not(test)))]"] {
            assert!(!is_production(&attributes(source)), "{source}");
        }
        assert!(!is_production(&attributes(
            "#[cfg_attr(not(test), cfg_attr(not(test), cfg(test)))]"
        )));
        for source in [
            "#[cfg(not(test))]",
            "#[cfg(any(test, feature = \"live\"))]",
            "#[cfg(all(not(test), feature = \"live\"))]",
        ] {
            assert!(is_production(&attributes(source)), "{source}");
        }
    }
}
