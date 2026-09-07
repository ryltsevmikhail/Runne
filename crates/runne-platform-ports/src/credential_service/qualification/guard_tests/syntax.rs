use syn::{Attribute, Item, Meta};

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
    attrs.iter().any(|attribute| {
        if attribute.path().is_ident("test") {
            return true;
        }
        let Meta::List(list) = &attribute.meta else {
            return false;
        };
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        let compact: String = list
            .tokens
            .to_string()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        compact == "test"
            || (compact.starts_with("all(")
                && compact.contains("test")
                && !compact.contains("not(test)"))
    })
}
