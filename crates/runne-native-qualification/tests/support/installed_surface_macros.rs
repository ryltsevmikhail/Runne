use std::collections::HashSet;

pub fn mentions_authority(item: &syn::ItemMacro, aliases: &HashSet<String>) -> bool {
    item.mac
        .path
        .segments
        .iter()
        .any(|segment| aliases.contains(&segment.ident.to_string()))
        || token_identifiers(&item.mac.tokens.to_string())
            .any(|identifier| aliases.contains(identifier))
}

fn token_identifiers(tokens: &str) -> impl Iterator<Item = &str> {
    tokens
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == '#')
        })
        .map(|token| token.trim_start_matches("r#"))
        .filter(|token| !token.is_empty())
}
