use super::super::super::lexer::{StringKind, Token};
use super::tokens::punct;

pub(super) fn module_attributes(
    attributes: &[Vec<Token>],
) -> Result<(bool, Option<String>), String> {
    let mut cfg_is_test = false;
    let mut path = None;
    for attribute in attributes {
        let Some(name) = attribute_name(attribute) else {
            return Err("parser: unsupported item attribute".to_owned());
        };
        match name {
            "cfg" => cfg_is_test |= cfg_test(attribute),
            "path" => path = Some(path_attribute(attribute)?),
            "cfg_attr" => return Err("parser: cfg_attr item attribute is ambiguous".to_owned()),
            _ if known_attribute(name) => {}
            _ => return Err(format!("parser: unsupported item attribute `{name}`")),
        }
    }
    Ok((cfg_is_test, path))
}

pub(super) fn validate_non_module_attributes(attributes: &[Vec<Token>]) -> Result<(), String> {
    for attribute in attributes {
        let Some(name) = attribute_name(attribute) else {
            return Err("parser: unsupported item attribute".to_owned());
        };
        if name == "cfg_attr" {
            return Err("parser: cfg_attr item attribute is ambiguous".to_owned());
        }
        if name != "cfg" && name != "path" && !known_attribute(name) {
            return Err(format!("parser: unsupported item attribute `{name}`"));
        }
    }
    Ok(())
}

fn path_attribute(attribute: &[Token]) -> Result<String, String> {
    match attribute {
        [
            Token::Ident(name),
            Token::Punct('='),
            Token::String { value, kind },
        ] if name == "path" && matches!(kind, StringKind::Ordinary | StringKind::Raw) => {
            Ok(value.clone())
        }
        [Token::Ident(name), Token::Punct('='), Token::String { .. }] if name == "path" => {
            Err("parser: path attribute requires an unescaped ordinary or raw string".to_owned())
        }
        _ => Err("parser: invalid path item attribute".to_owned()),
    }
}

fn cfg_test(attribute: &[Token]) -> bool {
    matches!(
        attribute,
        [Token::Ident(name), Token::Punct('('), Token::Ident(test), Token::Punct(')')]
            if name == "cfg" && test == "test"
    )
}

pub(super) fn attribute_start(tokens: &[Token], index: usize) -> bool {
    punct(tokens.get(index), '#')
        && (punct(tokens.get(index + 1), '[')
            || (punct(tokens.get(index + 1), '!') && punct(tokens.get(index + 2), '[')))
}

fn attribute_name(attribute: &[Token]) -> Option<&str> {
    match attribute.first() {
        Some(Token::Ident(name)) => Some(name),
        _ => None,
    }
}

fn known_attribute(name: &str) -> bool {
    matches!(
        name,
        "allow"
            | "automatically_derived"
            | "cold"
            | "deny"
            | "deprecated"
            | "derive"
            | "diagnostic"
            | "doc"
            | "error"
            | "expect"
            | "export_name"
            | "from"
            | "inline"
            | "link_name"
            | "link_section"
            | "must_use"
            | "no_mangle"
            | "non_exhaustive"
            | "repr"
            | "serde"
            | "source"
            | "track_caller"
            | "unsafe"
            | "used"
            | "warn"
    )
}
