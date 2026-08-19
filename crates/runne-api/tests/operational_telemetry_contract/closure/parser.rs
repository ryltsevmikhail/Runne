use super::lexer::{StringKind, Token};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ModuleDeclaration {
    pub(super) name: String,
    pub(super) path: Option<String>,
    pub(super) cfg_test: bool,
    pub(super) directory: PathBuf,
}

pub(super) fn declarations(tokens: &[Token]) -> Result<Vec<ModuleDeclaration>, String> {
    let mut declarations = Vec::new();
    parse_scope(tokens, 0, tokens.len(), PathBuf::new(), &mut declarations)?;
    Ok(declarations)
}

fn parse_scope(
    tokens: &[Token],
    mut index: usize,
    end: usize,
    directory: PathBuf,
    declarations: &mut Vec<ModuleDeclaration>,
) -> Result<(), String> {
    let mut attributes = Vec::new();
    while index < end {
        if attribute_start(tokens, index) {
            let open = index + usize::from(punct(tokens.get(index + 1), '!')) + 1;
            let close = matching(tokens, open, '[', ']')?;
            attributes.push(tokens[open + 1..close].to_vec());
            index = close + 1;
            continue;
        }
        let mut item = index;
        if ident(tokens.get(item), "pub") {
            item += 1;
            if punct(tokens.get(item), '(') {
                item = matching(tokens, item, '(', ')')? + 1;
            }
        }
        if ident(tokens.get(item), "mod") {
            index = parse_module(
                tokens,
                item,
                end,
                directory.clone(),
                attributes,
                declarations,
            )?;
            attributes = Vec::new();
            continue;
        }
        if macro_at(tokens, item, end) {
            return Err(format!(
                "parser at token {item}: unresolved item-position macro"
            ));
        }
        validate_non_module_attributes(&attributes)?;
        attributes.clear();
        if item_starts(tokens.get(item)) {
            index = skip_item(tokens, item, end)?;
        } else if let Some(open) = group_open(tokens.get(index)) {
            index = matching(tokens, index, open, closing(open))? + 1;
        } else if punct(tokens.get(index), '}') {
            return Err(format!("parser at token {index}: unexpected closing group"));
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn parse_module(
    tokens: &[Token],
    module: usize,
    end: usize,
    directory: PathBuf,
    attributes: Vec<Vec<Token>>,
    declarations: &mut Vec<ModuleDeclaration>,
) -> Result<usize, String> {
    let Some(Token::Ident(name)) = tokens.get(module + 1) else {
        return Err(format!("parser at token {module}: module name is missing"));
    };
    let (cfg_test, path) = module_attributes(&attributes)?;
    let next = module + 2;
    match tokens.get(next) {
        Some(Token::Punct(';')) => {
            declarations.push(ModuleDeclaration {
                name: name.clone(),
                path,
                cfg_test,
                directory,
            });
            Ok(next + 1)
        }
        Some(Token::Punct('{')) => {
            let close = matching(tokens, next, '{', '}')?;
            if !cfg_test {
                parse_scope(tokens, next + 1, close, directory.join(name), declarations)?;
            }
            Ok(close + 1)
        }
        _ if next >= end => Err(format!(
            "parser at token {module}: module terminator is missing"
        )),
        _ => Err(format!(
            "parser at token {module}: invalid module declaration"
        )),
    }
}

fn module_attributes(attributes: &[Vec<Token>]) -> Result<(bool, Option<String>), String> {
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

fn validate_non_module_attributes(attributes: &[Vec<Token>]) -> Result<(), String> {
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

fn attribute_start(tokens: &[Token], index: usize) -> bool {
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

fn macro_at(tokens: &[Token], mut index: usize, end: usize) -> bool {
    if !matches!(tokens.get(index), Some(Token::Ident(_))) {
        return false;
    }
    index += 1;
    while index + 2 < end && punct(tokens.get(index), ':') && punct(tokens.get(index + 1), ':') {
        if !matches!(tokens.get(index + 2), Some(Token::Ident(_))) {
            return false;
        }
        index += 3;
    }
    punct(tokens.get(index), '!') && group_open(tokens.get(index + 1)).is_some()
}

fn item_starts(token: Option<&Token>) -> bool {
    matches!(
        token,
        Some(Token::Ident(name))
            if matches!(
                name.as_str(),
                "const" | "enum" | "extern" | "fn" | "impl" | "static" | "struct" | "trait" | "type" | "union" | "use"
            )
    )
}

fn skip_item(tokens: &[Token], mut index: usize, end: usize) -> Result<usize, String> {
    let body_item = matches!(
        tokens.get(index),
        Some(Token::Ident(name)) if matches!(name.as_str(), "enum" | "extern" | "fn" | "impl" | "struct" | "trait" | "union")
    );
    while index < end {
        if punct(tokens.get(index), ';') {
            return Ok(index + 1);
        }
        if let Some(open) = group_open(tokens.get(index)) {
            let close = matching(tokens, index, open, closing(open))?;
            if open == '{' && body_item {
                return Ok(close + 1);
            }
            index = close + 1;
        } else {
            index += 1;
        }
    }
    Err("parser: unterminated item".to_owned())
}

fn matching(tokens: &[Token], start: usize, open: char, close: char) -> Result<usize, String> {
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if punct(Some(token), open) {
            depth += 1;
        } else if punct(Some(token), close) {
            depth -= 1;
            if depth == 0 {
                return Ok(index);
            }
        }
    }
    Err(format!(
        "parser at token {start}: unterminated `{open}` group"
    ))
}

fn ident(token: Option<&Token>, expected: &str) -> bool {
    matches!(token, Some(Token::Ident(value)) if value == expected)
}

fn punct(token: Option<&Token>, expected: char) -> bool {
    matches!(token, Some(Token::Punct(value)) if *value == expected)
}

fn group_open(token: Option<&Token>) -> Option<char> {
    match token {
        Some(Token::Punct(open @ ('(' | '[' | '{'))) => Some(*open),
        _ => None,
    }
}

fn closing(open: char) -> char {
    match open {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        _ => unreachable!(),
    }
}
